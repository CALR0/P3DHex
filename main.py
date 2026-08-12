#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P3DHex - a WPE/rPE-style Winsock packet editor.

Attaches to a target process, hooks Winsock (send/recv/WSASend/WSARecv) via
Frida, shows captured application-layer packets, lets you edit the raw bytes
and re-send them, and manages editable "send lists" (groups of saved packets
you can fire one by one or as a sequence with delays).

Use only on software you own or are authorized to test.
"""

import os
import sys
import json
import time
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import frida
except ImportError:
    frida = None

def _resource_dir():
    # In a PyInstaller onefile build bundled data lives under _MEIPASS.
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def _persist_dir():
    # Writable location that survives runs: next to the .exe when frozen.
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


HOOK_PATH = os.path.join(_resource_dir(), "hook.js")
LISTS_PATH = os.path.join(_persist_dir(), "sendlists.json")
FILTERS_PATH = os.path.join(_persist_dir(), "filters.json")

MAX_ROWS = 5000           # cap capture list to keep the GUI responsive
PREVIEW_BYTES = 24        # bytes shown in the list preview column
FILTER_COLS = 64          # offset columns in the filter grid


# ------------------------------------------------------------------ helpers
def bytes_to_hex(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def hex_to_bytes(text: str) -> bytes:
    cleaned = "".join(c for c in text if c in "0123456789abcdefABCDEF")
    if len(cleaned) % 2:
        raise ValueError("El hex tiene un numero impar de digitos.")
    return bytes(int(cleaned[i:i + 2], 16) for i in range(0, len(cleaned), 2))


# ------------------------------------------------------------- frida backend
class HookController:
    """Owns the Frida session/script and pumps messages into a queue."""

    def __init__(self, out_queue: queue.Queue):
        self.q = out_queue
        self.session = None
        self.script = None
        self.exports = None

    def list_processes(self):
        if frida is None:
            return []
        procs = frida.get_local_device().enumerate_processes()
        return sorted(procs, key=lambda p: p.name.lower())

    def attach(self, target):
        if frida is None:
            raise RuntimeError("Frida no esta instalado. Ejecuta: pip install frida")
        with open(HOOK_PATH, "r", encoding="utf-8") as f:
            source = f.read()
        # target may be a pid (int) or a process name (str)
        self.session = frida.get_local_device().attach(target)
        self.session.on("detached", self._on_detached)
        self.script = self.session.create_script(source)
        self.script.on("message", self._on_message)
        self.script.load()
        self.exports = getattr(self.script, "exports_sync", None) or self.script.exports

    def detach(self):
        try:
            if self.script:
                self.script.unload()
        except Exception:
            pass
        try:
            if self.session:
                self.session.detach()
        except Exception:
            pass
        self.script = None
        self.session = None
        self.exports = None

    def inject(self, socket_str: str, data: bytes) -> int:
        if not self.exports:
            raise RuntimeError("No hay un proceso conectado.")
        return self.exports.inject(socket_str, list(data))

    def set_filters(self, payload):
        if not self.exports:
            return None
        return self.exports.set_filters(payload)

    def _on_message(self, message, data):
        if message.get("type") == "send":
            self.q.put(("payload", message.get("payload"), data))
        elif message.get("type") == "error":
            self.q.put(("error", message.get("description", "error"), None))

    def _on_detached(self, *args):
        self.q.put(("detached", None, None))


# --------------------------------------------------------------------- GUI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("P3DHex")
        self.geometry("1150x720")
        self.minsize(980, 620)

        self.q = queue.Queue()
        self.ctrl = HookController(self.q)
        self.attached = False
        self.paused = False

        self.captures = []          # list of dicts: {dir, fn, socket, data}
        self.sockets = []           # known socket handles (strings)
        self.last_send_socket = None
        self.sendlists = {}         # name -> [ {name, hex} ]
        self._loop_stop = threading.Event()
        self._loop_busy = False
        self.filters = []           # [{name,active,onSend,onRecv,search:{},modify:{}}]
        self.filter_win = None
        self.filter_hits = {}       # name -> veces que hizo match
        self.dark = True            # modo oscuro por defecto
        self._colors = {}
        self._send_count = 0        # contador de envios en curso

        self._build_ui()
        self._load_lists()
        self._load_filters()
        self._apply_theme()
        self.after(60, self._pump)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- layout -----------------------------------------------------------
    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="Proceso:").pack(side="left")
        self.proc_cb = ttk.Combobox(top, width=45, state="normal")
        self.proc_cb.pack(side="left", padx=4)
        ttk.Button(top, text="Refrescar", command=self._refresh_procs).pack(side="left")
        self.btn_start = ttk.Button(top, text="Start", command=self._start)
        self.btn_start.pack(side="left", padx=(12, 2))
        self.btn_stop = ttk.Button(top, text="Stop", command=self._stop, state="disabled")
        self.btn_stop.pack(side="left", padx=2)
        self.pause_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Pausar captura", variable=self.pause_var).pack(side="left", padx=12)
        ttk.Button(top, text="Limpiar", command=self._clear_captures).pack(side="left")
        ttk.Button(top, text="Detener loop", command=self._stop_loop).pack(side="left", padx=(6, 0))
        ttk.Button(top, text="Filtros", command=self._open_filters).pack(side="left", padx=(6, 0))
        self.count_lbl = ttk.Label(top, text="Enviados: 0")
        self.count_lbl.pack(side="left", padx=(12, 0))

        self.theme_switch = tk.Canvas(top, width=48, height=24, highlightthickness=0, bd=0)
        self.theme_switch.pack(side="right", padx=(8, 0))
        self.theme_switch.bind("<Button-1>", lambda e: self._toggle_theme())
        ttk.Label(top, text="Tema:").pack(side="right")

        self.status = ttk.Label(top, text="Desconectado", foreground="#a00")
        self.status.pack(side="right", padx=(0, 12))

        main = ttk.PanedWindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # left: capture list
        left = ttk.Frame(main)
        cols = ("dir", "fn", "socket", "len", "flt", "preview")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for c, w, txt in (("dir", 50, "Dir"), ("fn", 75, "Func"),
                          ("socket", 85, "Socket"), ("len", 50, "Len"),
                          ("flt", 70, "Filtro"), ("preview", 360, "Datos (hex)")):
            self.tree.heading(c, text=txt)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_select_capture)
        self.tree.tag_configure("send", foreground="#008000")
        self.tree.tag_configure("recv", foreground="#0055cc")
        self.tree.tag_configure("filtered", background="#ffd27f")
        main.add(left, weight=3)

        # right: editor + send lists
        right = ttk.Frame(main)
        main.add(right, weight=2)

        edit = ttk.LabelFrame(right, text="Editor de paquete", padding=6)
        edit.pack(fill="both", expand=False)
        self.editor = tk.Text(edit, height=8, wrap="word",
                              font=("Consolas", 10))
        self.editor.pack(fill="both", expand=True)
        info = ttk.Frame(edit)
        info.pack(fill="x", pady=(4, 0))
        self.len_lbl = ttk.Label(info, text="0 bytes")
        self.len_lbl.pack(side="left")
        ttk.Label(info, text="Socket:").pack(side="left", padx=(12, 2))
        self.socket_cb = ttk.Combobox(info, width=16, state="normal")
        self.socket_cb.pack(side="left")
        self.editor.bind("<KeyRelease>", lambda e: self._update_len())

        btns = ttk.Frame(edit)
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text="Send", command=self._send_editor).pack(side="left")
        ttk.Button(btns, text="Anadir a lista", command=self._add_to_list).pack(side="left", padx=6)
        ttk.Button(btns, text="Send loop", command=self._send_editor_loop).pack(side="left")

        btns2 = ttk.Frame(edit)
        btns2.pack(fill="x", pady=(4, 0))
        ttk.Label(btns2, text="Delay ms:").pack(side="left")
        self.ed_delay_var = tk.StringVar(value="150")
        ttk.Entry(btns2, textvariable=self.ed_delay_var, width=7).pack(side="left")
        ttk.Label(btns2, text="Loop:").pack(side="left", padx=(10, 2))
        self.ed_loop_var = tk.StringVar(value="1")
        ttk.Entry(btns2, textvariable=self.ed_loop_var, width=6).pack(side="left")
        self.ed_continuous_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(btns2, text="Mandar continuo",
                        variable=self.ed_continuous_var).pack(side="left", padx=(10, 0))

        # send lists
        lists = ttk.LabelFrame(right, text="Send Lists", padding=6)
        lists.pack(fill="both", expand=True, pady=(8, 0))
        bar = ttk.Frame(lists)
        bar.pack(fill="x")
        ttk.Label(bar, text="Lista:").pack(side="left")
        self.list_cb = ttk.Combobox(bar, width=22, state="readonly")
        self.list_cb.pack(side="left", padx=4)
        self.list_cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_list_items())
        ttk.Button(bar, text="Nueva", command=self._new_list).pack(side="left")
        ttk.Button(bar, text="Borrar lista", command=self._del_list).pack(side="left", padx=4)
        ttk.Button(bar, text="Exportar", command=self._export_list).pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="Importar", command=self._import_list).pack(side="left", padx=4)

        self.items = tk.Listbox(lists, height=8, font=("Consolas", 9))
        self.items.pack(fill="both", expand=True, pady=6)
        self.items.bind("<Double-Button-1>", lambda e: self._edit_item())

        row = ttk.Frame(lists)
        row.pack(fill="x")
        ttk.Button(row, text="Editar", command=self._edit_item).pack(side="left")
        ttk.Button(row, text="Quitar", command=self._remove_item).pack(side="left", padx=4)
        ttk.Button(row, text="Subir", command=lambda: self._move_item(-1)).pack(side="left")
        ttk.Button(row, text="Bajar", command=lambda: self._move_item(1)).pack(side="left", padx=4)

        rowsock = ttk.Frame(lists)
        rowsock.pack(fill="x", pady=(6, 0))
        ttk.Label(rowsock, text="Socket destino:").pack(side="left")
        self.list_socket_var = tk.StringVar(value="")
        ttk.Entry(rowsock, textvariable=self.list_socket_var, width=20).pack(side="left", padx=4)
        ttk.Label(rowsock, text="(vacio = ultimo send capturado)",
                  foreground="#888").pack(side="left", padx=6)

        row2 = ttk.Frame(lists)
        row2.pack(fill="x", pady=(6, 0))
        ttk.Button(row2, text="Send item", command=self._send_item).pack(side="left")
        ttk.Button(row2, text="Send lista completa", command=self._send_whole_list).pack(side="left", padx=6)
        ttk.Label(row2, text="Delay ms:").pack(side="left")
        self.delay_var = tk.StringVar(value="150")
        ttk.Entry(row2, textvariable=self.delay_var, width=7).pack(side="left")
        ttk.Label(row2, text="Loop:").pack(side="left", padx=(10, 2))
        self.loop_var = tk.StringVar(value="1")
        ttk.Entry(row2, textvariable=self.loop_var, width=6).pack(side="left")
        self.continuous_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Mandar continuo",
                        variable=self.continuous_var).pack(side="left", padx=(10, 0))

        self._refresh_procs()

    # -- theme ------------------------------------------------------------
    def _colors_for(self, dark):
        if dark:
            return dict(panel="#252526", entry="#2d2d30", fg="#e6e6e6", sub="#9a9a9a",
                        btn="#3c3c3c", btn_active="#505050", sel="#0e639c", tree="#1e1e1e",
                        head="#333333", send="#4ec94e", recv="#4aa3ff", filt="#6b5320",
                        trough="#2d2d30", accent="#0e639c")
        return dict(panel="#f0f0f0", entry="#ffffff", fg="#101010", sub="#666666",
                    btn="#e1e1e1", btn_active="#d0d0d0", sel="#cce5ff", tree="#ffffff",
                    head="#e6e6e6", send="#008000", recv="#0055cc", filt="#ffd27f",
                    trough="#e0e0e0", accent="#0e639c")

    def _apply_theme(self):
        c = self._colors_for(self.dark)
        self._colors = c
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure(".", background=c["panel"], foreground=c["fg"])
        st.configure("TFrame", background=c["panel"])
        st.configure("TLabel", background=c["panel"], foreground=c["fg"])
        st.configure("TLabelframe", background=c["panel"], bordercolor=c["btn"])
        st.configure("TLabelframe.Label", background=c["panel"], foreground=c["fg"])
        st.configure("TButton", background=c["btn"], foreground=c["fg"], bordercolor=c["btn"])
        st.map("TButton",
               background=[("active", c["btn_active"]), ("disabled", c["panel"])],
               foreground=[("disabled", c["sub"])])
        st.configure("TCheckbutton", background=c["panel"], foreground=c["fg"])
        st.map("TCheckbutton", background=[("active", c["panel"])])
        st.configure("TEntry", fieldbackground=c["entry"], foreground=c["fg"],
                     insertcolor=c["fg"], bordercolor=c["btn"])
        st.configure("TCombobox", fieldbackground=c["entry"], foreground=c["fg"],
                     background=c["btn"], arrowcolor=c["fg"], bordercolor=c["btn"])
        st.map("TCombobox",
               fieldbackground=[("readonly", c["entry"])], foreground=[("readonly", c["fg"])])
        st.configure("Treeview", background=c["tree"], fieldbackground=c["tree"],
                     foreground=c["fg"], bordercolor=c["btn"])
        st.map("Treeview", background=[("selected", c["sel"])], foreground=[("selected", "#ffffff")])
        st.configure("Treeview.Heading", background=c["head"], foreground=c["fg"])
        st.map("Treeview.Heading", background=[("active", c["btn_active"])])
        for sb in ("TScrollbar", "Horizontal.TScrollbar", "Vertical.TScrollbar"):
            st.configure(sb, background=c["btn"], troughcolor=c["trough"],
                         bordercolor=c["btn"], arrowcolor=c["fg"])
        self.option_add("*TCombobox*Listbox.background", c["entry"])
        self.option_add("*TCombobox*Listbox.foreground", c["fg"])
        self.option_add("*TCombobox*Listbox.selectBackground", c["sel"])
        self.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

        self.configure(bg=c["panel"])
        self.editor.configure(bg=c["entry"], fg=c["fg"], insertbackground=c["fg"])
        self.items.configure(bg=c["entry"], fg=c["fg"],
                             selectbackground=c["sel"], selectforeground="#ffffff")
        self.tree.tag_configure("send", foreground=c["send"])
        self.tree.tag_configure("recv", foreground=c["recv"])
        self.tree.tag_configure("filtered", background=c["filt"])
        self._draw_theme_switch()
        if self.filter_win is not None:
            try:
                self.filter_win.apply_theme(c)
            except Exception:
                pass

    def _draw_theme_switch(self):
        c = self._colors
        cv = self.theme_switch
        cv.configure(bg=c["panel"])
        cv.delete("all")
        on = self.dark
        track = c["accent"] if on else "#b0b0b0"
        cv.create_oval(2, 2, 22, 22, fill=track, outline=track)
        cv.create_oval(26, 2, 46, 22, fill=track, outline=track)
        cv.create_rectangle(12, 2, 36, 22, fill=track, outline=track)
        kx = 36 if on else 12
        cv.create_oval(kx - 9, 3, kx + 9, 21, fill="#ffffff", outline="#ffffff")
        cv.create_text(kx, 12, text=("D" if on else "L"),
                       fill=track, font=("Segoe UI", 8, "bold"))

    def _toggle_theme(self):
        self.dark = not self.dark
        self._apply_theme()

    # -- process controls -------------------------------------------------
    def _refresh_procs(self):
        try:
            procs = self.ctrl.list_processes()
        except Exception as e:
            self.status.config(text=str(e), foreground="#a00")
            return
        values = [f"{p.name} ({p.pid})" for p in procs]
        self.proc_cb["values"] = values

    def _parse_target(self):
        text = self.proc_cb.get().strip()
        if not text:
            return None
        if text.endswith(")") and "(" in text:
            try:
                return int(text.rsplit("(", 1)[1].rstrip(")"))
            except ValueError:
                pass
        if text.isdigit():
            return int(text)
        return text  # process name

    def _start(self):
        target = self._parse_target()
        if target is None:
            messagebox.showwarning("P3DHex", "Elige o escribe un proceso (nombre o PID).")
            return
        try:
            self.ctrl.attach(target)
        except Exception as e:
            messagebox.showerror("P3DHex", f"No se pudo conectar:\n{e}")
            return
        self.attached = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.status.config(text=f"Conectado a {target}", foreground="#080")
        self._push_filters()   # aplica los filtros activos al proceso

    def _stop(self):
        self.ctrl.detach()
        self.attached = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status.config(text="Desconectado", foreground="#a00")

    # -- capture pipeline -------------------------------------------------
    def _pump(self):
        try:
            while True:
                kind, payload, data = self.q.get_nowait()
                if kind == "payload":
                    self._handle_payload(payload, data)
                elif kind == "error":
                    self.status.config(text=str(payload), foreground="#555")
                elif kind == "detached":
                    self._stop()
        except queue.Empty:
            pass
        # contador de envios en vivo
        self.count_lbl.config(text=f"Enviados: {self._send_count}")
        self.after(60, self._pump)

    def _handle_payload(self, payload, data):
        if not payload:
            return
        ev = payload.get("event")
        if ev == "ready":
            hooked = payload.get("hooked") or []
            module = payload.get("module")
            if not module:
                self.status.config(
                    text="ws2_32.dll no esta en el proceso: quiza no usa Winsock",
                    foreground="#a00")
            elif not hooked:
                self.status.config(text="No se pudo enganchar ninguna funcion",
                                   foreground="#a00")
            else:
                self.status.config(text=f"Enganchado: {', '.join(hooked)}",
                                   foreground="#080")
            return
        if ev == "stats":
            counts = payload.get("counts") or {}
            active = {k: v for k, v in counts.items() if v}
            if active:
                summary = "  ".join(f"{k}:{v}" for k, v in sorted(active.items()))
                self.title(f"P3DHex  [{summary}]")
            else:
                self.title("P3DHex  [sin trafico aun]")
            if self.filter_win is not None:
                try:
                    self.filter_win.update_hits()
                except Exception:
                    pass
            return
        if ev != "packet":
            return
        if self.pause_var.get():
            return
        socket = payload.get("socket", "?")
        direction = payload.get("dir", "?")
        fn = payload.get("fn", "?")
        raw = bytes(data) if data else b""

        if direction == "send":
            self.last_send_socket = socket
        if socket not in self.sockets:
            self.sockets.append(socket)
            self.socket_cb["values"] = self.sockets
            if not self.socket_cb.get():
                self.socket_cb.set(socket)

        hits = payload.get("filters") or []
        flt_names = []
        for h in hits:
            hid = h.get("id", "?") if isinstance(h, dict) else str(h)
            flt_names.append(hid)
            self.filter_hits[hid] = self.filter_hits.get(hid, 0) + 1
        flt_col = ",".join(flt_names)
        tags = (direction, "filtered") if flt_names else (direction,)

        rec = {"dir": direction, "fn": fn, "socket": socket, "data": raw}
        self.captures.append(rec)
        preview = bytes_to_hex(raw[:PREVIEW_BYTES]) + (" ..." if len(raw) > PREVIEW_BYTES else "")
        iid = self.tree.insert("", "end",
                               values=(direction, fn, socket, len(raw), flt_col, preview),
                               tags=tags)
        # keep list bounded
        if len(self.captures) > MAX_ROWS:
            self.captures.pop(0)
            first = self.tree.get_children()[0]
            self.tree.delete(first)
        self.tree.see(iid)

    def _clear_captures(self):
        self.captures.clear()
        self.tree.delete(*self.tree.get_children())

    def _index_of_iid(self, iid):
        return self.tree.index(iid)

    def _on_select_capture(self, _evt):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if 0 <= idx < len(self.captures):
            rec = self.captures[idx]
            self._set_editor(rec["data"])
            self.socket_cb.set(rec["socket"])

    def selected_capture_bytes(self):
        sel = self.tree.selection()
        if not sel:
            return None
        idx = self.tree.index(sel[0])
        if 0 <= idx < len(self.captures):
            return self.captures[idx]["data"]
        return None

    # -- editor -----------------------------------------------------------
    def _set_editor(self, data: bytes):
        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", bytes_to_hex(data))
        self._update_len()

    def _editor_bytes(self):
        return hex_to_bytes(self.editor.get("1.0", "end"))

    def _update_len(self):
        try:
            n = len(self._editor_bytes())
            self.len_lbl.config(text=f"{n} bytes", foreground="#000")
        except ValueError:
            self.len_lbl.config(text="hex invalido", foreground="#a00")

    def _pick_socket(self):
        return self.socket_cb.get().strip() or self.last_send_socket

    def _pick_list_socket(self):
        v = self.list_socket_var.get().strip()
        if v:
            return v
        return self.socket_cb.get().strip() or self.last_send_socket

    def _do_inject(self, data: bytes, sock=None):
        if not self.attached:
            messagebox.showwarning("P3DHex", "Primero conecta a un proceso (Start).")
            return False
        if sock is None:
            sock = self._pick_socket()
        if not sock:
            messagebox.showwarning("P3DHex",
                                   "No hay socket. Deja que la app envie algo primero, "
                                   "o selecciona un paquete 'send' capturado.")
            return False
        try:
            ret = self.ctrl.inject(sock, data)
        except Exception as e:
            messagebox.showerror("P3DHex", f"Fallo el inject:\n{e}")
            return False
        if ret is not None and ret < 0:
            self.status.config(text=f"inject devolvio {ret}", foreground="#a60")
        else:
            self.status.config(text=f"Enviados {len(data)} bytes (ret={ret})", foreground="#080")
        self._send_count = 1     # envio unico
        return True

    def _send_editor(self):
        try:
            data = self._editor_bytes()
        except ValueError as e:
            messagebox.showerror("P3DHex", str(e))
            return
        self._do_inject(data)

    def _send_editor_loop(self):
        if not self.attached:
            messagebox.showwarning("P3DHex", "Primero conecta a un proceso (Start).")
            return
        if self._loop_busy:
            messagebox.showinfo("P3DHex", "Ya hay un envio en curso. Usa 'Detener loop'.")
            return
        try:
            data = self._editor_bytes()
        except ValueError as e:
            messagebox.showerror("P3DHex", str(e))
            return
        if not data:
            return
        sock = self._pick_socket()
        if not sock:
            messagebox.showwarning("P3DHex",
                                   "No hay socket. Deja que la app envie algo primero.")
            return
        try:
            delay = max(0, int(self.ed_delay_var.get())) / 1000.0
        except ValueError:
            delay = 0.15
        try:
            loops = int(self.ed_loop_var.get())
        except ValueError:
            loops = 1
        if loops <= 0:
            loops = 1
        continuous = self.ed_continuous_var.get()

        self._loop_stop.clear()
        self._loop_busy = True
        self._send_count = 0     # reinicia el contador en cada envio

        def worker():
            sent = 0
            i = 0
            while not self._loop_stop.is_set():
                if not continuous and i >= loops:
                    break
                try:
                    self.ctrl.inject(sock, data)
                except Exception:
                    pass
                sent += 1
                self._send_count = sent
                if delay:
                    time.sleep(delay)
                i += 1
            self._loop_busy = False
            if continuous:
                msg = f"Editor: envio continuo detenido ({sent} envios)"
            else:
                msg = f"Editor: {sent} envios"
            self.q.put(("error", msg, None))

        threading.Thread(target=worker, daemon=True).start()

    # -- send lists -------------------------------------------------------
    def _load_lists(self):
        if os.path.exists(LISTS_PATH):
            try:
                with open(LISTS_PATH, "r", encoding="utf-8") as f:
                    self.sendlists = json.load(f)
            except Exception:
                self.sendlists = {}
        if not self.sendlists:
            self.sendlists = {"Default": []}
        self._refresh_list_names()

    def _save_lists(self):
        try:
            with open(LISTS_PATH, "w", encoding="utf-8") as f:
                json.dump(self.sendlists, f, indent=2)
        except Exception as e:
            messagebox.showerror("P3DHex", f"No se pudo guardar sendlists.json:\n{e}")

    def _refresh_list_names(self):
        names = list(self.sendlists.keys())
        self.list_cb["values"] = names
        if names and self.list_cb.get() not in names:
            self.list_cb.set(names[0])
        self._refresh_list_items()

    def _current_list(self):
        name = self.list_cb.get()
        return name if name in self.sendlists else None

    def _refresh_list_items(self):
        self.items.delete(0, "end")
        name = self._current_list()
        if not name:
            return
        for it in self.sendlists[name]:
            label = it.get("name") or "(sin nombre)"
            self.items.insert("end", f"{label}   [{it['hex'][:40]}]")

    def _new_list(self):
        name = _prompt(self, "Nueva lista", "Nombre de la lista:")
        if not name:
            return
        if name in self.sendlists:
            messagebox.showinfo("P3DHex", "Ya existe esa lista.")
            return
        self.sendlists[name] = []
        self._save_lists()
        self.list_cb.set(name)
        self._refresh_list_names()

    def _del_list(self):
        name = self._current_list()
        if not name:
            return
        if messagebox.askyesno("P3DHex", f"Borrar la lista '{name}'?"):
            del self.sendlists[name]
            if not self.sendlists:
                self.sendlists = {"Default": []}
            self._save_lists()
            self._refresh_list_names()

    def _add_to_list(self):
        try:
            data = self._editor_bytes()
        except ValueError as e:
            messagebox.showerror("P3DHex", str(e))
            return
        if not self.sendlists:
            self.sendlists = {"Default": []}
        name = self._choose_list("Anadir a lista")
        if not name:
            return
        label = _prompt(self, "Anadir paquete", "Nombre del paquete:") or f"pkt{len(self.sendlists[name]) + 1}"
        self.sendlists[name].append({"name": label, "hex": bytes_to_hex(data)})
        self._save_lists()
        self.list_cb.set(name)          # muestra la lista destino
        self._refresh_list_names()
        self.status.config(text=f"Paquete anadido a '{name}'", foreground="#080")

    def _choose_list(self, title):
        names = list(self.sendlists.keys())
        if not names:
            return None
        if len(names) == 1:
            return names[0]
        top = tk.Toplevel(self)
        top.title(title)
        top.transient(self)
        top.grab_set()
        try:
            top.configure(bg=self._colors["panel"])
        except Exception:
            pass
        ttk.Label(top, text="Enviar el paquete a la lista:", padding=8).pack()
        var = tk.StringVar(value=self._current_list() or names[0])
        cb = ttk.Combobox(top, textvariable=var, values=names, state="readonly", width=30)
        cb.pack(padx=10)
        res = {"v": None}

        def ok():
            res["v"] = var.get()
            top.destroy()

        row = ttk.Frame(top, padding=8)
        row.pack()
        ttk.Button(row, text="OK", command=ok).pack(side="left", padx=4)
        ttk.Button(row, text="Cancelar", command=top.destroy).pack(side="left")
        self.wait_window(top)
        return res["v"]

    def _export_list(self):
        name = self._current_list()
        if not name:
            messagebox.showwarning("P3DHex", "Elige una lista para exportar.")
            return
        path = filedialog.asksaveasfilename(
            title="Exportar lista", defaultextension=".json",
            initialfile=f"{name}.json",
            filetypes=[("Lista P3DHex", "*.json"), ("Todos", "*.*")])
        if not path:
            return
        payload = {"name": name, "items": self.sendlists[name]}
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            self.status.config(text=f"Lista '{name}' exportada", foreground="#080")
        except Exception as e:
            messagebox.showerror("P3DHex", f"No se pudo exportar:\n{e}")

    def _import_list(self):
        path = filedialog.askopenfilename(
            title="Importar lista",
            filetypes=[("Lista P3DHex", "*.json"), ("Todos", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("P3DHex", f"No se pudo leer el archivo:\n{e}")
            return

        # Accept: {"name","items"}, a bare list [...], or a full {name: [...]} dict.
        imported = {}
        if isinstance(data, dict) and "items" in data:
            imported[data.get("name") or "Importada"] = data["items"]
        elif isinstance(data, list):
            base = os.path.splitext(os.path.basename(path))[0] or "Importada"
            imported[base] = data
        elif isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list):
                    imported[k] = v
        if not imported:
            messagebox.showerror("P3DHex", "El archivo no tiene un formato de lista valido.")
            return

        last = None
        for name, items in imported.items():
            clean = [it for it in items if isinstance(it, dict) and "hex" in it]
            target = name
            n = 2
            while target in self.sendlists:      # no sobreescribir: renombra
                target = f"{name} ({n})"
                n += 1
            self.sendlists[target] = clean
            last = target
        self._save_lists()
        if last:
            self.list_cb.set(last)
        self._refresh_list_names()
        self.status.config(text=f"Importadas {len(imported)} lista(s)", foreground="#080")

    def _selected_item_index(self):
        sel = self.items.curselection()
        return sel[0] if sel else None

    def _load_item_to_editor(self):
        name = self._current_list()
        idx = self._selected_item_index()
        if name is None or idx is None:
            return
        it = self.sendlists[name][idx]
        try:
            self._set_editor(hex_to_bytes(it["hex"]))
        except ValueError:
            self.editor.delete("1.0", "end")
            self.editor.insert("1.0", it["hex"])
            self._update_len()

    def _edit_item(self):
        name = self._current_list()
        idx = self._selected_item_index()
        if name is None or idx is None:
            messagebox.showwarning("P3DHex", "Selecciona un item de la lista.")
            return
        it = self.sendlists[name][idx]
        result = self._edit_item_dialog(it.get("name", ""), it.get("hex", ""))
        if result is None:
            return
        new_name, new_hex = result
        try:
            data = hex_to_bytes(new_hex)
        except ValueError as e:
            messagebox.showerror("P3DHex", str(e))
            return
        it["name"] = new_name or it.get("name", "")
        it["hex"] = bytes_to_hex(data)          # normaliza el hex
        self._save_lists()                       # guarda permanente
        self._refresh_list_items()
        self.items.selection_set(idx)
        self.status.config(text=f"Item editado en '{name}'", foreground="#080")

    def _edit_item_dialog(self, cur_name, cur_hex):
        top = tk.Toplevel(self)
        top.title("Editar item")
        top.transient(self)
        top.grab_set()
        try:
            top.configure(bg=self._colors["panel"])
        except Exception:
            pass
        ttk.Label(top, text="Nombre:").pack(anchor="w", padx=8, pady=(8, 2))
        nvar = tk.StringVar(value=cur_name)
        ttk.Entry(top, textvariable=nvar, width=44).pack(fill="x", padx=8)
        ttk.Label(top, text="Hex:").pack(anchor="w", padx=8, pady=(8, 2))
        txt = tk.Text(top, height=6, width=50, font=("Consolas", 10))
        txt.pack(fill="both", expand=True, padx=8)
        txt.insert("1.0", cur_hex)
        try:
            txt.configure(bg=self._colors["entry"], fg=self._colors["fg"],
                          insertbackground=self._colors["fg"])
        except Exception:
            pass
        res = {"v": None}

        def ok():
            res["v"] = (nvar.get().strip(), txt.get("1.0", "end"))
            top.destroy()

        rowb = ttk.Frame(top, padding=8)
        rowb.pack(fill="x")
        ttk.Button(rowb, text="Guardar", command=ok).pack(side="left")
        ttk.Button(rowb, text="Cancelar", command=top.destroy).pack(side="left", padx=4)
        self.wait_window(top)
        return res["v"]

    def _remove_item(self):
        name = self._current_list()
        idx = self._selected_item_index()
        if name is None or idx is None:
            return
        del self.sendlists[name][idx]
        self._save_lists()
        self._refresh_list_items()

    def _move_item(self, delta):
        name = self._current_list()
        idx = self._selected_item_index()
        if name is None or idx is None:
            return
        new = idx + delta
        lst = self.sendlists[name]
        if 0 <= new < len(lst):
            lst[idx], lst[new] = lst[new], lst[idx]
            self._save_lists()
            self._refresh_list_items()
            self.items.selection_set(new)

    def _send_item(self):
        name = self._current_list()
        idx = self._selected_item_index()
        if name is None or idx is None:
            messagebox.showwarning("P3DHex", "Selecciona un item de la lista.")
            return
        try:
            data = hex_to_bytes(self.sendlists[name][idx]["hex"])
        except ValueError as e:
            messagebox.showerror("P3DHex", str(e))
            return
        self._do_inject(data, self._pick_list_socket())

    def _send_whole_list(self):
        name = self._current_list()
        if not name or not self.sendlists[name]:
            return
        if not self.attached:
            messagebox.showwarning("P3DHex", "Conecta a un proceso primero.")
            return
        if self._loop_busy:
            messagebox.showinfo("P3DHex", "Ya hay un envio en curso. Usa 'Detener loop'.")
            return
        try:
            delay = max(0, int(self.delay_var.get())) / 1000.0
        except ValueError:
            delay = 0.15
        try:
            loops = int(self.loop_var.get())
        except ValueError:
            loops = 1
        if loops <= 0:
            loops = 1
        items = list(self.sendlists[name])
        sock = self._pick_list_socket()
        if not sock:
            messagebox.showwarning("P3DHex",
                                   "No hay socket destino. Elige uno en 'Socket destino' "
                                   "o deja que el juego envie algo (Auto).")
            return

        continuous = self.continuous_var.get()

        self._loop_stop.clear()
        self._loop_busy = True
        self._send_count = 0     # reinicia el contador en cada envio

        def worker():
            sent = 0
            i = 0
            while not self._loop_stop.is_set():
                if not continuous and i >= loops:
                    break
                for it in items:
                    if self._loop_stop.is_set():
                        break
                    try:
                        data = hex_to_bytes(it["hex"])
                    except ValueError:
                        continue
                    try:
                        self.ctrl.inject(sock, data)
                    except Exception:
                        pass
                    sent += 1
                    self._send_count = sent
                    if delay:
                        time.sleep(delay)
                i += 1
            self._loop_busy = False
            stopped = self._loop_stop.is_set()
            if continuous:
                msg = f"Envio continuo detenido: {sent} paquetes"
            elif stopped:
                msg = f"Loop detenido: {sent} paquetes enviados"
            else:
                msg = f"Lista '{name}' enviada x{loops} ({sent} paquetes)"
            self.q.put(("error", msg, None))

        threading.Thread(target=worker, daemon=True).start()

    def _stop_loop(self):
        self._loop_stop.set()

    # -- filters ----------------------------------------------------------
    def _load_filters(self):
        if os.path.exists(FILTERS_PATH):
            try:
                with open(FILTERS_PATH, "r", encoding="utf-8") as f:
                    self.filters = json.load(f)
            except Exception:
                self.filters = []
        if not isinstance(self.filters, list):
            self.filters = []

    def _save_filters(self):
        try:
            with open(FILTERS_PATH, "w", encoding="utf-8") as f:
                json.dump(self.filters, f, indent=2)
        except Exception as e:
            messagebox.showerror("P3DHex", f"No se pudo guardar filters.json:\n{e}")

    def _filters_payload(self):
        """Only active filters, converted to the agent's compact format."""
        out = []
        for f in self.filters:
            if not f.get("active"):
                continue
            try:
                search = [{"o": int(k), "v": int(v, 16)} for k, v in f.get("search", {}).items()]
                modify = [{"o": int(k), "v": int(v, 16)} for k, v in f.get("modify", {}).items()]
            except (ValueError, TypeError):
                continue
            out.append({
                "id": f.get("name", "?"),
                "active": True,
                "onSend": bool(f.get("onSend", True)),
                "onRecv": bool(f.get("onRecv", True)),
                "search": search, "modify": modify,
            })
        return out

    def _push_filters(self):
        if not self.attached:
            if self.filter_win is not None:
                self.filter_win.set_push_status("Proceso NO conectado: da Start para aplicar", False)
            return
        payload = self._filters_payload()
        try:
            n = self.ctrl.set_filters(payload)
        except Exception as e:
            msg = f"Error aplicando filtros: {e}"
            self.status.config(text=msg, foreground="#a00")
            if self.filter_win is not None:
                self.filter_win.set_push_status(msg, False)
            return
        if payload:
            txt = f"{len(payload)} filtro(s) activo(s) aplicado(s) al proceso  (confirmado: {n})"
            self.status.config(text=txt, foreground="#080")
            if self.filter_win is not None:
                self.filter_win.set_push_status("APLICADO al proceso: "
                                                f"{len(payload)} filtro(s) activo(s)", True)
        else:
            self.status.config(text="Sin filtros activos (marca [x] alguno)", foreground="#a60")
            if self.filter_win is not None:
                self.filter_win.set_push_status("Ningun filtro activo ([x]). "
                                                "Actívalo con doble clic.", False)

    def _open_filters(self):
        if self.filter_win is not None and tk.Toplevel.winfo_exists(self.filter_win):
            self.filter_win.lift()
            return
        self.filter_win = FilterWindow(self)
        self._push_filters()   # refleja el estado real en la ventana

    # -- shutdown ---------------------------------------------------------
    def _on_close(self):
        try:
            self.ctrl.detach()
        finally:
            self.destroy()


class FilterWindow(tk.Toplevel):
    """WPE-style filter editor: offset grid with Search / Modify rows."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Filtros (Search / Modify)")
        self.geometry("980x420")
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.search_e = []
        self.modify_e = []
        self._cur = None
        self.grid_canvas = None
        self._build()
        self._refresh_list()
        try:
            self.apply_theme(app._colors)
        except Exception:
            pass

    def apply_theme(self, c):
        self.configure(bg=c["panel"])
        try:
            self.lb.configure(bg=c["entry"], fg=c["fg"],
                              selectbackground=c["sel"], selectforeground="#ffffff")
        except Exception:
            pass
        for e in self.search_e + self.modify_e:
            try:
                e.configure(bg=c["entry"], fg=c["fg"], insertbackground=c["fg"])
            except Exception:
                pass
        if self.grid_canvas is not None:
            try:
                self.grid_canvas.configure(bg=c["panel"])
            except Exception:
                pass

    def _build(self):
        left = ttk.Frame(self, padding=6)
        left.pack(side="left", fill="y")
        ttk.Label(left, text="Filtros (marca los activos):").pack(anchor="w")
        self.lb = tk.Listbox(left, width=26, height=16, font=("Consolas", 9),
                             exportselection=False)
        self.lb.pack(fill="y", expand=True)
        self.lb.bind("<<ListboxSelect>>", lambda e: self._load_selected())
        self.lb.bind("<Double-Button-1>", lambda e: self._toggle_active())

        b = ttk.Frame(left)
        b.pack(fill="x", pady=4)
        ttk.Button(b, text="Nuevo", command=self._new).pack(side="left")
        ttk.Button(b, text="Borrar", command=self._delete).pack(side="left", padx=3)
        ttk.Button(left, text="Activar / Desactivar (doble clic)",
                   command=self._toggle_active).pack(fill="x", pady=(0, 4))

        right = ttk.Frame(self, padding=6)
        right.pack(side="left", fill="both", expand=True)

        opt = ttk.Frame(right)
        opt.pack(fill="x")
        self.on_send = tk.BooleanVar(value=True)
        self.on_recv = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Aplicar en envios (send)", variable=self.on_send).pack(side="left")
        ttk.Checkbutton(opt, text="Aplicar en recepciones (recv)", variable=self.on_recv).pack(side="left", padx=10)

        self.pushlbl = ttk.Label(right, text="Estado: sin aplicar todavia", foreground="#a60")
        self.pushlbl.pack(anchor="w", pady=(4, 0))

        ttk.Label(right, foreground="#888",
                  text="Offsets 001+ (igual que WPE/rPE). Search = byte que debe coincidir "
                       "(vacio = cualquiera). Modify = byte a reescribir (vacio = no cambia). "
                       "Hex, ej: 47").pack(anchor="w", pady=(4, 2))

        wrap = ttk.Frame(right)
        wrap.pack(fill="x")
        canvas = tk.Canvas(wrap, height=110, highlightthickness=0)
        self.grid_canvas = canvas
        hbar = ttk.Scrollbar(wrap, orient="horizontal", command=canvas.xview)
        canvas.configure(xscrollcommand=hbar.set)
        canvas.pack(side="top", fill="x", expand=True)
        hbar.pack(side="bottom", fill="x")
        inner = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        ttk.Label(inner, text="Offset").grid(row=0, column=0, sticky="e", padx=3)
        ttk.Label(inner, text="Search").grid(row=1, column=0, sticky="e", padx=3)
        ttk.Label(inner, text="Modify").grid(row=2, column=0, sticky="e", padx=3)
        for c in range(FILTER_COLS):
            col = c + 1
            ttk.Label(inner, text=f"{c + 1:03}", width=3, anchor="center").grid(row=0, column=col)
            e1 = tk.Entry(inner, width=3, justify="center", font=("Consolas", 9))
            e1.grid(row=1, column=col, padx=1)
            e2 = tk.Entry(inner, width=3, justify="center", font=("Consolas", 9))
            e2.grid(row=2, column=col, padx=1)
            self.search_e.append(e1)
            self.modify_e.append(e2)

        actions = ttk.Frame(right)
        actions.pack(fill="x", pady=8)
        ttk.Button(actions, text="Guardar filtro", command=self._save_current).pack(side="left")
        ttk.Button(actions, text="Limpiar rejilla", command=self._clear_grid).pack(side="left", padx=6)
        ttk.Button(actions, text="Reiniciar hits", command=self._reset_hits).pack(side="left")
        self.info = ttk.Label(actions, text="", foreground="#080")
        self.info.pack(side="left", padx=10)

    # -- list helpers -----------------------------------------------------
    def _refresh_list(self, select=None):
        self.lb.delete(0, "end")
        for f in self.app.filters:
            mark = "[x]" if f.get("active") else "[ ]"
            name = f.get("name", "?")
            hits = self.app.filter_hits.get(name, 0)
            self.lb.insert("end", f"{mark} {name}  (hits: {hits})")
        if select is not None and 0 <= select < len(self.app.filters):
            self.lb.selection_clear(0, "end")
            self.lb.selection_set(select)
            self._cur = select
            self._load_into_grid(self.app.filters[select])

    def update_hits(self):
        """Refresh only the hit counters, keeping the current selection/grid."""
        sel = self._sel_index()
        self.lb.delete(0, "end")
        for f in self.app.filters:
            mark = "[x]" if f.get("active") else "[ ]"
            name = f.get("name", "?")
            hits = self.app.filter_hits.get(name, 0)
            self.lb.insert("end", f"{mark} {name}  (hits: {hits})")
        if sel is not None and sel < len(self.app.filters):
            self.lb.selection_set(sel)

    def _sel_index(self):
        s = self.lb.curselection()
        return s[0] if s else None

    def _new(self):
        name = _prompt(self, "Nuevo filtro", "Nombre del filtro:")
        if not name:
            return
        self.app.filters.append({"name": name, "active": True,
                                 "onSend": True, "onRecv": True,
                                 "search": {}, "modify": {}})
        self.app._save_filters()
        self.app._push_filters()
        self._refresh_list(select=len(self.app.filters) - 1)

    def _delete(self):
        idx = self._sel_index()
        if idx is None:
            return
        del self.app.filters[idx]
        self.app._save_filters()
        self.app._push_filters()
        self._cur = None
        self._clear_grid()
        self._refresh_list()

    def _toggle_active(self):
        idx = self._sel_index()
        if idx is None:
            return
        self.app.filters[idx]["active"] = not self.app.filters[idx].get("active")
        self.app._save_filters()
        self.app._push_filters()
        self._refresh_list(select=idx)

    # -- grid <-> model ---------------------------------------------------
    def _clear_grid(self):
        for e in self.search_e:
            e.delete(0, "end")
        for e in self.modify_e:
            e.delete(0, "end")

    def _load_selected(self):
        idx = self._sel_index()
        if idx is None:
            return
        self._cur = idx
        self._load_into_grid(self.app.filters[idx])

    def _load_into_grid(self, f):
        self._clear_grid()
        self.on_send.set(bool(f.get("onSend", True)))
        self.on_recv.set(bool(f.get("onRecv", True)))
        for k, v in f.get("search", {}).items():
            c = int(k)
            if 0 <= c < FILTER_COLS:
                self.search_e[c].insert(0, str(v).upper())
        for k, v in f.get("modify", {}).items():
            c = int(k)
            if 0 <= c < FILTER_COLS:
                self.modify_e[c].insert(0, str(v).upper())

    def _read_row(self, entries):
        out = {}
        for c, e in enumerate(entries):
            t = e.get().strip()
            if not t:
                continue
            try:
                out[str(c)] = f"{int(t, 16):02X}"
            except ValueError:
                raise ValueError(f"Offset {c}: '{t}' no es hex valido (usa 00-FF).")
        return out

    def _save_current(self):
        idx = self._sel_index() if self._cur is None else self._cur
        if idx is None or idx >= len(self.app.filters):
            messagebox.showwarning("Filtros", "Selecciona o crea un filtro primero.")
            return
        try:
            search = self._read_row(self.search_e)
            modify = self._read_row(self.modify_e)
        except ValueError as e:
            messagebox.showerror("Filtros", str(e))
            return
        f = self.app.filters[idx]
        f["search"] = search
        f["modify"] = modify
        f["onSend"] = self.on_send.get()
        f["onRecv"] = self.on_recv.get()
        self.app._save_filters()
        self.app._push_filters()
        self.info.config(text="Guardado y aplicado")
        self.after(1500, lambda: self.info.config(text=""))

    def set_push_status(self, text, ok=True):
        self.pushlbl.config(text="Estado: " + text, foreground="#080" if ok else "#a00")

    def _reset_hits(self):
        self.app.filter_hits.clear()
        self.update_hits()

    def _close(self):
        self.app.filter_win = None
        self.destroy()


def _prompt(parent, title, label):
    """Tiny modal text prompt (avoids importing simpledialog styling issues)."""
    top = tk.Toplevel(parent)
    top.title(title)
    top.transient(parent)
    top.grab_set()
    try:
        colors = getattr(parent, "_colors", None) or getattr(parent.app, "_colors", None)
        if colors:
            top.configure(bg=colors["panel"])
    except Exception:
        pass
    ttk.Label(top, text=label, padding=8).pack()
    var = tk.StringVar()
    ent = ttk.Entry(top, textvariable=var, width=32)
    ent.pack(padx=8)
    ent.focus_set()
    result = {"val": None}

    def ok():
        result["val"] = var.get().strip()
        top.destroy()

    def cancel():
        top.destroy()

    row = ttk.Frame(top, padding=8)
    row.pack()
    ttk.Button(row, text="OK", command=ok).pack(side="left", padx=4)
    ttk.Button(row, text="Cancelar", command=cancel).pack(side="left")
    ent.bind("<Return>", lambda e: ok())
    parent.wait_window(top)
    return result["val"]


if __name__ == "__main__":
    if frida is None:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("P3DHex",
                             "Falta el modulo 'frida'.\n\nInstala con:\n    pip install frida")
        sys.exit(1)
    App().mainloop()
