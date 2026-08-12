'use strict';

/*
 * Winsock capture + live filters (Frida agent).
 *
 * Data buffers are read from the exact arguments the app passes to Winsock.
 * Timing of asynchronous receives is taken from the IOCP completion
 * (ntdll!NtRemoveIoCompletion / ...Ex) or WSAGetOverlappedResult.
 *
 * Filters (WPE-style) can rewrite bytes in place before a send goes out or
 * before the app reads a received buffer. Each filter has a Search pattern
 * (offset -> byte that must match) and a Modify pattern (offset -> byte to
 * write); if all Search bytes match, the Modify bytes are written.
 *
 * Covers: send/recv, sendto/recvfrom, WSASend/WSASendTo, WSARecv/WSARecvFrom
 * (synchronous AND overlapped/async). Injection uses ws2_32!send.
 */

const PSIZE = Process.pointerSize;
const ABI = Process.arch === 'ia32' ? 'stdcall' : 'default';
const STRIDE = PSIZE * 2;               // WSABUF { ULONG len; CHAR* buf; } aligned
const STATUS_SUCCESS = 0x0;

const counts = {};
function bump(name) { counts[name] = (counts[name] || 0) + 1; }

let filters = [];                       // [{active,onSend,onRecv,search:[{o,v}],modify:[{o,v}]}]
const pending = {};                     // async recvs keyed by OVERLAPPED ptr

function loadMod(name) {
    try { return Module.load(name); } catch (e) {}
    try { return Process.findModuleByName(name); } catch (e) {}
    return null;
}
function expOf(mod, name) {
    if (!mod) return null;
    try { const a = mod.getExportByName(name); return (a && !a.isNull()) ? a : null; }
    catch (e) { return null; }
}

const ws2 = loadMod('ws2_32.dll');
const ntdll = loadMod('ntdll.dll');

const sendPtr = expOf(ws2, 'send');
const sendFn = sendPtr
    ? new NativeFunction(sendPtr, 'int', ['pointer', 'pointer', 'int', 'int'], ABI)
    : null;

// ---- filters ------------------------------------------------------------

function applyFilters(dir, ptr, len) {
    const hits = [];
    if (!filters.length || !ptr || ptr.isNull() || len <= 0) return hits;
    for (let fi = 0; fi < filters.length; fi++) {
        const f = filters[fi];
        if (!f.active) continue;
        if (dir === 'send' && !f.onSend) continue;
        if (dir === 'recv' && !f.onRecv) continue;

        let match = true;
        for (let i = 0; i < f.search.length; i++) {
            const s = f.search[i];
            if (s.o >= len) { match = false; break; }
            let cur;
            try { cur = ptr.add(s.o).readU8(); } catch (e) { match = false; break; }
            if (cur !== s.v) { match = false; break; }
        }
        if (!match) continue;

        let modified = false;
        for (let i = 0; i < f.modify.length; i++) {
            const m = f.modify[i];
            if (m.o >= len) continue;
            try { ptr.add(m.o).writeU8(m.v); modified = true; } catch (e) {}
        }
        const id = f.id || '?';
        hits.push({ id: id, mod: modified });
        bump('filter:' + id);
    }
    return hits;
}

// apply filters (may rewrite the buffer) then stream the final bytes to the GUI
function processBuffer(dir, fn, socket, ptr, len) {
    if (len <= 0 || !ptr || ptr.isNull()) return;
    const hits = applyFilters(dir, ptr, len);
    try {
        const data = ptr.readByteArray(len);
        send({ event: 'packet', dir: dir, fn: fn, socket: socket.toString(),
               len: len, filters: hits }, data);
    } catch (e) { /* unreadable */ }
}

// Walk a WSABUF array, processing up to `cap` bytes total (undefined = all).
function emitBuffers(dir, fn, socket, bufArray, bufCount, cap) {
    if (!bufArray || bufArray.isNull() || bufCount <= 0) return;
    let remaining = (cap === undefined) ? Infinity : cap;
    for (let i = 0; i < bufCount && remaining > 0; i++) {
        try {
            const rec = bufArray.add(i * STRIDE);
            const blen = rec.readU32();
            const bptr = rec.add(PSIZE).readPointer();
            const n = (remaining === Infinity) ? blen : Math.min(blen, remaining);
            processBuffer(dir, fn, socket, bptr, n);
            if (remaining !== Infinity) remaining -= n;
        } catch (e) { break; }
    }
}

// ---- synchronous send/recv, sendto/recvfrom -----------------------------

function hookSimple(fnName, dir, onLeaveRead) {
    const addr = expOf(ws2, fnName);
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) {
            bump(fnName);
            this.socket = args[0]; this.buf = args[1]; this.len = args[2].toInt32();
            if (!onLeaveRead) processBuffer(dir, fnName, this.socket, this.buf, this.len);
        },
        onLeave(retval) {
            if (onLeaveRead) processBuffer(dir, fnName, this.socket, this.buf, retval.toInt32());
        }
    });
    return true;
}

// ---- WSASend / WSASendTo ------------------------------------------------

function hookWsaSend(fnName) {
    const addr = expOf(ws2, fnName);
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) {
            bump(fnName);
            emitBuffers('send', fnName, args[0], args[1], args[2].toInt32());
        }
    });
    return true;
}

// ---- WSARecv / WSARecvFrom ----------------------------------------------

function hookWsaRecv(fnName, ovIdx) {
    const addr = expOf(ws2, fnName);
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) {
            bump(fnName);
            this.socket = args[0];
            this.arr = args[1];
            this.count = args[2].toInt32();
            this.lpRecvd = args[3];
            this.ov = args[ovIdx];
            if (this.ov && !this.ov.isNull()) {
                pending[this.ov.toString()] = {
                    socket: this.socket, arr: this.arr, count: this.count, fn: fnName
                };
            }
        },
        onLeave(retval) {
            if (retval.toInt32() === 0) {
                let n = 0;
                try { if (this.lpRecvd && !this.lpRecvd.isNull()) n = this.lpRecvd.readU32(); }
                catch (e) { n = 0; }
                if (n > 0) {
                    emitBuffers('recv', fnName, this.socket, this.arr, this.count, n);
                    if (this.ov && !this.ov.isNull()) delete pending[this.ov.toString()];
                }
            }
        }
    });
    return true;
}

// ---- async completion capture -------------------------------------------

function completeRecv(ovStr, nbytes) {
    const p = pending[ovStr];
    if (!p || nbytes <= 0) return;
    delete pending[ovStr];
    emitBuffers('recv', p.fn, p.socket, p.arr, p.count, nbytes);
    bump('recv_async');
}

function iosbInformation(iosb) {
    try { return iosb.add(PSIZE).readU32(); } catch (e) { return 0; }
}

function hookNtRemoveIoCompletion() {
    const addr = expOf(ntdll, 'NtRemoveIoCompletion');
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) { this.apcOut = args[2]; this.iosbOut = args[3]; },
        onLeave(retval) {
            if (retval.toInt32() !== STATUS_SUCCESS) return;
            let apc = null;
            try { apc = this.apcOut.readPointer(); } catch (e) { return; }
            if (!apc || apc.isNull()) return;
            const ovStr = apc.toString();
            if (!pending[ovStr]) return;
            completeRecv(ovStr, iosbInformation(this.iosbOut));
        }
    });
    return true;
}

function hookNtRemoveIoCompletionEx() {
    const addr = expOf(ntdll, 'NtRemoveIoCompletionEx');
    if (!addr) return false;
    const ENTRY = PSIZE * 4;
    Interceptor.attach(addr, {
        onEnter(args) { this.info = args[1]; this.numOut = args[3]; },
        onLeave(retval) {
            if (retval.toInt32() !== STATUS_SUCCESS) return;
            let num = 0;
            try { num = this.numOut.readU32(); } catch (e) { return; }
            for (let i = 0; i < num; i++) {
                try {
                    const base = this.info.add(i * ENTRY);
                    const apc = base.add(PSIZE).readPointer();
                    if (!apc || apc.isNull()) continue;
                    const ovStr = apc.toString();
                    if (!pending[ovStr]) continue;
                    completeRecv(ovStr, base.add(PSIZE * 3).readU32());
                } catch (e) { /* skip */ }
            }
        }
    });
    return true;
}

function hookWsaGetOverlappedResult() {
    const addr = expOf(ws2, 'WSAGetOverlappedResult');
    if (!addr) return false;
    Interceptor.attach(addr, {
        onEnter(args) { this.ov = args[1]; this.lpcb = args[2]; },
        onLeave(retval) {
            if (retval.toInt32() === 0) return;
            if (!this.ov || this.ov.isNull()) return;
            const ovStr = this.ov.toString();
            if (!pending[ovStr]) return;
            let n = 0;
            try { if (this.lpcb && !this.lpcb.isNull()) n = this.lpcb.readU32(); } catch (e) { return; }
            completeRecv(ovStr, n);
        }
    });
    return true;
}

// ---- install ------------------------------------------------------------

const hooked = [];
function reg(name, ok) { if (ok) hooked.push(name); }

reg('send', hookSimple('send', 'send', false));
reg('recv', hookSimple('recv', 'recv', true));
reg('sendto', hookSimple('sendto', 'send', false));
reg('recvfrom', hookSimple('recvfrom', 'recv', true));
reg('WSASend', hookWsaSend('WSASend'));
reg('WSASendTo', hookWsaSend('WSASendTo'));
reg('WSARecv', hookWsaRecv('WSARecv', 5));
reg('WSARecvFrom', hookWsaRecv('WSARecvFrom', 7));
reg('NtRemoveIoCompletion', hookNtRemoveIoCompletion());
reg('NtRemoveIoCompletionEx', hookNtRemoveIoCompletionEx());
reg('WSAGetOverlappedResult', hookWsaGetOverlappedResult());

send({
    event: 'ready',
    hasSend: !!sendFn,
    module: ws2 ? ws2.name : null,
    hooked: hooked
});

setInterval(function () { send({ event: 'stats', counts: counts }); }, 1000);

// ---- RPC ----------------------------------------------------------------

rpc.exports = {
    inject: function (socketStr, bytes) {
        if (!sendFn) return -2;
        const socket = ptr(socketStr);
        const len = bytes.length || 0;
        const buf = Memory.alloc(len > 0 ? len : 1);
        if (len > 0) buf.writeByteArray(bytes);
        try { return sendFn(socket, buf, len, 0); }
        catch (e) { return -1; }
    },
    setFilters: function (list) {
        filters = Array.isArray(list) ? list : [];
        return filters.length;
    }
};
