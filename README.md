# P3DHex

Editor de paquetes estilo **WPE Pro / rPE** para Windows. Se engancha a un
proceso, intercepta los paquetes de Winsock (`send`, `recv`, `WSASend`,
`WSARecv`), te deja **editar los bytes y reenviarlos**, y administra
**send-lists** (grupos de paquetes guardados, editables, que puedes disparar
uno por uno o en secuencia con delay).

El enganche lo hace **Frida** (inyecta el agente en el proceso, igual que la
DLL de WPE); la GUI está hecha en Python + Tkinter.

## Requisitos
- Windows 10/11 y **Python 3.8+** (marca "Add Python to PATH" al instalarlo).
- Frida (se instala solo la primera vez con `run.bat`).

## Uso rapido
1. Doble clic en **`run.bat`** (instala frida si falta y abre la app).
2. Elige el proceso en el desplegable (o escribe nombre/PID) y pulsa **Start**.
3. Deja que la aplicacion mande/reciba datos: veras los paquetes en la lista.
4. Haz clic en un paquete -> se carga en el **Editor**. Cambia el hex.
5. **Send** lo reinyecta por el socket. **Anadir a lista** lo guarda.
6. En **Send Lists**: crea listas, ordena, y usa *Send lista completa* con delay.

> **Send** usa un socket ya conectado que la app haya usado. Si aun no hay
> socket, deja que el programa envie algo primero o selecciona un paquete
> `send` capturado antes de inyectar.

## Generar el .exe
Ejecuta **`build.bat`**. El ejecutable queda en `dist\P3DHex.exe`.
`sendlists.json` se crea junto al `.exe` para conservar tus listas.
