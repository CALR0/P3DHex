@echo off
REM Builds a standalone P3DHex.exe into the dist\ folder.
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller frida
pyinstaller --noconfirm --onefile --windowed ^
    --name P3DHex ^
    --add-data "hook.js;." ^
    --collect-all frida ^
    main.py
echo.
echo Listo. El ejecutable esta en:  dist\P3DHex.exe
echo (Copia hook.js junto al .exe si lo mueves de carpeta.)
pause
