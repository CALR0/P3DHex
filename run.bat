@echo off
REM Launcher for P3DHex. Installs frida on first run if missing.
cd /d "%~dp0"
python -c "import frida" 2>nul
if errorlevel 1 (
    echo Instalando dependencias ^(frida^)...
    python -m pip install -r requirements.txt
)
python main.py
if errorlevel 1 pause
