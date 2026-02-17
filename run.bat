@echo off
setlocal
cd /d %~dp0

if not exist venv (
    echo [System] Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo [System] Checking required libraries...
set PYTHONUTF8=1
pip install -r requirements.txt --quiet

echo [System] Starting SimpleFTP Pro...
start "" "pythonw" "src/main.py"
