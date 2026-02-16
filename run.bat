@echo off
setlocal
cd /d %~dp0

if not exist venv (
    echo [System] 가상환경을 생성 중입니다...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo [System] 필수 라이브러리 체크 중...
pip install -r requirements.txt --quiet

echo [System] SimpleFTP Pro를 시작합니다...
python src/main.py
pause
