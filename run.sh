#!/bin/bash
BASE_DIR=$(cd "$(dirname "$0")"; pwd)
cd "$BASE_DIR"

if [ ! -d "venv" ]; then
    echo "[System] 가상환경을 찾을 수 없습니다. venv를 생성합니다..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

echo "[System] SimpleFTP Pro를 시작합니다..."
python3 src/main.py
