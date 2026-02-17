#!/bin/bash
BASE_DIR=$(cd "$(dirname "$0")"; pwd)
cd "$BASE_DIR"

if [ ! -d "venv" ]; then
    echo "[System] Virtual environment not found. Creating venv..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

echo "[System] Starting SimpleFTP Pro..."
python3 src/main.py
