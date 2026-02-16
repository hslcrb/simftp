import tkinter as tk
import sys
import os

# src 폴더를 패키지 검색 경로에 추가
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

from core.setup import initialize_environment
from app import SimpleFTPApp

def main():
    # 1. 시스템 환경 및 설정 파일 자동 생성 체크
    initialize_environment()
    
    # 2. Tkinter 루프 실행
    root = tk.Tk()
    app = SimpleFTPApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
