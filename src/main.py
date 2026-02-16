import tkinter as tk
from tkinter import ttk
import sys
import os

# src 폴더를 경로에 추가 (직접 실행 시 대비)
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from init_configs import init_all_configs
from config_manager import ConfigManager
from server_tab import ServerTab
from client_tab import ClientTab

class SimpleFTPApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🚀 SimpleFTP Pro - 통합 서버 & 클라이언트")
        self.root.geometry("1100x750")
        
        # 1. 설정 초기화 체크
        init_all_configs()
        self.config_manager = ConfigManager()

        # 2. 테마 및 스타일 설정
        self.setup_styles()

        # 3. 메인 레이아웃 (탭 인터페이스)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 서버 탭
        self.server_tab_frame = ttk.Frame(self.notebook)
        self.server_tab = ServerTab(self.server_tab_frame, self.config_manager)
        self.notebook.add(self.server_tab_frame, text=" 🖥️ FTP 서버 대시보드 ")

        # 클라이언트 탭
        self.client_tab_frame = ttk.Frame(self.notebook)
        self.client_tab = ClientTab(self.client_tab_frame, self.config_manager)
        self.notebook.add(self.client_tab_frame, text=" ☁️ FTP 파일 클라이언트 ")

    def setup_styles(self):
        style = ttk.Style()
        # 여기서 추가적인 테마 설정을 할 수 있습니다. (예: clam, alt 등)
        # style.theme_use('clam')
        
        # 강조용 버튼 스타일 예시
        style.configure("Accent.TButton", font=("맑은 고딕", 9, "bold"))

if __name__ == "__main__":
    root = tk.Tk()
    
    # 윈도우 아이콘 설정 (옵션)
    # try: root.iconbitmap("app.ico")
    # except: pass
    
    app = SimpleFTPApp(root)
    root.mainloop()
