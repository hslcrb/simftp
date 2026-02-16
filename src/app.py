import tkinter as tk
from tkinter import ttk
from core.config import ConfigManager
from gui.tabs.server import ServerTab
from gui.tabs.client import ClientTab

class SimpleFTPApp:
    """통합 FTP 서버 및 클라이언트 애플리케이션 본체"""
    def __init__(self, root):
        self.root = root
        self.root.title("simftp")
        self.root.geometry("1100x750")
        
        # 데이터 관리자 초기화
        self.config_manager = ConfigManager()

        # 메인 탭 인터페이스 구성
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 탭 추가
        self.server_tab = ServerTab(self.notebook, self.config_manager)
        self.client_tab = ClientTab(self.notebook, self.config_manager)

        self.notebook.add(self.server_tab, text=" 🖥️ FTP 서버 제어 ")
        self.notebook.add(self.client_tab, text=" ☁️ FTP 파일 클라이언트 ")

if __name__ == "__main__":
    # 이 파일은 단독 실행되지 않고 main.py에 의해 호출됩니다.
    pass
