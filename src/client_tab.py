import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ftplib import FTP, FTP_TLS
import os
import threading
from datetime import datetime
from typing import Optional

class ClientTab:
    """FTP 클라이언트 제어 탭"""
    def __init__(self, parent: ttk.Frame, config_manager):
        self.parent = parent
        self.config_manager = config_manager
        self.ftp: Optional[FTP] = None
        
        # 데이터 로드
        self.config = self.config_manager.load_client_config()
        
        # UI 상태
        self.current_local_path = os.path.expanduser("~")
        self.current_remote_path = "/"
        self.use_ftps = tk.BooleanVar(value=self.config.get('use_ftps', False))

        self.setup_ui()
        self.refresh_local_view()

    def setup_ui(self) -> None:
        # 상단 연결 바
        conn_frame = ttk.LabelFrame(self.parent, text="🌐 서버 연결", padding=10)
        conn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(conn_frame, text="호스트:").pack(side=tk.LEFT, padx=5)
        self.e_host = ttk.Entry(conn_frame, width=15)
        self.e_host.pack(side=tk.LEFT, padx=5)
        self.e_host.insert(0, self.config.get('last_host', '127.0.0.1'))

        ttk.Label(conn_frame, text="포트:").pack(side=tk.LEFT, padx=5)
        self.e_port = ttk.Entry(conn_frame, width=6)
        self.e_port.pack(side=tk.LEFT, padx=5)
        self.e_port.insert(0, str(self.config.get('last_port', 2121)))

        ttk.Label(conn_frame, text="사용자:").pack(side=tk.LEFT, padx=5)
        self.e_user = ttk.Entry(conn_frame, width=10)
        self.e_user.pack(side=tk.LEFT, padx=5)
        self.e_user.insert(0, self.config.get('last_user', 'user'))

        ttk.Label(conn_frame, text="암호:").pack(side=tk.LEFT, padx=5)
        self.e_pass = ttk.Entry(conn_frame, width=10, show="*")
        self.e_pass.pack(side=tk.LEFT, padx=5)
        self.e_pass.insert(0, "12345")

        ttk.Checkbutton(conn_frame, text="FTPS", variable=self.use_ftps).pack(side=tk.LEFT, padx=5)

        self.btn_connect = ttk.Button(conn_frame, text="🔌 연결", command=self.connect)
        self.btn_connect.pack(side=tk.LEFT, padx=10)
        self.btn_disconnect = ttk.Button(conn_frame, text="❌ 해제", state=tk.DISABLED, command=self.disconnect)
        self.btn_disconnect.pack(side=tk.LEFT)

        # 메인 파일 브라우저
        paned = ttk.PanedWindow(self.parent, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 로컬 패널
        l_frame = ttk.LabelFrame(paned, text="💻 내 컴퓨터", padding=5)
        paned.add(l_frame, weight=1)
        
        l_path_row = ttk.Frame(l_frame)
        l_path_row.pack(fill=tk.X)
        self.l_path = ttk.Entry(l_path_row)
        self.l_path.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.l_path.insert(0, self.current_local_path)
        ttk.Button(l_path_row, text="이동", width=5, command=self.go_local).pack(side=tk.LEFT)
        
        self.l_tree = ttk.Treeview(l_frame, columns=("Size"), show="tree headings")
        self.l_tree.heading("#0", text="이름")
        self.l_tree.heading("Size", text="크기")
        self.l_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.l_tree.bind("<Double-1>", self.on_l_double_click)

        l_btn_row = ttk.Frame(l_frame)
        l_btn_row.pack(fill=tk.X)
        ttk.Button(l_btn_row, text="⬆️ 업로드", command=self.upload).pack(side=tk.RIGHT)

        # 원격 패널
        r_frame = ttk.LabelFrame(paned, text="☁️ FTP 서버", padding=5)
        paned.add(r_frame, weight=1)

        r_path_row = ttk.Frame(r_frame)
        r_path_row.pack(fill=tk.X)
        self.r_path = ttk.Entry(r_path_row)
        self.r_path.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.r_path.insert(0, "/")
        ttk.Button(r_path_row, text="이동", width=5, command=self.go_remote).pack(side=tk.LEFT)

        self.r_tree = ttk.Treeview(r_frame, columns=("Size", "Perm"), show="tree headings")
        self.r_tree.heading("#0", text="이름")
        self.r_tree.heading("Size", text="크기")
        self.r_tree.heading("Perm", text="권한")
        self.r_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.r_tree.bind("<Double-1>", self.on_r_double_click)

        r_btn_row = ttk.Frame(r_frame)
        r_btn_row.pack(fill=tk.X)
        ttk.Button(r_btn_row, text="⬇️ 다운로드", command=self.download).pack(side=tk.LEFT)
        ttk.Button(r_btn_row, text="🗑️ 삭제", command=self.delete_remote).pack(side=tk.RIGHT)

        self.status = ttk.Label(self.parent, text="준비됨", relief=tk.SUNKEN, padding=2)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    # --- 클라이언트 로직 ---
    def refresh_local_view(self):
        for i in self.l_tree.get_children(): self.l_tree.delete(i)
        try:
            for item in os.listdir(self.current_local_path):
                path = os.path.join(self.current_local_path, item)
                size = f"{os.path.getsize(path):,}" if os.path.isfile(path) else "<DIR>"
                icon = "📁" if os.path.isdir(path) else "📄"
                self.l_tree.insert("", tk.END, text=f"{icon} {item}", values=(size,))
        except Exception as e: messagebox.showerror("오류", str(e))

    def go_local(self):
        path = self.l_path.get()
        if os.path.isdir(path):
            self.current_local_path = path
            self.refresh_local_view()

    def on_l_double_click(self, event):
        sel = self.l_tree.selection()
        if not sel: return
        item_text = self.l_tree.item(sel[0], "text")[3:]
        new_path = os.path.join(self.current_local_path, item_text)
        if os.path.isdir(new_path):
            self.current_local_path = new_path
            self.l_path.delete(0, tk.END); self.l_path.insert(0, self.current_local_path)
            self.refresh_local_view()

    def connect(self):
        h = self.e_host.get(); p = int(self.e_port.get())
        u = self.e_user.get(); pw = self.e_pass.get()
        
        try:
            if self.use_ftps.get():
                self.ftp = FTP_TLS()
                self.ftp.connect(h, p); self.ftp.login(u, pw); self.ftp.prot_p()
            else:
                self.ftp = FTP()
                self.ftp.connect(h, p); self.ftp.login(u, pw)
            
            self.btn_connect.config(state=tk.DISABLED); self.btn_disconnect.config(state=tk.NORMAL)
            self.status.config(text=f"접속됨: {h}")
            self.refresh_remote_view()
            
            # 접속 정보 저장
            self.config.update({"last_host": h, "last_port": p, "last_user": u, "use_ftps": self.use_ftps.get()})
            self.config_manager.save_client_config(self.config)
        except Exception as e: messagebox.showerror("연결 실패", str(e))

    def disconnect(self):
        if self.ftp:
            try: self.ftp.quit()
            except: pass
            self.ftp = None
        self.btn_connect.config(state=tk.NORMAL); self.btn_disconnect.config(state=tk.DISABLED)
        self.status.config(text="연결 해제됨")
        for i in self.r_tree.get_children(): self.r_tree.delete(i)

    def refresh_remote_view(self):
        if not self.ftp: return
        for i in self.r_tree.get_children(): self.r_tree.delete(i)
        try:
            items = []
            self.ftp.retrlines('LIST', items.append)
            for line in items:
                # 간단한 리스트 파싱 (이름, 크기, 권한)
                parts = line.split(None, 8)
                if len(parts) < 9: continue
                name = parts[8]; size = parts[4]; perm = parts[0]
                icon = "📁" if perm.startswith('d') else "📄"
                self.r_tree.insert("", tk.END, text=f"{icon} {name}", values=(size, perm))
            self.r_path.delete(0, tk.END); self.r_path.insert(0, self.ftp.pwd())
        except Exception as e: messagebox.showerror("조회 오류", str(e))

    def go_remote(self):
        if not self.ftp: return
        try: self.ftp.cwd(self.r_path.get()); self.refresh_remote_view()
        except Exception as e: messagebox.showerror("이동 오류", str(e))

    def on_r_double_click(self, event):
        if not self.ftp: return
        sel = self.r_tree.selection()
        if not sel: return
        name = self.r_tree.item(sel[0], "text")[3:]
        perm = self.r_tree.item(sel[0], "values")[1]
        if perm.startswith('d'):
            self.ftp.cwd(name)
            self.refresh_remote_view()

    def upload(self):
        if not self.ftp: return
        sel = self.l_tree.selection()
        if not sel: return
        name = self.l_tree.item(sel[0], "text")[3:]
        path = os.path.join(self.current_local_path, name)
        if os.path.isfile(path):
            with open(path, 'rb') as f:
                self.ftp.storbinary(f"STOR {name}", f)
            self.refresh_remote_view()
            self.status.config(text=f"업로드 완료: {name}")

    def download(self):
        if not self.ftp: return
        sel = self.r_tree.selection()
        if not sel: return
        name = self.r_tree.item(sel[0], "text")[3:]
        local_path = os.path.join(self.current_local_path, name)
        with open(local_path, 'wb') as f:
            self.ftp.retrbinary(f"RETR {name}", f.write)
        self.refresh_local_view()
        self.status.config(text=f"다운로드 완료: {name}")

    def delete_remote(self):
        if not self.ftp: return
        sel = self.r_tree.selection()
        if not sel: return
        name = self.r_tree.item(sel[0], "text")[3:]
        if messagebox.askyesno("삭제", f"서버에서 '{name}'을(를) 삭제하시겠습니까?"):
            try:
                self.ftp.delete(name)
            except:
                self.ftp.rmd(name)
            self.refresh_remote_view()
