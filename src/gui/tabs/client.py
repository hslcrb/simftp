import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ftplib import FTP, FTP_TLS
import os
import threading
from typing import Optional

class ClientTab(ttk.Frame):
    """모듈화된 FTP 클라이언트 제어 탭"""
    def __init__(self, parent, config_manager):
        super().__init__(parent)
        self.config_manager = config_manager
        self.ftp = None
        
        # 데이터 로드
        self.config = self.config_manager.get_client_config()
        self.cur_l = os.path.expanduser("~")
        self.cur_r = "/"
        self.use_ftps = tk.BooleanVar(value=self.config.get('use_ftps', False))

        self._setup_ui()
        self.refresh_l()

    def _setup_ui(self):
        # 상단 연결 컨트롤
        top = ttk.LabelFrame(self, text="🌐 원격 접속 정보", padding=10)
        top.pack(fill=tk.X, padx=10, pady=5)
        
        row1 = ttk.Frame(top); row1.pack(fill=tk.X)
        ttk.Label(row1, text="호스트:").pack(side=tk.LEFT)
        self.e_h = ttk.Entry(row1, width=15); self.e_h.pack(side=tk.LEFT, padx=5)
        self.e_h.insert(0, self.config.get('last_host', '127.0.0.1'))
        
        ttk.Label(row1, text="포트:").pack(side=tk.LEFT, padx=(5,0))
        self.e_p = ttk.Entry(row1, width=6); self.e_p.pack(side=tk.LEFT, padx=5)
        self.e_p.insert(0, str(self.config.get('last_port', 2121)))
        
        ttk.Label(row1, text="아이디:").pack(side=tk.LEFT, padx=(5,0))
        self.e_u = ttk.Entry(row1, width=12); self.e_u.pack(side=tk.LEFT, padx=5)
        self.e_u.insert(0, self.config.get('last_user', 'user'))
        
        ttk.Label(row1, text="암호:").pack(side=tk.LEFT, padx=(5,0))
        self.e_pw = ttk.Entry(row1, width=12, show="*"); self.e_pw.pack(side=tk.LEFT, padx=5)
        self.e_pw.insert(0, "12345")
        
        self.show_pw_client = tk.BooleanVar(value=False)
        ttk.Checkbutton(row1, text="보기", variable=self.show_pw_client,
                        command=lambda: self.e_pw.config(show="" if self.show_pw_client.get() else "*")).pack(side=tk.LEFT)
        
        ttk.Checkbutton(row1, text="FTPS", variable=self.use_ftps).pack(side=tk.LEFT, padx=5)
        self.conn_btn = ttk.Button(row1, text="🔌 연결", command=self.connect); self.conn_btn.pack(side=tk.LEFT, padx=5)
        self.disc_btn = ttk.Button(row1, text="❌ 해제", state=tk.DISABLED, command=self.disconnect); self.disc_btn.pack(side=tk.LEFT)

        # 메인 브라우저 영역
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 내 컴퓨터 (로컬)
        l_wrap = ttk.LabelFrame(paned, text="💻 내 컴퓨터", padding=5)
        paned.add(l_wrap, weight=1)
        l_path_row = ttk.Frame(l_wrap); l_path_row.pack(fill=tk.X)
        self.l_path_e = ttk.Entry(l_path_row); self.l_path_e.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.l_path_e.insert(0, self.cur_l)
        ttk.Button(l_path_row, text="GO", width=4, command=self._go_l).pack(side=tk.LEFT)
        self.l_tree = ttk.Treeview(l_wrap, columns=("Size"), show="tree headings")
        self.l_tree.heading("#0", text="이름"); self.l_tree.heading("Size", text="크기")
        self.l_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.l_tree.bind("<Double-1>", self._on_l_double_click)
        ttk.Button(l_wrap, text="⬆️ 업로드", command=self.upload).pack(side=tk.RIGHT)

        # 서버 (원격)
        r_wrap = ttk.LabelFrame(paned, text="☁️ FTP 서버", padding=5)
        paned.add(r_wrap, weight=1)
        r_path_row = ttk.Frame(r_wrap); r_path_row.pack(fill=tk.X)
        self.r_path_e = ttk.Entry(r_path_row); self.r_path_e.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.r_path_e.insert(0, "/")
        ttk.Button(r_path_row, text="GO", width=4, command=self._go_r).pack(side=tk.LEFT)
        self.r_tree = ttk.Treeview(r_wrap, columns=("Size", "Perm"), show="tree headings")
        self.r_tree.heading("#0", text="이름"); self.r_tree.heading("Size", text="크기"); self.r_tree.heading("Perm", text="권한")
        self.r_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.r_tree.bind("<Double-1>", self._on_r_double_click)
        r_btn_row = ttk.Frame(r_wrap); r_btn_row.pack(fill=tk.X)
        ttk.Button(r_btn_row, text="⬇️ 다운로드", command=self.download).pack(side=tk.LEFT)
        ttk.Button(r_btn_row, text="🗑️ 삭제", command=self.delete_r).pack(side=tk.RIGHT)

        self.status = ttk.Label(self, text="준비됨", relief=tk.SUNKEN, padding=2)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def refresh_l(self):
        for i in self.l_tree.get_children(): self.l_tree.delete(i)
        try:
            for it in os.listdir(self.cur_l):
                p = os.path.join(self.cur_l, it)
                sz = f"{os.path.getsize(p):,}" if os.path.isfile(p) else "<DIR>"
                ic = "📁" if os.path.isdir(p) else "📄"
                self.l_tree.insert("", tk.END, text=f"{ic} {it}", values=(sz,))
        except Exception as e: messagebox.showerror("오류", str(e))

    def _go_l(self):
        p = self.l_path_e.get()
        if os.path.isdir(p): self.cur_l = p; self.refresh_l()

    def _on_l_double_click(self, e):
        sel = self.l_tree.selection()
        if not sel: return
        n = self.l_tree.item(sel[0], "text")[3:]
        p = os.path.join(self.cur_l, n)
        if os.path.isdir(p): self.cur_l = p; self.l_path_e.delete(0, tk.END); self.l_path_e.insert(0, p); self.refresh_l()

    def connect(self):
        h, p = self.e_h.get(), int(self.e_p.get())
        u, pw = self.e_u.get(), self.e_pw.get()
        try:
            if self.use_ftps.get():
                self.ftp = FTP_TLS(); self.ftp.connect(h, p); self.ftp.login(u, pw); self.ftp.prot_p()
            else:
                self.ftp = FTP(); self.ftp.connect(h, p); self.ftp.login(u, pw)
            self.conn_btn.config(state=tk.DISABLED); self.disc_btn.config(state=tk.NORMAL)
            self.status.config(text=f"접속됨: {h}"); self.refresh_r()
            self.config.update({"last_host":h,"last_port":p,"last_user":u,"use_ftps":self.use_ftps.get()})
            self.config_manager.save_client_config(self.config)
        except Exception as e: messagebox.showerror("실패", str(e))

    def disconnect(self):
        if self.ftp: 
            try: self.ftp.quit()
            except: pass
            self.ftp = None
        self.conn_btn.config(state=tk.NORMAL); self.disc_btn.config(state=tk.DISABLED)
        self.status.config(text="해제됨"); self.refresh_r()

    def refresh_r(self):
        for i in self.r_tree.get_children(): self.r_tree.delete(i)
        if not self.ftp: return
        try:
            ls = []
            self.ftp.retrlines('LIST', ls.append)
            for line in ls:
                ps = line.split(None, 8)
                if len(ps) < 9: continue
                n, sz, pm = ps[8], ps[4], ps[0]
                ic = "📁" if pm.startswith('d') else "📄"
                self.r_tree.insert("", tk.END, text=f"{ic} {n}", values=(sz, pm))
            self.r_path_e.delete(0, tk.END); self.r_path_e.insert(0, self.ftp.pwd())
        except Exception as e: messagebox.showerror("오류", str(e))

    def _go_r(self):
        if not self.ftp: return
        try: self.ftp.cwd(self.r_path_e.get()); self.refresh_r()
        except Exception as e: messagebox.showerror("오류", str(e))

    def _on_r_double_click(self, e):
        if not self.ftp: return
        sel = self.r_tree.selection()
        if not sel: return
        n = self.r_tree.item(sel[0], "text")[3:]; pm = self.r_tree.item(sel[0], "values")[1]
        if pm.startswith('d'): self.ftp.cwd(n); self.refresh_r()

    def upload(self):
        if not self.ftp: return
        sel = self.l_tree.selection()
        if not sel: return
        n = self.l_tree.item(sel[0], "text")[3:]; p = os.path.join(self.cur_l, n)
        if os.path.isfile(p):
            with open(p, 'rb') as f: self.ftp.storbinary(f"STOR {n}", f)
            self.refresh_r(); self.status.config(text=f"업로드 완료: {n}")

    def download(self):
        if not self.ftp: return
        sel = self.r_tree.selection()
        if not sel: return
        n = self.r_tree.item(sel[0], "text")[3:]; p = os.path.join(self.cur_l, n)
        with open(p, 'wb') as f: self.ftp.retrbinary(f"RETR {n}", f.write)
        self.refresh_l(); self.status.config(text=f"다운로드 완료: {n}")

    def delete_r(self):
        if not self.ftp: return
        sel = self.r_tree.selection()
        if not sel: return
        n = self.r_tree.item(sel[0], "text")[3:]
        if messagebox.askyesno("삭제", f"서버에서 {n}을 삭제할까요?"):
            try: self.ftp.delete(n)
            except: self.ftp.rmd(n)
            self.refresh_r()
