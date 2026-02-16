import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import threading
from datetime import datetime
from typing import Optional, List, Dict
import socket
from OpenSSL import crypto
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer

class ServerTab:
    """인라인 UX/UI가 적용된 FTP 서버 제어 탭"""
    def __init__(self, parent: ttk.Frame, config_manager):
        self.parent = parent
        self.config_manager = config_manager
        self.server: Optional[FTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.is_running = False
        
        # 데이터 로드
        self.config = self.config_manager.load_server_config()
        self.users = self.config_manager.load_users()
        
        # UI 상태 변수
        self.use_ftps = tk.BooleanVar(value=self.config.get('use_ftps', False))
        self.allow_anonymous = tk.BooleanVar(value=self.config.get('allow_anonymous', False))
        
        # 인라인 편집 중인 사용자 인덱스 (-1은 추가 모드)
        self.editing_index = None

        self.setup_ui()
        self.refresh_users_tree()

    def setup_ui(self) -> None:
        """메인 레이아웃: 왼쪽(설정 및 사용자 목록), 오른쪽(인라인 편집기 및 로그)"""
        self.paned = ttk.PanedWindow(self.parent, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 1. 왼쪽 프레임 (설정 + 리스트)
        self.left_frame = ttk.Frame(self.paned)
        self.paned.add(self.left_frame, weight=2)

        # 서버 환경 설정
        config_frame = ttk.LabelFrame(self.left_frame, text="⚙️ 서버 환경", padding=10)
        config_frame.pack(fill=tk.X, padx=5, pady=5)

        # 포트/IP
        row1 = ttk.Frame(config_frame)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="포트:", width=8).pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(row1, width=10)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, str(self.config.get('port', 2121)))

        ttk.Label(row1, text="IP:").pack(side=tk.LEFT, padx=(15, 5))
        self.ip_display = ttk.Label(row1, text=self.get_local_ip(), foreground="blue", font=("Consolas", 10, "bold"))
        self.ip_display.pack(side=tk.LEFT)

        # 루트 경로
        row2 = ttk.Frame(config_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="공유 루트:", width=8).pack(side=tk.LEFT)
        self.root_dir_entry = ttk.Entry(row2)
        self.root_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.root_dir_entry.insert(0, self.config.get('root_dir', ''))
        ttk.Button(row2, text="📁", width=3, command=self.browse_root).pack(side=tk.LEFT)

        # 옵션들
        row3 = ttk.Frame(config_frame)
        row3.pack(fill=tk.X, pady=5)
        ttk.Checkbutton(row3, text="익명 허용", variable=self.allow_anonymous).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(row3, text="FTPS 전송 암호화", variable=self.use_ftps).pack(side=tk.LEFT, padx=15)

        # 사용자 목록
        list_frame = ttk.LabelFrame(self.left_frame, text="👥 사용자 계정 목록", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.users_tree = ttk.Treeview(list_frame, columns=("권한", "홈"), show="tree headings", height=8)
        self.users_tree.heading("#0", text="ID (더블클릭 시 편집)")
        self.users_tree.heading("권한", text="권한")
        self.users_tree.heading("홈", text="경로")
        self.users_tree.column("#0", width=120)
        self.users_tree.column("권한", width=100)
        self.users_tree.column("홈", width=200)
        self.users_tree.pack(fill=tk.BOTH, expand=True)

        self.users_tree.bind("<Double-1>", lambda e: self.edit_user_inline())

        btn_row = ttk.Frame(list_frame)
        btn_row.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(btn_row, text="➕ 신규 사용자", command=self.new_user_inline).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="➖ 삭제", command=self.remove_user).pack(side=tk.LEFT, padx=2)

        # 1. 오른쪽 프레임 (인라인 편집기 + 로그)
        self.right_frame = ttk.Frame(self.paned)
        self.paned.add(self.right_frame, weight=3)

        # 인라인 편집기 프레임
        self.editor_frame = ttk.LabelFrame(self.right_frame, text="📝 사용자 상세 편집", padding=15)
        self.editor_frame.pack(fill=tk.X, padx=5, pady=5)

        # ID/PW
        e_row1 = ttk.Frame(self.editor_frame)
        e_row1.pack(fill=tk.X, pady=5)
        ttk.Label(e_row1, text="ID:", width=8).pack(side=tk.LEFT)
        self.e_id = ttk.Entry(e_row1, width=15)
        self.e_id.pack(side=tk.LEFT, padx=5)
        ttk.Label(e_row1, text="PW:", width=5).pack(side=tk.LEFT, padx=(10, 0))
        self.e_pw = ttk.Entry(e_row1, width=15, show="*")
        self.e_pw.pack(side=tk.LEFT, padx=5)

        # 홈 디렉토리
        e_row2 = ttk.Frame(self.editor_frame)
        e_row2.pack(fill=tk.X, pady=5)
        ttk.Label(e_row2, text="전용폴더:", width=8).pack(side=tk.LEFT)
        self.e_home = ttk.Entry(e_row2)
        self.e_home.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(e_row2, text="📁", width=3, command=self.browse_user_home).pack(side=tk.LEFT)

        # 권한 설정 (그리드)
        e_row3 = ttk.LabelFrame(self.editor_frame, text="부여 권한", padding=5)
        e_row3.pack(fill=tk.X, pady=5)
        
        self.perm_vars = {}
        perm_labels = [('e', '접속'), ('l', '목록'), ('r', '읽기'), ('w', '쓰기'),
                       ('a', '추가'), ('d', '삭제'), ('f', '이름변경'), ('m', 'mkdir')]
        for i, (p, label) in enumerate(perm_labels):
            var = tk.BooleanVar(value=True)
            self.perm_vars[p] = var
            ttk.Checkbutton(e_row3, text=label, variable=var).grid(row=i//4, column=i%4, padx=10, pady=2, sticky=tk.W)

        # 저장/취소 버튼
        e_row4 = ttk.Frame(self.editor_frame)
        e_row4.pack(fill=tk.X, pady=(10, 0))
        self.save_btn = ttk.Button(e_row4, text="💾 정보 업데이트", style="Accent.TButton", command=self.save_user_inline)
        self.save_btn.pack(side=tk.RIGHT, padx=5)
        ttk.Button(e_row4, text="🔄 초기화", command=self.clear_editor).pack(side=tk.RIGHT, padx=5)

        # 서버 제어
        control_frame = ttk.Frame(self.right_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        self.start_btn = ttk.Button(control_frame, text="▶️ 서버 시작", width=20, command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(control_frame, text="⏹️ 중지", width=10, state=tk.DISABLED, command=self.stop_server)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # 로그
        log_frame = ttk.LabelFrame(self.right_frame, text="📜 실시간 활동 로그", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, font=("Consolas", 9), height=10, state=tk.DISABLED, bg="#f8f9fa")
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.status_label = ttk.Label(self.right_frame, text="● 서버 대기 중", padding=5, foreground="gray")
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    # --- UI 로직 ---
    def browse_root(self):
        d = filedialog.askdirectory(initialdir=self.root_dir_entry.get())
        if d: self.root_dir_entry.delete(0, tk.END); self.root_dir_entry.insert(0, d)

    def browse_user_home(self):
        d = filedialog.askdirectory(initialdir=self.e_home.get())
        if d: self.e_home.delete(0, tk.END); self.e_home.insert(0, d)

    def refresh_users_tree(self):
        for i in self.users_tree.get_children(): self.users_tree.delete(i)
        for u in self.users:
            self.users_tree.insert("", tk.END, text=f"👤 {u['username']}", values=(u['perms'], u['home_dir']))

    def clear_editor(self):
        self.editing_index = None
        self.e_id.config(state=tk.NORMAL)
        self.e_id.delete(0, tk.END); self.e_pw.delete(0, tk.END)
        self.e_home.delete(0, tk.END); self.e_home.insert(0, self.root_dir_entry.get())
        for var in self.perm_vars.values(): var.set(True)
        self.save_btn.config(text="💾 신규 추가")

    def new_user_inline(self):
        self.clear_editor()
        self.e_id.focus()

    def edit_user_inline(self):
        sel = self.users_tree.selection()
        if not sel: return
        idx = self.users_tree.index(sel[0])
        user = self.users[idx]
        self.editing_index = idx
        
        self.e_id.config(state=tk.NORMAL)
        self.e_id.delete(0, tk.END); self.e_id.insert(0, user['username'])
        self.e_id.config(state='readonly')
        
        self.e_pw.delete(0, tk.END); self.e_pw.insert(0, user['password'])
        self.e_home.delete(0, tk.END); self.e_home.insert(0, user['home_dir'])
        for p, var in self.perm_vars.items(): var.set(p in user['perms'])
        self.save_btn.config(text="💾 변경사항 저장")

    def save_user_inline(self):
        uid = self.e_id.get().strip()
        pw = self.e_pw.get()
        home = self.e_home.get().strip()
        perms = ''.join([p for p, v in self.perm_vars.items() if v.get()])
        
        if not uid or not pw or not home:
            messagebox.showwarning("입력 오류", "모든 필드를 입력해주세요.")
            return

        user_data = {"username": uid, "password": pw, "home_dir": home, "perms": perms}

        if self.editing_index is not None:
            self.users[self.editing_index] = user_data
            self.log(f"사용자 수정: {uid}")
        else:
            if any(u['username'] == uid for u in self.users):
                messagebox.showerror("중복", "이미 존재하는 ID입니다.")
                return
            self.users.append(user_data)
            self.log(f"신규 사용자 추가: {uid}")

        self.config_manager.save_users(self.users)
        self.refresh_users_tree()
        self.clear_editor()

    def remove_user(self):
        sel = self.users_tree.selection()
        if not sel: return
        idx = self.users_tree.index(sel[0])
        uid = self.users[idx]['username']
        if messagebox.askyesno("삭제 확인", f"'{uid}' 계정을 삭제하시겠습니까?"):
            self.users.pop(idx)
            self.config_manager.save_users(self.users)
            self.refresh_users_tree()
            self.clear_editor()
            self.log(f"사용자 제거: {uid}")

    # --- 서버 코어 로직 ---
    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
            return ip
        except: return "127.0.0.1"

    def generate_self_signed_cert(self):
        try:
            k = crypto.PKey(); k.generate_key(crypto.TYPE_RSA, 2048)
            cert = crypto.X509()
            cert.get_subject().CN = "localhost"
            cert.set_serial_number(1000)
            cert.gmtime_notBefore().__add__(0); cert.gmtime_notAfter().__add__(365*24*60*60)
            cert.set_issuer(cert.get_subject()); cert.set_pubkey(k); cert.sign(k, 'sha256')
            with open("config/server.crt", "wb") as f: f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            with open("config/server.key", "wb") as f: f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
            self.log("인증서 생성 완료")
            return True
        except Exception as e:
            self.log(f"인증서 생성 실패: {e}")
            return False

    def start_server(self):
        port = int(self.port_entry.get())
        root = self.root_dir_entry.get()
        
        # 설정 저장
        self.config.update({"port": port, "root_dir": root, "allow_anonymous": self.allow_anonymous.get(), "use_ftps": self.use_ftps.get()})
        self.config_manager.save_server_config(self.config)

        try:
            auth = DummyAuthorizer()
            for u in self.users:
                if not os.path.exists(u['home_dir']): os.makedirs(u['home_dir'])
                auth.add_user(u['username'], u['password'], u['home_dir'], perm=u['perms'])
            
            if self.allow_anonymous.get():
                if not os.path.exists(root): os.makedirs(root)
                auth.add_anonymous(root, perm="elr")
            
            if self.use_ftps.get():
                if not os.path.exists("config/server.crt"): self.generate_self_signed_cert()
                handler = TLS_FTPHandler
                handler.certfile = "config/server.crt"
                handler.keyfile = "config/server.key"
                handler.tls_control_conn = True; handler.tls_data_conn = True
            else:
                handler = FTPHandler
            
            handler.authorizer = auth
            self.server = FTPServer(("0.0.0.0", port), handler)
            self.server.max_cons = 256; self.server.max_cons_per_ip = 10

            def run():
                try: self.server.serve_forever()
                except: pass

            self.server_thread = threading.Thread(target=run, daemon=True)
            self.server_thread.start()
            
            self.is_running = True
            self.start_btn.config(state=tk.DISABLED); self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text=f"● 서버 활성 (포트: {port})", foreground="green")
            self.log(f"서버가 시작되었습니다. (주소: {self.get_local_ip()}:{port})")
            
        except Exception as e:
            messagebox.showerror("서버 오류", str(e))
            self.log(f"서버 시작 실패: {e}")

    def stop_server(self):
        if self.server:
            self.server.close_all()
            self.is_running = False
            self.start_btn.config(state=tk.NORMAL); self.stop_btn.config(state=tk.DISABLED)
            self.status_label.config(text="● 서버 중지됨", foreground="red")
            self.log("서버가 중지되었습니다.")
