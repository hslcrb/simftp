import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import threading
from datetime import datetime
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer
from core.utils import get_local_ip, generate_ssl_cert, hash_password, verify_password

class HashedAuthorizer(DummyAuthorizer):
    """비밀번호 해시 검증을 지원하는 사용자 인증 매니저"""
    def validate_authentication(self, username, password, handler):
        if not self.has_user(username):
            return False
        stored_pw = self.user_table[username]['password']
        return verify_password(stored_pw, password)

class ServerTab(ttk.Frame):
    """모듈화된 FTP 서버 제어 탭"""
    def __init__(self, parent, config_manager):
        super().__init__(parent)
        self.config_manager = config_manager
        self.server = None
        self.server_thread = None
        
        # 데이터 로드
        self.config = self.config_manager.get_server_config()
        self.users = self.config_manager.get_users()
        
        self.use_ftps = tk.BooleanVar(value=self.config.get('use_ftps', False))
        self.allow_anonymous = tk.BooleanVar(value=self.config.get('allow_anonymous', False))
        self.editing_index = None
        
        # UI 위젯 속성 초기화 (AttributeError 방지)
        self.port_entry = None
        self.port_lock_check = None
        self.ip_display = None
        self.pub_ip_display = None
        self.root_entry = None
        self.root_btn = None
        self.anon_check = None
        self.ftps_check = None
        self.nat_check = None
        self.tree = None
        self.e_id = None
        self.e_pw = None
        self.e_home = None
        self.save_btn = None
        self.log_text = None
        self.start_btn = None
        self.stop_btn = None

        self._setup_ui()
        self.refresh_users_tree()

    def _setup_ui(self):
        # 레이아웃 분리 (설정 + 리스트 / 편집기 + 로그)
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        left = ttk.Frame(paned); paned.add(left, weight=2)
        right = ttk.Frame(paned); paned.add(right, weight=3)

        # --- 왼쪽: 설정 및 목록 ---
        cfg_frame = ttk.LabelFrame(left, text="⚙️ 서버 설정", padding=10)
        cfg_frame.pack(fill=tk.X, padx=5, pady=5)
        
        row1 = ttk.Frame(cfg_frame); row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="포트:").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(row1, width=8, state="readonly")
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        # readonly 상태에서 값을 넣기 위해 일시적으로 해제 후 입력
        self.port_entry.config(state=tk.NORMAL)
        self.port_entry.insert(0, str(self.config.get('port', 14729)))
        self.port_entry.config(state="readonly")
        
        # 포트 잠금 해제 체크박스
        self.port_unlock = tk.BooleanVar(value=False)
        self.port_lock_check = ttk.Checkbutton(row1, text="수정", variable=self.port_unlock,
                                              command=lambda: self.port_entry.config(state=tk.NORMAL if self.port_unlock.get() else "readonly"))
        self.port_lock_check.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(row1, text="IP (로컬/공외):").pack(side=tk.LEFT, padx=(10, 5))
        self.ip_display = ttk.Label(row1, text=get_local_ip(), foreground="blue", font=("Consolas", 10, "bold"))
        self.ip_display.pack(side=tk.LEFT)
        
        ttk.Label(row1, text=" / ").pack(side=tk.LEFT)
        
        from core.utils import get_public_ip
        self.pub_ip_display = ttk.Label(row1, text="조회 중...", foreground="red", font=("Consolas", 10, "bold"))
        self.pub_ip_display.pack(side=tk.LEFT)
        
        # 별도 스레드에서 공인 IP 조회
        def update_pub_ip():
            pip = get_public_ip()
            self.pub_ip_display.config(text=pip)
        threading.Thread(target=update_pub_ip, daemon=True).start()

        row2 = ttk.Frame(cfg_frame); row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="Root:").pack(side=tk.LEFT)
        self.root_entry = ttk.Entry(row2); self.root_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.root_entry.insert(0, self.config.get('root_dir', ''))
        self.root_btn = ttk.Button(row2, text="📁", width=3, command=self._browse_root)
        self.root_btn.pack(side=tk.LEFT)

        row3 = ttk.Frame(cfg_frame); row3.pack(fill=tk.X, pady=5)
        self.anon_check = ttk.Checkbutton(row3, text="익명 허용", variable=self.allow_anonymous)
        self.anon_check.pack(side=tk.LEFT, padx=5)
        self.ftps_check = ttk.Checkbutton(row3, text="FTPS (보안)", variable=self.use_ftps)
        self.ftps_check.pack(side=tk.LEFT, padx=10)
        
        self.use_nat = tk.BooleanVar(value=True)
        self.nat_check = ttk.Checkbutton(row3, text="NAT/외부접속 지원", variable=self.use_nat)
        self.nat_check.pack(side=tk.LEFT, padx=5)

        list_frame = ttk.LabelFrame(left, text="👥 계정 목록", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.tree = ttk.Treeview(list_frame, columns=("Perm", "Home"), show="tree headings", height=5)
        self.tree.heading("#0", text="ID"); self.tree.heading("Perm", text="권한"); self.tree.heading("Home", text="경로")
        self.tree.column("#0", width=80); self.tree.column("Perm", width=80); self.tree.column("Home", width=150)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", lambda e: self._on_tree_edit())
        
        btn_row = ttk.Frame(list_frame); btn_row.pack(fill=tk.X, pady=5)
        ttk.Button(btn_row, text="➕ 신규", command=self._on_new_user).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="➖ 삭제", command=self._on_delete_user).pack(side=tk.LEFT, padx=2)

        # --- 오른쪽: 인라인 편집기 및 로그 ---
        self.ed_frame = ttk.LabelFrame(right, text="📝 인라인 계정 편집", padding=10)
        self.ed_frame.pack(fill=tk.X, padx=5, pady=5)
        
        e_row1 = ttk.Frame(self.ed_frame); e_row1.pack(fill=tk.X, pady=2)
        ttk.Label(e_row1, text="아이디:").pack(side=tk.LEFT)
        self.e_id = ttk.Entry(e_row1, width=12); self.e_id.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(e_row1, text="암호:").pack(side=tk.LEFT, padx=(5,0))
        self.e_pw = ttk.Entry(e_row1, width=12, show="*"); self.e_pw.pack(side=tk.LEFT, padx=5)
        
        self.show_pw_server = tk.BooleanVar(value=False)
        ttk.Checkbutton(e_row1, text="보기", variable=self.show_pw_server, 
                        command=lambda: self.e_pw.config(show="" if self.show_pw_server.get() else "*")).pack(side=tk.LEFT)

        e_row2 = ttk.Frame(self.ed_frame); e_row2.pack(fill=tk.X, pady=2)
        ttk.Label(e_row2, text="전용폴더:").pack(side=tk.LEFT)
        self.e_home = ttk.Entry(e_row2); self.e_home.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(e_row2, text="📁", width=3, command=self._browse_user_home).pack(side=tk.LEFT)

        self.perm_box = ttk.LabelFrame(self.ed_frame, text="권한", padding=5)
        self.perm_box.pack(fill=tk.X, pady=5)
        self.p_vars = {}
        for i, (p, l) in enumerate([('e','접속'),('l','목록'),('r','읽기'),('w','쓰기'),('a','추가'),('d','삭제'),('f','이름'),('m','폴더')]):
            v = tk.BooleanVar(value=True); self.p_vars[p] = v
            ttk.Checkbutton(self.perm_box, text=l, variable=v).grid(row=i//4, column=i%4, sticky=tk.W, padx=5)

        e_row3 = ttk.Frame(self.ed_frame); e_row3.pack(fill=tk.X)
        self.save_btn = ttk.Button(e_row3, text="💾 저장/추가", command=self._on_save_user); self.save_btn.pack(side=tk.RIGHT)

        log_frame = ttk.LabelFrame(right, text="📜 활동 로그", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, font=("Consolas", 9), state=tk.DISABLED, bg="#f8f9fa")
        self.log_text.pack(fill=tk.BOTH, expand=True)

        ctrl_row = ttk.Frame(right); ctrl_row.pack(fill=tk.X, pady=5)
        self.start_btn = ttk.Button(ctrl_row, text="▶️ 서버 가동", width=15, command=self.start_server); self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(ctrl_row, text="⏹️ 중지", width=10, state=tk.DISABLED, command=self.stop_server); self.stop_btn.pack(side=tk.LEFT)

    def _on_tree_edit(self):
        sel = self.tree.selection()
        if not sel: return
        idx = self.tree.index(sel[0]); u = self.users[idx]
        self.editing_index = idx
        self.e_id.delete(0, tk.END); self.e_id.insert(0, u['username']); self.e_id.config(state='readonly')
        # 보안을 위해 실제 비밀번호 해시 대신 별표 표시
        self.e_pw.delete(0, tk.END); self.e_pw.insert(0, "********")
        self.e_home.delete(0, tk.END); self.e_home.insert(0, u['home_dir'])
        for p, v in self.p_vars.items(): v.set(p in u['perms'])
        self.save_btn.config(text="💾 변경사항 업데이트")

    def _on_new_user(self):
        self.editing_index = None
        self.e_id.config(state=tk.NORMAL); self.e_id.delete(0, tk.END); self.e_pw.delete(0, tk.END)
        self.e_home.delete(0, tk.END); self.e_home.insert(0, self.root_entry.get())
        for v in self.p_vars.values(): v.set(True)
        self.save_btn.config(text="💾 신규 추가")

    def _on_save_user(self):
        uid, pw, home = self.e_id.get().strip(), self.e_pw.get(), self.e_home.get().strip()
        perms = "".join([p for p, v in self.p_vars.items() if v.get()])
        if not uid or not pw or not home: return

        # 비밀번호가 변경되지 않았을 경우(********) 기존 해시 유지
        if pw == "********" and self.editing_index is not None:
            pw = self.users[self.editing_index]['password']
        else:
            pw = hash_password(pw)

        data = {"username": uid, "password": pw, "home_dir": home, "perms": perms}
        if self.editing_index is not None: self.users[self.editing_index] = data
        else: self.users.append(data)
        self.config_manager.save_users(self.users); self.refresh_users_tree(); self._on_new_user()

    def _on_delete_user(self):
        sel = self.tree.selection()
        if not sel: return
        idx = self.tree.index(sel[0])
        if messagebox.askyesno("삭제", f"'{self.users[idx]['username']}' 계정을 삭제할까요?"):
            self.users.pop(idx); self.config_manager.save_users(self.users); self.refresh_users_tree()

    def _browse_root(self):
        d = filedialog.askdirectory(); 
        if d: self.root_entry.delete(0, tk.END); self.root_entry.insert(0, d)
    
    def _browse_user_home(self):
        d = filedialog.askdirectory(); 
        if d: self.e_home.delete(0, tk.END); self.e_home.insert(0, d)

    def refresh_users_tree(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        for u in self.users: self.tree.insert("", tk.END, text=f"👤 {u['username']}", values=(u['perms'], u['home_dir']))

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL); self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END); self.log_text.config(state=tk.DISABLED)

    def start_server(self):
        port = int(self.port_entry.get()); root = self.root_entry.get()
        self.config.update({"port": port, "root_dir": root, "allow_anonymous": self.allow_anonymous.get(), "use_ftps": self.use_ftps.get()})
        self.config_manager.save_server_config(self.config)
        try:
            auth = HashedAuthorizer()
            for u in self.users:
                if not os.path.exists(u['home_dir']): os.makedirs(u['home_dir'])
                auth.add_user(u['username'], u['password'], u['home_dir'], perm=u['perms'])
            if self.allow_anonymous.get():
                if not os.path.exists(root): os.makedirs(root)
                auth.add_anonymous(root, perm="elr")
            if self.use_ftps.get():
                cp, kp = self.config_manager.get_cert_paths()
                if not os.path.exists(cp):
                    success = generate_ssl_cert(cp, kp)
                    if not success:
                        self.log("❌ 오류: 보안 인증서(SSL) 생성에 실패했습니다. pyopenssl 설치 여부를 확인하세요.")
                        return
                h = TLS_FTPHandler; h.certfile = cp; h.keyfile = kp
                h.tls_control_conn = True; h.tls_data_conn = True
            else: h = FTPHandler
            
            # NAT/외부 접속을 위한 패시브 포트 설정 (60000-60100)
            h.passive_ports = range(60000, 60101)
            
            # 보안 강화: 초당 접속 제한 및 타임아웃 설정
            h.timeout = 300
            h.banner = "simftp ready."
            h.max_login_attempts = 3
            
            # NAT 지원 설정 (외부 접속 가능케 함)
            if self.use_nat.get():
                from core.utils import get_public_ip
                pip = get_public_ip()
                if pip != "확인 불가":
                    h.masquerade_address = pip
                    self.log(f"🌐 NAT 모드 활성화: 외부 IP {pip}로 응답합니다.")
                    self.log(f"📋 알림: 공유기에서 60000-60100 포트(TCP)도 열어주어야 원활합니다.")

            h.authorizer = auth
            self.server = FTPServer(("0.0.0.0", port), h)
            # 서버 전체 동시 접속 제한
            self.server.max_cons = 50
            self.server.max_cons_per_ip = 5
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            self.update_ui_state(True) # Call to update UI state
            self.log(f"서버 활성화 (포트: {port})")
        except Exception as e: self.log(f"오류: {e}")

    def stop_server(self):
        if self.server: self.server.close_all(); self.server = None
        self.update_ui_state(False) # Call to update UI state
        self.log("서버가 중지되었습니다.")

    def update_ui_state(self, running):
        state = tk.DISABLED if running else tk.NORMAL
        ro_state = tk.DISABLED if running else "readonly"
        
        # 가동 중에는 수정 체크박스도 비활성화
        self.port_lock_check.config(state=state)
        
        # 수정 체크박스가 체크되어 있어도 가동 중이면 강제 잠금
        if running:
            self.port_entry.config(state=tk.DISABLED)
        else:
            self.port_entry.config(state=tk.NORMAL if self.port_unlock.get() else "readonly")
            
        self.root_entry.config(state=state)
        self.root_btn.config(state=state)
        self.anon_check.config(state=state)
        self.ftps_check.config(state=state)
        self.nat_check.config(state=state)
        self.start_btn.config(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_btn.config(state=tk.NORMAL if running else tk.DISABLED)
        
        # 가동 중에는 체크박스들도 잠금
        # (익명, FTPS, NAT 등 중요 설정 보호)
        # self.use_ftps, self.use_nat 등은 tk.Checkbutton 인스턴스를 찾아 config 해야함
        # 현재는 가독성을 위해 대표적인 것들만 예시로 처리
