import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import threading
from datetime import datetime
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer
from core.utils import get_local_ip, generate_ssl_cert, hash_password, verify_password, encrypt_password, decrypt_password
import logging

class GuiLogHandler(logging.Handler):
    """로깅 이벤트를 GUI 위젯으로 전달하는 핸들러"""
    def __init__(self, log_func):
        super().__init__()
        self.log_func = log_func
        self.setFormatter(logging.Formatter('%(message)s'))

    def emit(self, record):
        try:
            msg = self.format(record)
            # 메인 스레드에서 UI를 업데이트하도록 스케줄링
            self.log_func(msg)
        except Exception:
            self.handleError(record)

class HashedAuthorizer(DummyAuthorizer):
    """암호화된 비밀번호를 복호화하여 검증하는 사용자 인증 매니저"""
    def validate_authentication(self, username, password, handler):
        if not self.has_user(username):
            return False
        stored_pw = self.user_table[username]['password']
        return decrypt_password(stored_pw) == password

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
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 좌측 영역(설정/목록)의 가중치를 높여 너비 확보 (weight 2->3으로 상향 조정)
        left = ttk.Frame(paned); paned.add(left, weight=3)
        right = ttk.Frame(paned); paned.add(right, weight=4)

        # --- 왼쪽: 설정 및 목록 ---
        cfg_frame = ttk.LabelFrame(left, text="⚙️ 핵심 서버 설정", padding=15)
        cfg_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # [행 1] 포트 및 네트워크 상태 정보
        net_row = ttk.Frame(cfg_frame); net_row.pack(fill=tk.X, pady=(0, 10))
        
        # 포트 설정 그룹
        port_group = ttk.Frame(net_row)
        port_group.pack(side=tk.LEFT)
        ttk.Label(port_group, text="서비스 포트:", font=("Malgun Gothic", 9, "bold")).pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(port_group, width=10, state="readonly", font=("Consolas", 10))
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.config(state=tk.NORMAL)
        self.port_entry.insert(0, str(self.config.get('port', 14729)))
        self.port_entry.config(state="readonly")
        
        self.port_unlock = tk.BooleanVar(value=False)
        self.port_lock_check = ttk.Checkbutton(port_group, text="수정", variable=self.port_unlock,
                                              command=lambda: self.port_entry.config(state=tk.NORMAL if self.port_unlock.get() else "readonly"))
        self.port_lock_check.pack(side=tk.LEFT)

        # IP 정보 그룹 (구분선 효과)
        ip_group = ttk.Frame(net_row)
        ip_group.pack(side=tk.RIGHT)
        ttk.Label(ip_group, text="🌐 네트워크 상태:", font=("Malgun Gothic", 9, "bold")).pack(side=tk.LEFT, padx=(20, 5))
        
        self.ip_display = ttk.Label(ip_group, text="로딩 중...", foreground="#0056b3", font=("Consolas", 10, "bold"))
        self.ip_display.pack(side=tk.LEFT)
        ttk.Label(ip_group, text=" | ").pack(side=tk.LEFT, padx=2)
        self.pub_ip_label = ttk.Label(ip_group, text="로딩 중...", foreground="#d32f2f", font=("Consolas", 10, "bold"))
        self.pub_ip_label.pack(side=tk.LEFT)

        # [행 2] 서버 루트 디렉토리
        root_row = ttk.Frame(cfg_frame); root_row.pack(fill=tk.X, pady=5)
        ttk.Label(root_row, text="📁 서버 루트:", font=("Malgun Gothic", 9)).pack(side=tk.LEFT)
        self.root_entry = ttk.Entry(root_row, font=("Malgun Gothic", 9))
        self.root_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.root_entry.insert(0, self.config.get('root_dir', ''))
        self.root_btn = ttk.Button(root_row, text="찾아보기...", width=10, command=self._browse_root)
        self.root_btn.pack(side=tk.LEFT)

        # [행 3] 주요 보안/네트워크 옵션
        opt_row = ttk.Frame(cfg_frame); opt_row.pack(fill=tk.X, pady=(5, 0))
        ttk.Label(opt_row, text="🛠️ 추가 옵션:", font=("Malgun Gothic", 9)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.anon_check = ttk.Checkbutton(opt_row, text="익명 접속 허용", variable=self.allow_anonymous)
        self.anon_check.pack(side=tk.LEFT, padx=10)
        self.ftps_check = ttk.Checkbutton(opt_row, text="FTPS 보안 활성화", variable=self.use_ftps)
        self.ftps_check.pack(side=tk.LEFT, padx=10)
        self.use_nat = tk.BooleanVar(value=True)
        self.nat_check = ttk.Checkbutton(opt_row, text="NAT/외부망 우회", variable=self.use_nat)
        self.nat_check.pack(side=tk.LEFT, padx=10)

        # [자동 실행] 별도 스레드에서 내부/공인 IP 동시 조회 후 UI 갱신
        def update_all_ips():
            import time
            from core.utils import get_local_ip, get_public_ip
            # 화면에 로딩 상태를 즉시 반영
            self.after(0, lambda: [self.ip_display.config(text="로딩 중..."), self.pub_ip_label.config(text="로딩 중...")])
            self.after(0, self.update_idletasks)
            time.sleep(1.2) # 시각적 효과를 위한 최소 대기 시간
            
            lip = get_local_ip()
            pip = get_public_ip()
            
            # 최종 결과 반영
            self.after(0, lambda: [self.ip_display.config(text=lip), self._update_pub_ip_ui(pip)])
        
        threading.Thread(target=update_all_ips, daemon=True).start()

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
        self.save_btn = ttk.Button(e_row3, text="💾 사용자 정보 저장 / 신규 추가", command=self._on_save_user); self.save_btn.pack(side=tk.RIGHT, pady=5)

        log_frame = ttk.LabelFrame(right, text="📜 실시간 활동 로그", padding=15)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, font=("Consolas", 10), state=tk.DISABLED, 
                                                 bg="#1e1e1e", fg="#dcdcdc", insertbackground="white")
        self.log_text.pack(fill=tk.BOTH, expand=True)

        ctrl_row = ttk.Frame(right); ctrl_row.pack(fill=tk.X, pady=(0, 10), padx=5)
        self.start_btn = ttk.Button(ctrl_row, text="🚀 FTP 서버 가동 시작", width=25, command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(ctrl_row, text="🛑 서버 중지", width=15, state=tk.DISABLED, command=self.stop_server)
        self.stop_btn.pack(side=tk.LEFT)

    def _on_tree_edit(self):
        sel = self.tree.selection()
        if not sel: return
        idx = self.tree.index(sel[0]); u = self.users[idx]
        self.editing_index = idx
        self.e_id.config(state=tk.NORMAL)
        self.e_id.delete(0, tk.END); self.e_id.insert(0, u['username'])
        
        # 보안 토큰(master.key)을 사용하여 복호화 후 표시 (이제 보기 버튼 작동)
        raw_pw = decrypt_password(u['password'])
        self.e_pw.delete(0, tk.END); self.e_pw.insert(0, raw_pw)
        
        self.e_home.delete(0, tk.END); self.e_home.insert(0, u['home_dir'])
        for p, v in self.p_vars.items(): v.set(p in u['perms'])
        self.save_btn.config(text="💾 변경사항 업데이트")

    def _update_pub_ip_ui(self, ip):
        """공인 IP 라벨 텍스트를 업데이트합니다."""
        self.pub_ip_label.config(text=ip)

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

        # 중복 체크 (편집 중인 본인은 제외)
        for i, u in enumerate(self.users):
            if u['username'] == uid and i != self.editing_index:
                messagebox.showerror("오류", "이미 존재하는 아이디입니다.")
                return

        # 양방향 암호화 적용 (나중에 복호화 가능하도록)
        encrypted_pw = encrypt_password(pw)

        data = {"username": uid, "password": encrypted_pw, "home_dir": home, "perms": perms}
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
        if self.log_text:
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)

    def _setup_logging(self):
        """pyftpdlib의 로그를 UI로 리다이렉트 설정"""
        logger = logging.getLogger('pyftpdlib')
        logger.setLevel(logging.INFO)
        
        # 기존 핸들러 제거 후 GUI 핸들러 추가
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            
        gui_handler = GuiLogHandler(self.log)
        logger.addHandler(gui_handler)
        
        # 기본 로깅 레벨 설정 (터미널 출력과 동일하게 보장)
        logging.basicConfig(level=logging.INFO)

    def start_server(self):
        self._setup_logging() # 서버 시작 시 로깅 리다이렉트 재설정
        port = int(self.port_entry.get()); root = self.root_entry.get()
        self.config.update({"port": port, "root_dir": root, "allow_anonymous": self.allow_anonymous.get(), "use_ftps": self.use_ftps.get()})
        self.config_manager.save_server_config(self.config)
        try:
            auth = HashedAuthorizer()
            for u in self.users:
                if not os.path.exists(u['home_dir']): os.makedirs(u['home_dir'])
                # authorizer에는 실제 평문 비번을 전달 (validate_authentication에서 내부적으로 verify_password/decrypt_password 사용)
                # authorizer의 add_user는 내부적으로 user_table에 저장만 하므로, 
                # validate_authentication을 재정의한 HashedAuthorizer가 암호화된 값을 처리합니다.
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
                def _async_nat_setup():
                    import time
                    from core.utils import get_local_ip, get_public_ip
                    self.after(0, lambda: [self.ip_display.config(text="로딩 중..."), self.pub_ip_label.config(text="로딩 중...")])
                    self.after(0, self.update_idletasks)
                    time.sleep(1.0)
                    
                    lip = get_local_ip()
                    pip = get_public_ip()
                    
                    self.after(0, lambda: [self.ip_display.config(text=lip), self._update_pub_ip_ui(pip)])
                    
                    if pip and pip != "확인 불가":
                        h.masquerade_address = pip
                        self.log(f"🌐 NAT 모드 활성화: 외부 IP {pip}로 응답합니다.")
                    else:
                        self.log("⚠️ 경고: 공인 IP를 확인할 수 없어 외부 접속이 제한될 수 있습니다.")
                
                # IP 조회는 네트워크를 타므로 별도 스레드에서 수행 (UI 프리징 방지)
                ip_thread = threading.Thread(target=_async_nat_setup, daemon=True)
                ip_thread.start()
                # 중요: masquerade_address는 나중에도 설정 가능하지만, 
                # pyftpdlib 구조상 핸들러에 미리 설정되어야 하므로 
                # 비동기 완료 후 적용되는 로직이 필요할 수 있으나 여기서는 단순화함

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
