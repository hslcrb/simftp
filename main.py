import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer
from ftplib import FTP, FTP_TLS
import os
import threading
from datetime import datetime
from typing import Optional
import socket
import ssl
from OpenSSL import crypto


class FTPServerTab:
    """FTP 서버 탭"""
    def __init__(self, parent: ttk.Frame):
        self.parent = parent
        self.server: Optional[FTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.is_running = False
        self.users = []  # 사용자 목록: [{username, password, home_dir, perms}, ...]
        
        # 보안 설정 변수
        self.use_ftps = tk.BooleanVar(value=False)
        self.cert_path = tk.StringVar(value="server.crt")
        self.key_path = tk.StringVar(value="server.key")
        self.max_cons = tk.IntVar(value=256)
        self.max_cons_per_ip = tk.IntVar(value=5)
        
        # UI 위젯들
        self.port_entry: ttk.Entry
        self.root_dir_entry: ttk.Entry
        self.allow_anonymous: tk.BooleanVar
        self.anonymous_checkbox: ttk.Checkbutton
        self.users_tree: ttk.Treeview
        self.start_btn: ttk.Button
        self.stop_btn: ttk.Button
        self.log_text: scrolledtext.ScrolledText
        self.status_label: ttk.Label
        self.cert_entry: ttk.Entry
        self.key_entry: ttk.Entry
        
        self.setup_ui()
        
    def setup_ui(self) -> None:
        """서버 탭 UI 구성"""
        # 상단 설정 프레임
        config_frame = ttk.LabelFrame(self.parent, text="서버 설정", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # 포트 설정
        ttk.Label(config_frame, text="포트:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.port_entry = ttk.Entry(config_frame, width=15)
        self.port_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.port_entry.insert(0, "2121")
        
        # 루트 디렉토리
        ttk.Label(config_frame, text="루트 디렉토리:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.root_dir_entry = ttk.Entry(config_frame, width=35)
        self.root_dir_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        self.root_dir_entry.insert(0, os.path.expanduser("~/ftp_root"))
        
        ttk.Button(config_frame, text="찾아보기...", command=self.browse_directory).grid(row=0, column=4, padx=5, pady=5)
        
        # 익명 로그인 허용
        self.allow_anonymous = tk.BooleanVar(value=False)
        self.anonymous_checkbox = ttk.Checkbutton(
            config_frame, 
            text="익명 로그인 허용 (anonymous)", 
            variable=self.allow_anonymous
        )
        self.anonymous_checkbox.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # 보안 설정 프레임 (상단 설정 프레임 내부에 추가)
        security_frame = ttk.LabelFrame(self.parent, text="🔐 보안 및 FTPS 설정", padding=10)
        security_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # FTPS 활성화
        ttk.Checkbutton(security_frame, text="FTPS (TLS/SSL) 암호화 사용", variable=self.use_ftps).grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # 인증서 및 키 경로
        ttk.Label(security_frame, text="인증서(.crt):").grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.cert_entry = ttk.Entry(security_frame, textvariable=self.cert_path, width=30)
        self.cert_entry.grid(row=1, column=1, padx=5, pady=2, sticky=tk.W)
        ttk.Button(security_frame, text="찾기", command=lambda: self.browse_file(self.cert_path)).grid(row=1, column=2, padx=5, pady=2)
        
        ttk.Label(security_frame, text="개인키(.key):").grid(row=2, column=0, padx=5, pady=2, sticky=tk.W)
        self.key_entry = ttk.Entry(security_frame, textvariable=self.key_path, width=30)
        self.key_entry.grid(row=2, column=1, padx=5, pady=2, sticky=tk.W)
        ttk.Button(security_frame, text="찾기", command=lambda: self.browse_file(self.key_path)).grid(row=2, column=2, padx=5, pady=2)
        
        ttk.Button(security_frame, text="내장 인증서 생성", command=self.generate_self_signed_cert).grid(row=1, column=3, rowspan=2, padx=10, pady=2)
        
        # 접속 제한
        ttk.Label(security_frame, text="최대 접속 수:").grid(row=3, column=0, padx=5, pady=2, sticky=tk.W)
        ttk.Entry(security_frame, textvariable=self.max_cons, width=10).grid(row=3, column=1, padx=5, pady=2, sticky=tk.W)
        
        ttk.Label(security_frame, text="IP당 최대 접속:").grid(row=3, column=2, padx=5, pady=2, sticky=tk.W)
        ttk.Entry(security_frame, textvariable=self.max_cons_per_ip, width=10).grid(row=3, column=3, padx=5, pady=2, sticky=tk.W)
        
        # 사용자 관리 프레임
        users_frame = ttk.LabelFrame(self.parent, text="사용자 관리", padding=10)
        users_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 사용자 목록 트리뷰
        tree_frame = ttk.Frame(users_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.users_tree = ttk.Treeview(
            tree_frame, 
            columns=("비밀번호", "홈 디렉토리", "권한"), 
            show="tree headings",
            height=6
        )
        self.users_tree.heading("#0", text="사용자명")
        self.users_tree.heading("비밀번호", text="비밀번호")
        self.users_tree.heading("홈 디렉토리", text="홈 디렉토리")
        self.users_tree.heading("권한", text="권한")
        self.users_tree.column("#0", width=150)
        self.users_tree.column("비밀번호", width=120)
        self.users_tree.column("홈 디렉토리", width=300)
        self.users_tree.column("권한", width=150)
        
        users_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.users_tree.yview)
        self.users_tree.configure(yscrollcommand=users_scrollbar.set)
        
        self.users_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        users_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 사용자 관리 버튼
        user_btn_frame = ttk.Frame(users_frame)
        user_btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(user_btn_frame, text="➕ 사용자 추가", command=self.add_user).pack(side=tk.LEFT, padx=2)
        ttk.Button(user_btn_frame, text="➖ 사용자 삭제", command=self.remove_user).pack(side=tk.LEFT, padx=2)
        ttk.Button(user_btn_frame, text="✏️ 사용자 수정", command=self.edit_user).pack(side=tk.LEFT, padx=2)
        ttk.Button(user_btn_frame, text="🔐 권한 수정", command=self.edit_permissions).pack(side=tk.LEFT, padx=2)
        
        # 서버 제어 버튼
        btn_frame = ttk.Frame(users_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.start_btn = ttk.Button(btn_frame, text="🟢 서버 시작", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="🔴 서버 중지", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # 로그 프레임
        log_frame = ttk.LabelFrame(self.parent, text="서버 로그", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=12, width=80, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 상태 표시줄
        status_frame = ttk.Frame(self.parent)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="● 서버 중지됨", relief=tk.SUNKEN, foreground="red")
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 기본 사용자 추가
        self.add_default_user()
        
    def add_default_user(self) -> None:
        """기본 사용자 추가"""
        default_user = {
            'username': 'user',
            'password': '12345',
            'home_dir': self.root_dir_entry.get(),
            'perms': 'elradfmw'  # 모든 권한
        }
        self.users.append(default_user)
        self.refresh_users_tree()
        
    def refresh_users_tree(self) -> None:
        """사용자 목록 트리뷰 새로고침"""
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
            
        for user in self.users:
            masked_pw = '*' * len(user['password'])
            perms_desc = self.get_perms_description(user['perms'])
            self.users_tree.insert(
                "", tk.END, 
                text=f"👤 {user['username']}", 
                values=(masked_pw, user['home_dir'], perms_desc)
            )
            
    def get_perms_description(self, perms: str) -> str:
        """권한 문자열을 설명으로 변환"""
        perm_map = {
            'e': '접속', 'l': '목록', 'r': '읽기', 'a': '추가',
            'd': '삭제', 'f': '이름변경', 'm': 'mkdir', 'w': '쓰기'
        }
        return ','.join([perm_map.get(p, p) for p in perms])
        
    def add_user(self) -> None:
        """사용자 추가 대화상자"""
        dialog = tk.Toplevel(self.parent)
        dialog.title("사용자 추가")
        dialog.geometry("500x300")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        # 사용자명
        ttk.Label(dialog, text="사용자명:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        username_entry = ttk.Entry(dialog, width=30)
        username_entry.grid(row=0, column=1, padx=10, pady=10)
        
        # 비밀번호
        ttk.Label(dialog, text="비밀번호:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        password_entry = ttk.Entry(dialog, width=30, show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        # 홈 디렉토리
        ttk.Label(dialog, text="홈 디렉토리:").grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        home_dir_entry = ttk.Entry(dialog, width=30)
        home_dir_entry.grid(row=2, column=1, padx=10, pady=10)
        home_dir_entry.insert(0, self.root_dir_entry.get())
        
        def browse_home_dir():
            directory = filedialog.askdirectory(initialdir=home_dir_entry.get())
            if directory:
                home_dir_entry.delete(0, tk.END)
                home_dir_entry.insert(0, directory)
                
        ttk.Button(dialog, text="찾아보기...", command=browse_home_dir).grid(row=2, column=2, padx=5, pady=10)
        
        # 권한 설정
        ttk.Label(dialog, text="권한:").grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
        perms_frame = ttk.Frame(dialog)
        perms_frame.grid(row=3, column=1, padx=10, pady=10, sticky=tk.W)
        
        perm_vars = {}
        perm_labels = [('e', '접속'), ('l', '목록'), ('r', '읽기'), ('w', '쓰기'),
                       ('a', '추가'), ('d', '삭제'), ('f', '이름변경'), ('m', 'mkdir')]
        
        for i, (perm, label) in enumerate(perm_labels):
            var = tk.BooleanVar(value=True)
            perm_vars[perm] = var
            ttk.Checkbutton(perms_frame, text=label, variable=var).grid(row=i//4, column=i%4, sticky=tk.W)
        
        def save_user():
            username = username_entry.get().strip()
            password = password_entry.get()
            home_dir = home_dir_entry.get().strip()
            
            if not username:
                messagebox.showerror("오류", "사용자명을 입력하세요.")
                return
            if not password:
                messagebox.showerror("오류", "비밀번호를 입력하세요.")
                return
            if not home_dir:
                messagebox.showerror("오류", "홈 디렉토리를 입력하세요.")
                return
                
            # 권한 문자열 생성
            perms = ''.join([p for p, var in perm_vars.items() if var.get()])
            
            # 사용자 추가
            new_user = {
                'username': username,
                'password': password,
                'home_dir': home_dir,
                'perms': perms
            }
            self.users.append(new_user)
            self.refresh_users_tree()
            dialog.destroy()
            messagebox.showinfo("성공", f"사용자 '{username}'이(가) 추가되었습니다.")
        
        # 버튼
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=20)
        
        ttk.Button(btn_frame, text="저장", command=save_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="취소", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
    def remove_user(self) -> None:
        """선택한 사용자 삭제"""
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("경고", "삭제할 사용자를 선택하세요.")
            return
            
        index = self.users_tree.index(selection[0])
        username = self.users[index]['username']
        
        if messagebox.askyesno("확인", f"사용자 '{username}'을(를) 삭제하시겠습니까?"):
            self.users.pop(index)
            self.refresh_users_tree()
            messagebox.showinfo("성공", f"사용자 '{username}'이(가) 삭제되었습니다.")
            
    def edit_user(self) -> None:
        """선택한 사용자 수정"""
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("경고", "수정할 사용자를 선택하세요.")
            return
            
        index = self.users_tree.index(selection[0])
        user = self.users[index]
        
        # 수정 대화상자 (추가 대화상자와 유사하지만 기존 값 로드)
        dialog = tk.Toplevel(self.parent)
        dialog.title("사용자 수정")
        dialog.geometry("500x300")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="사용자명:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        username_entry = ttk.Entry(dialog, width=30)
        username_entry.grid(row=0, column=1, padx=10, pady=10)
        username_entry.insert(0, user['username'])
        username_entry.config(state='readonly')  # 사용자명은 수정 불가
        
        ttk.Label(dialog, text="비밀번호:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        password_entry = ttk.Entry(dialog, width=30, show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=10)
        password_entry.insert(0, user['password'])
        
        ttk.Label(dialog, text="홈 디렉토리:").grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        home_dir_entry = ttk.Entry(dialog, width=30)
        home_dir_entry.grid(row=2, column=1, padx=10, pady=10)
        home_dir_entry.insert(0, user['home_dir'])
        
        def browse_home_dir():
            directory = filedialog.askdirectory(initialdir=home_dir_entry.get())
            if directory:
                home_dir_entry.delete(0, tk.END)
                home_dir_entry.insert(0, directory)
                
        ttk.Button(dialog, text="찾아보기...", command=browse_home_dir).grid(row=2, column=2, padx=5, pady=10)
        
        ttk.Label(dialog, text="권한:").grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
        perms_frame = ttk.Frame(dialog)
        perms_frame.grid(row=3, column=1, padx=10, pady=10, sticky=tk.W)
        
        perm_vars = {}
        perm_labels = [('e', '접속'), ('l', '목록'), ('r', '읽기'), ('w', '쓰기'),
                       ('a', '추가'), ('d', '삭제'), ('f', '이름변경'), ('m', 'mkdir')]
        
        for i, (perm, label) in enumerate(perm_labels):
            var = tk.BooleanVar(value=(perm in user['perms']))
            perm_vars[perm] = var
            ttk.Checkbutton(perms_frame, text=label, variable=var).grid(row=i//4, column=i%4, sticky=tk.W)
        
        def save_changes():
            password = password_entry.get()
            home_dir = home_dir_entry.get().strip()
            
            if not password:
                messagebox.showerror("오류", "비밀번호를 입력하세요.")
                return
            if not home_dir:
                messagebox.showerror("오류", "홈 디렉토리를 입력하세요.")
                return
                
            perms = ''.join([p for p, var in perm_vars.items() if var.get()])
            
            self.users[index]['password'] = password
            self.users[index]['home_dir'] = home_dir
            self.users[index]['perms'] = perms
            
            self.refresh_users_tree()
            dialog.destroy()
            messagebox.showinfo("성공", "사용자 정보가 수정되었습니다.")
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=20)
        
        ttk.Button(btn_frame, text="저장", command=save_changes).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="취소", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
    def edit_permissions(self) -> None:
        """선택한 사용자의 권한만 빠르게 수정"""
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("경고", "권한을 수정할 사용자를 선택하세요.")
            return
            
        index = self.users_tree.index(selection[0])
        user = self.users[index]
        
        dialog = tk.Toplevel(self.parent)
        dialog.title(f"권한 수정 - {user['username']}")
        dialog.geometry("400x200")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text=f"사용자 '{user['username']}'의 권한을 설정하세요:").pack(pady=10)
        
        perms_frame = ttk.Frame(dialog)
        perms_frame.pack(padx=10, pady=5)
        
        perm_vars = {}
        perm_labels = [('e', '접속'), ('l', '목록'), ('r', '읽기'), ('w', '쓰기'),
                       ('a', '추가'), ('d', '삭제'), ('f', '이름변경'), ('m', 'mkdir')]
        
        for i, (perm, label) in enumerate(perm_labels):
            var = tk.BooleanVar(value=(perm in user['perms']))
            perm_vars[perm] = var
            ttk.Checkbutton(perms_frame, text=label, variable=var).grid(row=i//4, column=i%4, sticky=tk.W, padx=5, pady=2)
            
        def save_perms():
            perms = ''.join([p for p, var in perm_vars.items() if var.get()])
            self.users[index]['perms'] = perms
            self.refresh_users_tree()
            dialog.destroy()
            messagebox.showinfo("성공", f"'{user['username']}'의 권한이 업데이트되었습니다.")
            
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=15)
        
        ttk.Button(btn_frame, text="저장", command=save_perms).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="취소", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
    def browse_file(self, var: tk.StringVar) -> None:
        """파일 선택 대화상자"""
        filename = filedialog.askopenfilename()
        if filename:
            var.set(filename)
            
    def generate_self_signed_cert(self) -> None:
        """자가 서명 인증서 및 개인키 생성"""
        try:
            # 키 생성
            k = crypto.PKey()
            k.generate_key(crypto.TYPE_RSA, 2048)
            
            # 인증서 생성
            cert = crypto.X509()
            cert.get_subject().C = "KR"
            cert.get_subject().ST = "Seoul"
            cert.get_subject().L = "Seoul"
            cert.get_subject().O = "SimpleFTP"
            cert.get_subject().OU = "IT"
            cert.get_subject().CN = "localhost"
            cert.set_serial_number(1000)
            cert.gmtime_notBefore().__add__(0)
            cert.gmtime_notAfter().__add__(10*365*24*60*60) # 10년
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(k)
            cert.sign(k, 'sha256')
            
            # 파일 저장
            cert_file = self.cert_path.get()
            key_file = self.key_path.get()
            
            with open(cert_file, "wt") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
            with open(key_file, "wt") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8'))
                
            self.log(f"인증서 생성 완료: {cert_file}, {key_file}")
            messagebox.showinfo("성공", "자가 서명 인증서와 개인키가 생성되었습니다.")
        except Exception as e:
            self.log(f"인증서 생성 실패: {str(e)}")
            messagebox.showerror("오류", f"인증서 생성 실패:\n{str(e)}")

    def browse_directory(self) -> None:
        """디렉토리 선택 대화상자"""
        directory = filedialog.askdirectory(initialdir=self.root_dir_entry.get())
        if directory:
            self.root_dir_entry.delete(0, tk.END)
            self.root_dir_entry.insert(0, directory)
            
    def log(self, message: str) -> None:
        """로그 메시지 추가"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def start_server(self) -> None:
        """FTP 서버 시작"""
        port = int(self.port_entry.get())
        root_dir = self.root_dir_entry.get()
        allow_anon = self.allow_anonymous.get()
        
        if not self.users and not allow_anon:
            messagebox.showerror("오류", "최소 한 명의 사용자를 추가하거나 익명 로그인을 허용해야 합니다.")
            return
        
        # 루트 디렉토리 생성
        if not os.path.exists(root_dir):
            try:
                os.makedirs(root_dir)
                self.log(f"루트 디렉토리 생성: {root_dir}")
            except Exception as e:
                messagebox.showerror("오류", f"디렉토리 생성 실패:\n{str(e)}")
                return
                
        try:
            # Authorizer 설정
            authorizer = DummyAuthorizer()
            
            # 사용자 추가
            for user in self.users:
                home_dir = user['home_dir']
                if not os.path.exists(home_dir):
                    os.makedirs(home_dir)
                authorizer.add_user(user['username'], user['password'], home_dir, perm=user['perms'])
                self.log(f"사용자 등록: {user['username']} (권한: {user['perms']})")
            
            # 익명 로그인 설정
            if allow_anon:
                if not os.path.exists(root_dir):
                    os.makedirs(root_dir)
                authorizer.add_anonymous(root_dir, perm="elr")  # 익명은 읽기 전용
                self.log("익명 로그인 허용 (읽기 전용)")
            
            # Handler 및 TLS 설정
            if self.use_ftps.get():
                cert = self.cert_path.get()
                key = self.key_path.get()
                if not os.path.exists(cert) or not os.path.exists(key):
                    if messagebox.askyesno("인증서 오류", "인증서 또는 개인키 파일이 없습니다. 자동으로 생성할까요?"):
                        self.generate_self_signed_cert()
                    else:
                        return
                
                handler = TLS_FTPHandler
                handler.certfile = cert
                handler.keyfile = key
                handler.tls_control_conn = True
                handler.tls_data_conn = True
                self.log("FTPS (TLS/SSL) 암호화 활성화")
            else:
                handler = FTPHandler
                
            handler.authorizer = authorizer
            
            # 서버 생성
            server = FTPServer(("0.0.0.0", port), handler)
            self.server = server
            
            # 접속 제한 설정
            server.max_cons = self.max_cons.get()
            server.max_cons_per_ip = self.max_cons_per_ip.get()
            
            # 서버를 별도 스레드에서 실행
            def run_server():
                try:
                    self.log(f"FTP 서버 시작 - 포트: {port}")
                    self.log(f"로컬 IP: {self.get_local_ip()}")
                    self.log(f"등록된 사용자: {len(self.users)}명")
                    assert self.server is not None
                    self.server.serve_forever()
                except Exception as e:
                    self.log(f"서버 오류: {str(e)}")
                    
            self.server_thread = threading.Thread(target=run_server, daemon=True)
            assert self.server_thread is not None
            self.server_thread.start()
            
            self.is_running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text=f"● 서버 실행 중 - 포트 {port}", foreground="green")
            
            user_info = "\n".join([f"  - {u['username']}" for u in self.users])
            anon_info = "\n  - anonymous (익명)" if allow_anon else ""
            
            messagebox.showinfo("성공", f"FTP 서버가 포트 {port}에서 시작되었습니다.\n\n"
                                       f"접속 정보:\n"
                                       f"주소: {self.get_local_ip()}\n"
                                       f"포트: {port}\n\n"
                                       f"등록된 사용자:\n{user_info}{anon_info}")
        except Exception as e:
            messagebox.showerror("오류", f"서버 시작 실패:\n{str(e)}")
            self.log(f"서버 시작 실패: {str(e)}")
            
    def stop_server(self) -> None:
        """FTP 서버 중지"""
        if self.server:
            try:
                assert self.server is not None
                self.server.close_all()
                self.log("FTP 서버 중지됨")
                self.is_running = False
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
                self.status_label.config(text="● 서버 중지됨", foreground="red")
                messagebox.showinfo("알림", "FTP 서버가 중지되었습니다.")
            except Exception as e:
                messagebox.showerror("오류", f"서버 중지 실패:\n{str(e)}")
                
    def get_local_ip(self) -> str:
        """로컬 IP 주소 가져오기"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"



class FTPClientTab:
    """FTP 클라이언트 탭 (기존 코드)"""
    def __init__(self, parent: ttk.Frame):
        self.parent = parent
        
        # FTP 연결 및 경로 정보
        self.ftp: Optional[FTP] = None
        self.current_remote_path = "/"
        self.current_local_path = os.path.expanduser("~")
        
        # UI 위젯들
        self.host_entry: ttk.Entry
        self.port_entry: ttk.Entry
        self.user_entry: ttk.Entry
        self.pass_entry: ttk.Entry
        self.connect_btn: ttk.Button
        self.disconnect_btn: ttk.Button
        self.local_path_entry: ttk.Entry
        self.local_tree: ttk.Treeview
        self.remote_path_entry: ttk.Entry
        self.remote_tree: ttk.Treeview
        self.status_label: ttk.Label
        self.progress: ttk.Progressbar
        self.use_ftps = tk.BooleanVar(value=False)
        
        self.setup_ui()
        self.refresh_local_view()
        
    def setup_ui(self) -> None:
        """클라이언트 탭 UI 구성"""
        # 상단 연결 프레임
        connection_frame = ttk.LabelFrame(self.parent, text="서버 연결", padding=10)
        connection_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(connection_frame, text="호스트:").grid(row=0, column=0, padx=5)
        self.host_entry = ttk.Entry(connection_frame, width=20)
        self.host_entry.grid(row=0, column=1, padx=5)
        self.host_entry.insert(0, "127.0.0.1")
        
        ttk.Label(connection_frame, text="포트:").grid(row=0, column=2, padx=5)
        self.port_entry = ttk.Entry(connection_frame, width=8)
        self.port_entry.grid(row=0, column=3, padx=5)
        self.port_entry.insert(0, "2121")
        
        ttk.Label(connection_frame, text="사용자명:").grid(row=0, column=4, padx=5)
        self.user_entry = ttk.Entry(connection_frame, width=15)
        self.user_entry.grid(row=0, column=5, padx=5)
        self.user_entry.insert(0, "user")
        
        ttk.Label(connection_frame, text="비밀번호:").grid(row=0, column=6, padx=5)
        self.pass_entry = ttk.Entry(connection_frame, width=15, show="*")
        self.pass_entry.grid(row=0, column=7, padx=5)
        self.pass_entry.insert(0, "12345")
        
        self.connect_btn = ttk.Button(connection_frame, text="연결", command=self.connect)
        self.connect_btn.grid(row=0, column=8, padx=5)
        
        self.disconnect_btn = ttk.Button(connection_frame, text="연결 해제", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_btn.grid(row=0, column=9, padx=5)
        
        ttk.Checkbutton(connection_frame, text="FTPS", variable=self.use_ftps).grid(row=0, column=10, padx=5)
        
        # 메인 프레임 (로컬/원격 2개 패널)
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 로컬 파일 패널
        local_frame = ttk.LabelFrame(main_frame, text="로컬 파일", padding=10)
        local_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # 로컬 경로
        local_path_frame = ttk.Frame(local_frame)
        local_path_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(local_path_frame, text="경로:").pack(side=tk.LEFT)
        self.local_path_entry = ttk.Entry(local_path_frame)
        self.local_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.local_path_entry.insert(0, self.current_local_path)
        
        ttk.Button(local_path_frame, text="이동", command=self.change_local_dir).pack(side=tk.LEFT)
        ttk.Button(local_path_frame, text="상위", command=self.local_parent_dir).pack(side=tk.LEFT, padx=2)
        
        # 로컬 파일 트리뷰
        local_tree_frame = ttk.Frame(local_frame)
        local_tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.local_tree = ttk.Treeview(local_tree_frame, columns=("크기", "수정일"), show="tree headings")
        self.local_tree.heading("#0", text="이름")
        self.local_tree.heading("크기", text="크기")
        self.local_tree.heading("수정일", text="수정일")
        self.local_tree.column("#0", width=200)
        self.local_tree.column("크기", width=100)
        self.local_tree.column("수정일", width=150)
        
        local_scrollbar = ttk.Scrollbar(local_tree_frame, orient=tk.VERTICAL, command=self.local_tree.yview)
        self.local_tree.configure(yscrollcommand=local_scrollbar.set)
        
        self.local_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        local_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.local_tree.bind("<Double-1>", self.on_local_double_click)
        
        # 로컬 버튼
        local_btn_frame = ttk.Frame(local_frame)
        local_btn_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(local_btn_frame, text="새로고침", command=self.refresh_local_view).pack(side=tk.LEFT, padx=2)
        ttk.Button(local_btn_frame, text="업로드 ➜", command=self.upload_file).pack(side=tk.LEFT, padx=2)
        
        # 원격 파일 패널
        remote_frame = ttk.LabelFrame(main_frame, text="원격 파일 (FTP 서버)", padding=10)
        remote_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        # 원격 경로
        remote_path_frame = ttk.Frame(remote_frame)
        remote_path_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(remote_path_frame, text="경로:").pack(side=tk.LEFT)
        self.remote_path_entry = ttk.Entry(remote_path_frame)
        self.remote_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.remote_path_entry.insert(0, self.current_remote_path)
        
        ttk.Button(remote_path_frame, text="이동", command=self.change_remote_dir).pack(side=tk.LEFT)
        ttk.Button(remote_path_frame, text="상위", command=self.remote_parent_dir).pack(side=tk.LEFT, padx=2)
        
        # 원격 파일 트리뷰
        remote_tree_frame = ttk.Frame(remote_frame)
        remote_tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.remote_tree = ttk.Treeview(remote_tree_frame, columns=("크기", "권한", "수정일"), show="tree headings")
        self.remote_tree.heading("#0", text="이름")
        self.remote_tree.heading("크기", text="크기")
        self.remote_tree.heading("권한", text="권한")
        self.remote_tree.heading("수정일", text="수정일")
        self.remote_tree.column("#0", width=200)
        self.remote_tree.column("크기", width=100)
        self.remote_tree.column("권한", width=100)
        self.remote_tree.column("수정일", width=120)
        
        remote_scrollbar = ttk.Scrollbar(remote_tree_frame, orient=tk.VERTICAL, command=self.remote_tree.yview)
        self.remote_tree.configure(yscrollcommand=remote_scrollbar.set)
        
        self.remote_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        remote_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.remote_tree.bind("<Double-1>", self.on_remote_double_click)
        
        # 원격 버튼
        remote_btn_frame = ttk.Frame(remote_frame)
        remote_btn_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(remote_btn_frame, text="새로고침", command=self.refresh_remote_view).pack(side=tk.LEFT, padx=2)
        ttk.Button(remote_btn_frame, text="➜ 다운로드", command=self.download_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(remote_btn_frame, text="삭제", command=self.delete_remote_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(remote_btn_frame, text="폴더 생성", command=self.create_remote_dir).pack(side=tk.LEFT, padx=2)
        
        # 하단 상태 표시줄
        status_frame = ttk.Frame(self.parent)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="연결되지 않음", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate', length=200)
        self.progress.pack(side=tk.RIGHT, padx=5)
        
    def connect(self) -> None:
        """FTP 서버에 연결"""
        host = self.host_entry.get()
        port = int(self.port_entry.get())
        user = self.user_entry.get()
        password = self.pass_entry.get()
        
        try:
            if self.use_ftps.get():
                ftp_conn = FTP_TLS()
                self.ftp = ftp_conn
            else:
                ftp_conn = FTP()
                self.ftp = ftp_conn
                
            ftp_conn.connect(host, port, timeout=10)
            ftp_conn.login(user, password)
            
            if self.use_ftps.get() and isinstance(ftp_conn, FTP_TLS):
                ftp_conn.prot_p() # 데이터 연결도 암호화
            
            self.status_label.config(text=f"연결됨: {host}:{port}")
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            
            self.current_remote_path = self.ftp.pwd()
            self.remote_path_entry.delete(0, tk.END)
            self.remote_path_entry.insert(0, self.current_remote_path)
            
            self.refresh_remote_view()
            messagebox.showinfo("성공", f"{host}에 성공적으로 연결되었습니다.")
        except Exception as e:
            messagebox.showerror("연결 오류", f"FTP 서버 연결 실패:\n{str(e)}")
            self.ftp = None
            
    def disconnect(self) -> None:
        """FTP 연결 해제"""
        if self.ftp:
            assert self.ftp is not None
            try:
                self.ftp.quit()
            except:
                pass
            self.ftp = None
            
        self.status_label.config(text="연결되지 않음")
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        
        for item in self.remote_tree.get_children():
            self.remote_tree.delete(item)
            
    def refresh_local_view(self) -> None:
        """로컬 파일 목록 새로고침"""
        for item in self.local_tree.get_children():
            self.local_tree.delete(item)
            
        try:
            items = os.listdir(self.current_local_path)
            items.sort()
            
            for item in items:
                full_path = os.path.join(self.current_local_path, item)
                if os.path.isdir(full_path):
                    try:
                        mtime = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d %H:%M")
                        self.local_tree.insert("", tk.END, text=f"📁 {item}", values=("<DIR>", mtime), tags=("folder",))
                    except:
                        self.local_tree.insert("", tk.END, text=f"📁 {item}", values=("<DIR>", ""), tags=("folder",))
                        
            for item in items:
                full_path = os.path.join(self.current_local_path, item)
                if os.path.isfile(full_path):
                    try:
                        size = os.path.getsize(full_path)
                        size_str = self.format_size(size)
                        mtime = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d %H:%M")
                        self.local_tree.insert("", tk.END, text=f"📄 {item}", values=(size_str, mtime), tags=("file",))
                    except:
                        self.local_tree.insert("", tk.END, text=f"📄 {item}", values=("", ""), tags=("file",))
        except Exception as e:
            messagebox.showerror("오류", f"로컬 디렉토리 읽기 실패:\n{str(e)}")
            
    def refresh_remote_view(self) -> None:
        """원격 파일 목록 새로고침"""
        if not self.ftp:
            return
        
        assert self.ftp is not None
            
        for item in self.remote_tree.get_children():
            self.remote_tree.delete(item)
            
        try:
            files = []
            self.ftp.dir(files.append)
            
            for file_info in files:
                parts = file_info.split(None, 8)
                if len(parts) < 9:
                    continue
                    
                permissions = parts[0]
                size = parts[4]
                name = parts[8]
                date_time = f"{parts[5]} {parts[6]} {parts[7]}"
                
                is_dir = permissions.startswith('d')
                
                if is_dir:
                    self.remote_tree.insert("", tk.END, text=f"📁 {name}", 
                                          values=("<DIR>", permissions, date_time), tags=("folder",))
                else:
                    size_str = self.format_size(int(size))
                    self.remote_tree.insert("", tk.END, text=f"📄 {name}", 
                                          values=(size_str, permissions, date_time), tags=("file",))
        except Exception as e:
            messagebox.showerror("오류", f"원격 디렉토리 읽기 실패:\n{str(e)}")
            
    def on_local_double_click(self, event) -> None:
        """로컬 파일 더블클릭 처리"""
        selection = self.local_tree.selection()
        if not selection:
            return
            
        item = self.local_tree.item(selection[0])
        name = item['text'].replace("📁 ", "").replace("📄 ", "")
        
        if "folder" in item['tags']:
            new_path = os.path.join(self.current_local_path, name)
            if os.path.isdir(new_path):
                self.current_local_path = new_path
                self.local_path_entry.delete(0, tk.END)
                self.local_path_entry.insert(0, self.current_local_path)
                self.refresh_local_view()
                
    def on_remote_double_click(self, event) -> None:
        """원격 파일 더블클릭 처리"""
        if not self.ftp:
            return
        
        assert self.ftp is not None
            
        selection = self.remote_tree.selection()
        if not selection:
            return
            
        item = self.remote_tree.item(selection[0])
        name = item['text'].replace("📁 ", "").replace("📄 ", "")
        
        if "folder" in item['tags']:
            try:
                self.ftp.cwd(name)
                self.current_remote_path = self.ftp.pwd()
                self.remote_path_entry.delete(0, tk.END)
                self.remote_path_entry.insert(0, self.current_remote_path)
                self.refresh_remote_view()
            except Exception as e:
                messagebox.showerror("오류", f"디렉토리 변경 실패:\n{str(e)}")
                
    def change_local_dir(self) -> None:
        """로컬 디렉토리 변경"""
        new_path = self.local_path_entry.get()
        if os.path.isdir(new_path):
            self.current_local_path = new_path
            self.refresh_local_view()
        else:
            messagebox.showerror("오류", "유효하지 않은 경로입니다.")
            
    def change_remote_dir(self) -> None:
        """원격 디렉토리 변경"""
        if not self.ftp:
            return
        
        assert self.ftp is not None
            
        new_path = self.remote_path_entry.get()
        try:
            self.ftp.cwd(new_path)
            self.current_remote_path = self.ftp.pwd()
            self.refresh_remote_view()
        except Exception as e:
            messagebox.showerror("오류", f"디렉토리 변경 실패:\n{str(e)}")
            
    def local_parent_dir(self) -> None:
        """로컬 상위 디렉토리로 이동"""
        parent = os.path.dirname(self.current_local_path)
        if parent and parent != self.current_local_path:
            self.current_local_path = parent
            self.local_path_entry.delete(0, tk.END)
            self.local_path_entry.insert(0, self.current_local_path)
            self.refresh_local_view()
            
    def remote_parent_dir(self) -> None:
        """원격 상위 디렉토리로 이동"""
        if not self.ftp:
            return
        
        assert self.ftp is not None
            
        try:
            self.ftp.cwd("..")
            self.current_remote_path = self.ftp.pwd()
            self.remote_path_entry.delete(0, tk.END)
            self.remote_path_entry.insert(0, self.current_remote_path)
            self.refresh_remote_view()
        except Exception as e:
            messagebox.showerror("오류", f"상위 디렉토리 이동 실패:\n{str(e)}")
            
    def upload_file(self) -> None:
        """파일 업로드"""
        if not self.ftp:
            messagebox.showwarning("경고", "먼저 FTP 서버에 연결하세요.")
            return
        
        assert self.ftp is not None
        ftp_conn = self.ftp
            
        selection = self.local_tree.selection()
        if not selection:
            messagebox.showwarning("경고", "업로드할 파일을 선택하세요.")
            return
            
        item = self.local_tree.item(selection[0])
        if "folder" in item['tags']:
            messagebox.showwarning("경고", "폴더 업로드는 현재 지원되지 않습니다.")
            return
            
        filename = item['text'].replace("📄 ", "")
        local_path = os.path.join(self.current_local_path, filename)
        
        def do_upload():
            try:
                self.progress.start()
                with open(local_path, 'rb') as f:
                    ftp_conn.storbinary(f'STOR {filename}', f)
                self.progress.stop()
                self.status_label.config(text=f"업로드 완료: {filename}")
                self.refresh_remote_view()
                messagebox.showinfo("성공", f"{filename} 업로드 완료")
            except Exception as e:
                self.progress.stop()
                messagebox.showerror("오류", f"업로드 실패:\n{str(e)}")
                
        threading.Thread(target=do_upload, daemon=True).start()
        
    def download_file(self) -> None:
        """파일 다운로드"""
        if not self.ftp:
            messagebox.showwarning("경고", "먼저 FTP 서버에 연결하세요.")
            return
        
        assert self.ftp is not None
        ftp_conn = self.ftp
            
        selection = self.remote_tree.selection()
        if not selection:
            messagebox.showwarning("경고", "다운로드할 파일을 선택하세요.")
            return
            
        item = self.remote_tree.item(selection[0])
        if "folder" in item['tags']:
            messagebox.showwarning("경고", "폴더 다운로드는 현재 지원되지 않습니다.")
            return
            
        filename = item['text'].replace("📄 ", "")
        local_path = os.path.join(self.current_local_path, filename)
        
        def do_download():
            try:
                self.progress.start()
                with open(local_path, 'wb') as f:
                    ftp_conn.retrbinary(f'RETR {filename}', f.write)
                self.progress.stop()
                self.status_label.config(text=f"다운로드 완료: {filename}")
                self.refresh_local_view()
                messagebox.showinfo("성공", f"{filename} 다운로드 완료")
            except Exception as e:
                self.progress.stop()
                messagebox.showerror("오류", f"다운로드 실패:\n{str(e)}")
                
        threading.Thread(target=do_download, daemon=True).start()
        
    def delete_remote_file(self) -> None:
        """원격 파일 삭제"""
        if not self.ftp:
            messagebox.showwarning("경고", "먼저 FTP 서버에 연결하세요.")
            return
        
        assert self.ftp is not None
            
        selection = self.remote_tree.selection()
        if not selection:
            messagebox.showwarning("경고", "삭제할 파일을 선택하세요.")
            return
            
        item = self.remote_tree.item(selection[0])
        filename = item['text'].replace("📁 ", "").replace("📄 ", "")
        
        if not messagebox.askyesno("확인", f"'{filename}'을(를) 정말 삭제하시겠습니까?"):
            return
            
        try:
            if "folder" in item['tags']:
                self.ftp.rmd(filename)
            else:
                self.ftp.delete(filename)
            self.status_label.config(text=f"삭제 완료: {filename}")
            self.refresh_remote_view()
        except Exception as e:
            messagebox.showerror("오류", f"삭제 실패:\n{str(e)}")
            
    def create_remote_dir(self) -> None:
        """원격 디렉토리 생성"""
        if not self.ftp:
            messagebox.showwarning("경고", "먼저 FTP 서버에 연결하세요.")
            return
        
        assert self.ftp is not None
            
        from tkinter import simpledialog
        dirname = simpledialog.askstring("폴더 생성", "새 폴더 이름:")
        
        if dirname:
            try:
                self.ftp.mkd(dirname)
                self.status_label.config(text=f"폴더 생성 완료: {dirname}")
                self.refresh_remote_view()
            except Exception as e:
                messagebox.showerror("오류", f"폴더 생성 실패:\n{str(e)}")
                
    def format_size(self, size: int) -> str:
        """파일 크기를 읽기 쉬운 형식으로 변환"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"


class SimpleFTPApp:
    """메인 애플리케이션"""
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SimpleFTP - FTP Server & Client")
        self.root.geometry("1200x750")
        
        # 탭 컨트롤 생성
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 서버 탭 (기본)
        server_frame = ttk.Frame(self.notebook)
        self.notebook.add(server_frame, text="🖥️  FTP 서버")
        self.server_tab = FTPServerTab(server_frame)
        
        # 클라이언트 탭
        client_frame = ttk.Frame(self.notebook)
        self.notebook.add(client_frame, text="💻  FTP 클라이언트")
        self.client_tab = FTPClientTab(client_frame)
        
        # 기본 탭을 서버로 설정
        self.notebook.select(0)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def on_closing(self) -> None:
        """프로그램 종료 시 처리"""
        # 서버가 실행 중이면 중지
        if self.server_tab.is_running:
            if messagebox.askokcancel("종료", "FTP 서버가 실행 중입니다. 종료하시겠습니까?"):
                self.server_tab.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    root = tk.Tk()
    app = SimpleFTPApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
