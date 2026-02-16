import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ftplib import FTP, error_perm
import os
import threading
from datetime import datetime
from typing import Optional


class FTPClient:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SimpleFTP - FTP Client")
        self.root.geometry("1200x700")
        
        # FTP 연결 및 경로 정보
        self.ftp: Optional[FTP] = None
        self.current_remote_path = "/"
        self.current_local_path = os.path.expanduser("~")
        
        # UI 위젯들 (setup_ui에서 초기화됨)
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
        
        self.setup_ui()
        self.refresh_local_view()
        
    def setup_ui(self):
        """UI 구성"""
        # 스타일 설정
        style = ttk.Style()
        style.theme_use('clam')
        
        # 상단 연결 프레임
        connection_frame = ttk.LabelFrame(self.root, text="서버 연결", padding=10)
        connection_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(connection_frame, text="호스트:").grid(row=0, column=0, padx=5)
        self.host_entry = ttk.Entry(connection_frame, width=20)
        self.host_entry.grid(row=0, column=1, padx=5)
        self.host_entry.insert(0, "ftp.example.com")
        
        ttk.Label(connection_frame, text="포트:").grid(row=0, column=2, padx=5)
        self.port_entry = ttk.Entry(connection_frame, width=8)
        self.port_entry.grid(row=0, column=3, padx=5)
        self.port_entry.insert(0, "21")
        
        ttk.Label(connection_frame, text="사용자명:").grid(row=0, column=4, padx=5)
        self.user_entry = ttk.Entry(connection_frame, width=15)
        self.user_entry.grid(row=0, column=5, padx=5)
        
        ttk.Label(connection_frame, text="비밀번호:").grid(row=0, column=6, padx=5)
        self.pass_entry = ttk.Entry(connection_frame, width=15, show="*")
        self.pass_entry.grid(row=0, column=7, padx=5)
        
        self.connect_btn = ttk.Button(connection_frame, text="연결", command=self.connect)
        self.connect_btn.grid(row=0, column=8, padx=5)
        
        self.disconnect_btn = ttk.Button(connection_frame, text="연결 해제", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_btn.grid(row=0, column=9, padx=5)
        
        # 메인 프레임 (로컬/원격 2개 패널)
        main_frame = ttk.Frame(self.root)
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
        self.remote_tree.bind("<Button-3>", self.show_remote_context_menu)
        
        # 원격 버튼
        remote_btn_frame = ttk.Frame(remote_frame)
        remote_btn_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(remote_btn_frame, text="새로고침", command=self.refresh_remote_view).pack(side=tk.LEFT, padx=2)
        ttk.Button(remote_btn_frame, text="➜ 다운로드", command=self.download_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(remote_btn_frame, text="삭제", command=self.delete_remote_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(remote_btn_frame, text="폴더 생성", command=self.create_remote_dir).pack(side=tk.LEFT, padx=2)
        
        # 하단 상태 표시줄
        status_frame = ttk.Frame(self.root)
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
            self.ftp = FTP()
            assert self.ftp is not None  # 타입 체커를 위한 검증
            self.ftp.connect(host, port, timeout=10)
            self.ftp.login(user, password)
            
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
            assert self.ftp is not None  # 타입 체커를 위한 검증
            try:
                self.ftp.quit()
            except:
                pass
            self.ftp = None
            
        self.status_label.config(text="연결되지 않음")
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        
        # 원격 트리 초기화
        for item in self.remote_tree.get_children():
            self.remote_tree.delete(item)
            
    def refresh_local_view(self):
        """로컬 파일 목록 새로고침"""
        for item in self.local_tree.get_children():
            self.local_tree.delete(item)
            
        try:
            items = os.listdir(self.current_local_path)
            items.sort()
            
            # 폴더 먼저
            for item in items:
                full_path = os.path.join(self.current_local_path, item)
                if os.path.isdir(full_path):
                    try:
                        mtime = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d %H:%M")
                        self.local_tree.insert("", tk.END, text=f"📁 {item}", values=("<DIR>", mtime), tags=("folder",))
                    except:
                        self.local_tree.insert("", tk.END, text=f"📁 {item}", values=("<DIR>", ""), tags=("folder",))
                        
            # 파일
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
        
        assert self.ftp is not None  # 타입 체커를 위한 검증
            
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
                
                # 날짜/시간 정보 결합
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
            
    def on_local_double_click(self, event):
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
        
        assert self.ftp is not None  # 타입 체커를 위한 검증
            
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
                
    def change_local_dir(self):
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
        
        assert self.ftp is not None  # 타입 체커를 위한 검증
            
        new_path = self.remote_path_entry.get()
        try:
            self.ftp.cwd(new_path)
            self.current_remote_path = self.ftp.pwd()
            self.refresh_remote_view()
        except Exception as e:
            messagebox.showerror("오류", f"디렉토리 변경 실패:\n{str(e)}")
            
    def local_parent_dir(self):
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
        
        assert self.ftp is not None  # 타입 체커를 위한 검증
            
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
        
        assert self.ftp is not None  # 타입 체커를 위한 검증
        ftp_conn = self.ftp  # 클로저에서 사용하기 위해 로컬 변수에 저장
            
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
                self.root.after(0, self.refresh_remote_view)
                self.root.after(0, lambda: messagebox.showinfo("성공", f"{filename} 업로드 완료"))
            except Exception as e:
                self.progress.stop()
                self.root.after(0, lambda: messagebox.showerror("오류", f"업로드 실패:\n{str(e)}"))
                
        threading.Thread(target=do_upload, daemon=True).start()
        
    def download_file(self) -> None:
        """파일 다운로드"""
        if not self.ftp:
            messagebox.showwarning("경고", "먼저 FTP 서버에 연결하세요.")
            return
        
        assert self.ftp is not None  # 타입 체커를 위한 검증
        ftp_conn = self.ftp  # 클로저에서 사용하기 위해 로컬 변수에 저장
            
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
                self.root.after(0, self.refresh_local_view)
                self.root.after(0, lambda: messagebox.showinfo("성공", f"{filename} 다운로드 완료"))
            except Exception as e:
                self.progress.stop()
                self.root.after(0, lambda: messagebox.showerror("오류", f"다운로드 실패:\n{str(e)}"))
                
        threading.Thread(target=do_download, daemon=True).start()
        
    def delete_remote_file(self) -> None:
        """원격 파일 삭제"""
        if not self.ftp:
            messagebox.showwarning("경고", "먼저 FTP 서버에 연결하세요.")
            return
        
        assert self.ftp is not None  # 타입 체커를 위한 검증
            
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
        
        assert self.ftp is not None  # 타입 체커를 위한 검증
            
        from tkinter import simpledialog
        dirname = simpledialog.askstring("폴더 생성", "새 폴더 이름:")
        
        if dirname:
            try:
                self.ftp.mkd(dirname)
                self.status_label.config(text=f"폴더 생성 완료: {dirname}")
                self.refresh_remote_view()
            except Exception as e:
                messagebox.showerror("오류", f"폴더 생성 실패:\n{str(e)}")
                
    def show_remote_context_menu(self, event):
        """원격 파일 우클릭 메뉴"""
        # TODO: 추가 기능 (이름 변경, 권한 변경 등)
        pass
        
    def format_size(self, size):
        """파일 크기를 읽기 쉬운 형식으로 변환"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"


def main():
    root = tk.Tk()
    app = FTPClient(root)
    root.mainloop()


if __name__ == "__main__":
    main()
