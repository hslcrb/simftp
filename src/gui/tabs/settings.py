import tkinter as tk
from tkinter import ttk, messagebox
import os
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone

class SettingsTab(ttk.Frame):
    """보안 도구 및 서버 자동 재시작 스케줄링 기능을 제공하는 설정 탭"""
    def __init__(self, parent, config_manager, server_tab):
        super().__init__(parent)
        self.config_manager = config_manager
        self.server_tab = server_tab
        
        # 권장 설정: 매일 00:01 한국 표준시(KST) 재시작 활성화
        self.auto_restart = tk.BooleanVar(value=True)
        
        self._setup_ui()
        self._start_scheduler()

    def _setup_ui(self):
        container = ttk.Frame(self, padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Label(container, text="🛠️ 시스템 설정 및 보안 도구", font=("Malgun Gothic", 16, "bold"))
        header.pack(pady=(0, 20))

        # --- 서버 관리 스케줄링 ---
        sched_frame = ttk.LabelFrame(container, text="📅 서버 관리 스케줄링 (권장 설정)", padding=15)
        sched_frame.pack(fill=tk.X, pady=10)

        sched_info = (
            "서버의 안정성과 바뀐 공인 IP의 자동 갱신을 위해\n"
            "매일 00시 01분(KST)에 서버를 자동으로 재시작합니다."
        )
        ttk.Label(sched_frame, text=sched_info).pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Checkbutton(sched_frame, text="매일 00:01 (KST) 자동 재시작 활성화", variable=self.auto_restart).pack(side=tk.RIGHT)

        # --- 위험 구역 (Critical Zone) ---
        danger_frame = ttk.LabelFrame(container, text="🚨 위험 구역 (Critical Zone)", padding=15)
        danger_frame.pack(fill=tk.X, pady=10)

        warning_text = (
            "주의: 아래 작업들은 시스템 보안 데이터를 초기화합니다.\n"
            "작업 후에는 기존 설정이나 비밀번호를 복구할 수 없을 수 있습니다."
        )
        ttk.Label(danger_frame, text=warning_text, foreground="red").pack(pady=(0, 15))

        # 마스터 키 초기화 버튼
        self.reset_key_btn = tk.Button(
            danger_frame, 
            text="🔑 마스터 키(master.key) 초기화 및 재생성", 
            bg="#dc3545", 
            fg="white", 
            font=("Malgun Gothic", 10, "bold"),
            command=self.confirm_reset_master_key,
            padx=10,
            pady=5
        )
        self.reset_key_btn.pack(fill=tk.X, pady=5)
        ttk.Label(danger_frame, text="※ 초기화 시 기존 유저들의 모든 비밀번호를 다시 설정해야 합니다.", font=("Malgun Gothic", 8)).pack()

        # SSL 인증서 초기화 버튼
        self.reset_cert_btn = tk.Button(
            danger_frame, 
            text="📜 SSL/TLS 인증서 초기화 및 재생성", 
            bg="#6c757d", 
            fg="white", 
            font=("Malgun Gothic", 10, "bold"),
            command=self.confirm_reset_certs,
            padx=10,
            pady=5
        )
        self.reset_cert_btn.pack(fill=tk.X, pady=(15, 5))
        ttk.Label(danger_frame, text="※ 인증서 갱신이 필요하거나 개인키 유출이 의심될 때 사용하세요.", font=("Malgun Gothic", 8)).pack()

        # --- 정보 영역 ---
        info_frame = ttk.LabelFrame(container, text="ℹ️ 시스템 정보", padding=15)
        info_frame.pack(fill=tk.X, pady=10)
        
        config_path = self.config_manager.config_dir
        ttk.Label(info_frame, text=f"설정 저장 경로: {config_path}").pack(anchor=tk.W)

    def _start_scheduler(self):
        """백그라운드 스케줄러 스레드 시작"""
        thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        thread.start()

    def _scheduler_loop(self):
        """매일 00:01 KST에 서버 재시작 여부 확인"""
        last_run_date = ""
        while True:
            try:
                if self.auto_restart.get():
                    # KST (UTC+9) 시간 계산
                    kst_now = datetime.now(timezone(timedelta(hours=9)))
                    current_date = kst_now.strftime("%Y-%m-%d")
                    
                    # 00:01분인지 확인 (초 단위는 무시하고 1분 동안 체크)
                    if kst_now.hour == 0 and kst_now.minute == 1:
                        if last_run_date != current_date:
                            self.server_tab.log("⏰ 스케줄러: 예정된 자동 재시작을 수행합니다. (KST 00:01)")
                            self._perform_restart()
                            last_run_date = current_date
                
                # 30초마다 체크
                time.sleep(30)
            except Exception as e:
                print(f"[Scheduler Error] {e}")
                time.sleep(60)

    def _perform_restart(self):
        """서버가 구동 중이면 중지 후 다시 시작"""
        if self.server_tab.server:
            # GUI 스레드에서 실행하도록 after 사용
            self.after(0, self._restart_logic)

    def _restart_logic(self):
        """실제 재시작 로직 호출 (GUI 세이프)"""
        was_running = self.server_tab.server is not None
        if was_running:
            self.server_tab.stop_server()
            # 서버가 완전히 내려갈 시간을 약간 줌
            self.after(2000, self.server_tab.start_server)
        else:
            # 가동 중이 아니었더라도 자동 가동 설정에 따라 시작 가능
            self.server_tab.start_server()

    def confirm_reset_master_key(self):
        """3번의 경고 후 마스터 키 초기화 (진행률 표시)"""
        if not messagebox.askretrycancel("⚠️ 1단계 경고 (1/3)", "정말로 마스터 키를 초기화하시겠습니까?\n이 작업은 모든 계정의 비밀번호를 읽을 수 없게 만듭니다."):
            return
        if not messagebox.askyesno("⚠️⚠️ 2단계 경고 (2/3)", "이 작업은 절대로 되돌릴 수 없습니다.\n계속 진행하시겠습니까?"):
            return
        if not messagebox.askokcancel("⚠️⚠️⚠️ 최종 확인 (3/3)", "마지막 확인입니다. [확인] 클릭 시 즉시 삭제 및 재생성됩니다."):
            return
        
        try:
            key_path = os.path.join(self.config_manager.config_dir, 'master.key')
            if os.path.exists(key_path):
                os.remove(key_path)
            
            from core.utils import get_master_key
            get_master_key()
            
            messagebox.showinfo("완료", "마스터 키가 성공적으로 재생성되었습니다.\n이제 계정 목록에서 비밀번호를 모두 재설정해 주세요.")
        except Exception as e:
            messagebox.showerror("오류", f"초기화 실패: {str(e)}")

    def confirm_reset_certs(self):
        """3번의 경고 후 SSL 인증서 초기화 (진행률 표시)"""
        if not messagebox.askretrycancel("⚠️ 1단계 경고 (1/3)", "SSL/TLS 인증서를 초기화하시겠습니까?\n기존 보안 연결 정보가 삭제됩니다."):
            return
        if not messagebox.askyesno("⚠️⚠️ 2단계 경고 (2/3)", "인증서를 새로 생성하면 기존 연결이 끊길 수 있습니다.\n계속하시겠습니까?"):
            return
        if not messagebox.askokcancel("⚠️⚠️⚠️ 최종 확인 (3/3)", "인증서와 개인키를 삭제하고 즉시 다시 만듭니다."):
            return
            
        try:
            cp, kp = self.config_manager.get_cert_paths()
            if os.path.exists(cp): os.remove(cp)
            if os.path.exists(kp): os.remove(kp)
            
            from core.utils import generate_ssl_cert
            generate_ssl_cert(cp, kp)
            
            messagebox.showinfo("완료", "SSL 인증서와 개인키가 새로 생성되었습니다.")
        except Exception as e:
            messagebox.showerror("오류", f"초기화 실패: {str(e)}")
