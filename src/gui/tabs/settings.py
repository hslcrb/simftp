import tkinter as tk
from tkinter import ttk, messagebox
import os
import shutil

class SettingsTab(ttk.Frame):
    """보안 도구 및 초기화 기능을 제공하는 설정 탭"""
    def __init__(self, parent, config_manager):
        super().__init__(parent)
        self.config_manager = config_manager
        self._setup_ui()

    def _setup_ui(self):
        container = ttk.Frame(self, padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Label(container, text="🛠️ 시스템 설정 및 보안 도구", font=("Malgun Gothic", 16, "bold"))
        header.pack(pady=(0, 20))

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

    def confirm_reset_master_key(self):
        """3번의 경고 후 마스터 키 초기화"""
        if not messagebox.askretrycancel("⚠️ 1차 경고", "정말로 마스터 키를 초기화하시겠습니까?\n모든 계정의 비밀번호를 읽을 수 없게 됩니다."):
            return
        if not messagebox.askyesno("⚠️⚠️ 2차 경고", "이 작업은 되돌릴 수 없습니다. \n계속하시겠습니까?"):
            return
        if not messagebox.askokcancel("⚠️⚠️⚠️ 최종 확인", "마지막 확인입니다. 클릭 시 즉시 삭제 및 재생성됩니다."):
            return
        
        try:
            key_path = os.path.join(self.config_manager.config_dir, 'master.key')
            if os.path.exists(key_path):
                os.remove(key_path)
            
            # 재생성 유도 (utils.get_master_key 호출)
            from core.utils import get_master_key
            get_master_key()
            
            messagebox.showinfo("완료", "마스터 키가 성공적으로 재생성되었습니다.\n이제 계정 목록에서 비밀번호를 모두 재설정해 주세요.")
        except Exception as e:
            messagebox.showerror("오류", f"초기화 실패: {str(e)}")

    def confirm_reset_certs(self):
        """SSL 인증서 초기화"""
        if not messagebox.askyesno("확인", "인증서를 초기화하고 새로 만드시겠습니까?"):
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
