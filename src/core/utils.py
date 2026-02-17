import socket
import urllib.request
from datetime import datetime
from OpenSSL import crypto
import os

def get_local_ip():
    """현재 시스템의 로컬 IP 주소를 반환합니다."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_public_ip():
    """가장 정확한 결과를 내는 PowerShell 명령어를 사용하여 실시간 공인 IP를 조회합니다."""
    import subprocess
    try:
        # PowerShell은 시스템 네트워크 스택을 정직하게 사용하여 정확한 .199를 가져옵니다.
        cmd = ['powershell', '-Command', "Invoke-RestMethod -Uri 'https://api.ipify.org'"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True)
        
        ip = result.stdout.strip()
        # IP 형식 검증
        if ip and ip.count('.') == 3:
            return ip
    except Exception:
        pass
    return "확인 불가"

def generate_ssl_cert(cert_path, key_path):
    """자가 서명 SSL 인증서와 개인키를 생성합니다."""
    try:
        # 디렉토리가 없으면 생성
        cert_dir = os.path.dirname(cert_path)
        if cert_dir and not os.path.exists(cert_dir):
            os.makedirs(cert_dir)

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        cert = crypto.X509()
        cert.get_subject().CN = "simftp-Server"
        cert.set_serial_number(1000)
        
        # 유효 기간 설정 (현재부터 10년)
        cert.set_notBefore(b"20000101000000Z")
        cert.set_notAfter(b"20991231235959Z")
        
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        with open(cert_path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_path, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        return True
    except Exception as e:
        print(f"[Crypto Error] {e}")
        return False

from cryptography.fernet import Fernet
import base64

def get_master_key():
    """시스템에서 사용할 고유 암호화 키를 가져오거나 생성합니다."""
    key_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'config', 'master.key')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        with open(key_path, 'wb') as f:
            f.write(key)
        return key

def encrypt_password(password):
    """비밀번호를 양방향 암호화합니다."""
    if not password: return ""
    f = Fernet(get_master_key())
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    """암호화된 비밀번호를 복호화합니다."""
    if not encrypted_password: return ""
    try:
        f = Fernet(get_master_key())
        return f.decrypt(encrypted_password.encode()).decode()
    except Exception:
        # 이전에 저장된 평문이나 해시일 경우 그대로 반환 (하위 호환)
        return encrypted_password

def hash_password(password, salt=None):
    """(더 이상 사용되지 않으나 하위 호환을 위해 유지)"""
    return password

def verify_password(stored_password, provided_password):
    """암호화된 비번과 입력된 비번을 비교합니다."""
    return decrypt_password(stored_password) == provided_password
