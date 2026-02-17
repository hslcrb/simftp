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
    """외부 인터넷 접속용 공인 IP 주소를 반환합니다."""
    try:
        # 여러 서비스를 통해 공인 IP 확인 시도
        services = ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://checkip.amazonaws.com']
        for service in services:
            try:
                with urllib.request.urlopen(service, timeout=3) as response:
                    return response.read().decode('utf-8').strip()
            except:
                continue
        return "확인 불가"
    except Exception:
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

import hashlib
import secrets

def hash_password(password, salt=None):
    """비밀번호를 솔트와 함께 해싱합니다."""
    if not salt:
        salt = secrets.token_hex(8)
    h = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${h}"

def verify_password(stored_password, provided_password):
    """제공된 비밀번호가 저장된 해시와 일치하는지 확인합니다."""
    try:
        if '$' not in stored_password:  # 하위 호환성 (평문 처리)
            return stored_password == provided_password
        salt, _ = stored_password.split('$', 1)
        return hash_password(provided_password, salt) == stored_password
    except Exception:
        return False
