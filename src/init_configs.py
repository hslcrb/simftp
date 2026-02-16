import json
import os

def init_all_configs(config_dir='config'):
    """필요한 모든 JSON 설정 파일의 기본 템플릿을 생성합니다."""
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
        print(f"디렉토리 생성: {config_dir}")

    # 1. 서버 기본 설정 템플릿
    server_config_path = os.path.join(config_dir, 'server_config.json')
    if not os.path.exists(server_config_path):
        default_server_config = {
            "port": 2121,
            "root_dir": os.path.abspath(os.path.join(os.path.expanduser("~"), "ftp_root")),
            "allow_anonymous": False,
            "use_ftps": False,
            "cert_path": "config/server.crt",
            "key_path": "config/server.key",
            "max_cons": 256,
            "max_cons_per_ip": 5
        }
        with open(server_config_path, 'w', encoding='utf-8') as f:
            json.dump(default_server_config, f, indent=4, ensure_ascii=False)
        print(f"생성됨: {server_config_path}")

    # 2. 사용자 목록 템플릿
    users_path = os.path.join(config_dir, 'users.json')
    if not os.path.exists(users_path):
        default_users = [
            {
                "username": "user",
                "password": "12345",
                "home_dir": os.path.abspath(os.path.join(os.path.expanduser("~"), "ftp_root")),
                "perms": "elradfmw"
            }
        ]
        with open(users_path, 'w', encoding='utf-8') as f:
            json.dump(default_users, f, indent=4, ensure_ascii=False)
        print(f"생성됨: {users_path}")

    # 3. 클라이언트 최근 접속 정보 템플릿
    client_config_path = os.path.join(config_dir, 'client_config.json')
    if not os.path.exists(client_config_path):
        default_client_config = {
            "last_host": "127.0.0.1",
            "last_port": 2121,
            "last_user": "user",
            "use_ftps": False
        }
        with open(client_config_path, 'w', encoding='utf-8') as f:
            json.dump(default_client_config, f, indent=4, ensure_ascii=False)
        print(f"생성됨: {client_config_path}")

if __name__ == "__main__":
    init_all_configs()
