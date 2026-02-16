import json
import os

def initialize_environment(config_dir='config'):
    """시스템 실행에 필요한 디렉토리 및 JSON 템플릿을 자동 생성합니다."""
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)

    templates = {
        'server_config.json': {
            "port": 2121,
            "root_dir": os.path.abspath(os.path.join(os.path.expanduser("~"), "ftp_root")),
            "allow_anonymous": False,
            "use_ftps": False,
            "cert_path": "config/server.crt",
            "key_path": "config/server.key",
            "max_cons": 256,
            "max_cons_per_ip": 5
        },
        'users.json': [
            {
                "username": "user",
                "password": "12345",
                "home_dir": os.path.abspath(os.path.join(os.path.expanduser("~"), "ftp_root")),
                "perms": "elradfmw"
            }
        ],
        'client_config.json': {
            "last_host": "127.0.0.1",
            "last_port": 2121,
            "last_user": "user",
            "use_ftps": False
        }
    }

    for filename, data in templates.items():
        path = os.path.join(config_dir, filename)
        if not os.path.exists(path):
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"[System] 생성됨: {path}")

if __name__ == "__main__":
    initialize_environment()
