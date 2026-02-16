import json
import os

class ConfigManager:
    """JSON 설정 파일의 로드 및 저장을 관리합니다."""
    def __init__(self, config_dir='config'):
        self.config_dir = config_dir
        self.server_config_path = os.path.join(config_dir, 'server_config.json')
        self.users_path = os.path.join(config_dir, 'users.json')
        self.client_config_path = os.path.join(config_dir, 'client_config.json')

    def load_server_config(self):
        try:
            with open(self.server_config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}

    def save_server_config(self, config):
        with open(self.server_config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)

    def load_users(self):
        try:
            with open(self.users_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []

    def save_users(self, users):
        with open(self.users_path, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=4, ensure_ascii=False)

    def load_client_config(self):
        try:
            with open(self.client_config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}

    def save_client_config(self, config):
        with open(self.client_config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
