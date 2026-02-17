import json
import os

class ConfigManager:
    """모든 JSON 설정 및 인증서 경로를 절대 경로로 관리합니다."""
    def __init__(self, config_dir_name='config'):
        # 프로젝트 루트 디렉토리 (src의 상위)
        # os.getcwd() 대신 실행 파일 위치 기준으로 고정하여 안정성 확보
        self.root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.config_dir = os.path.join(self.root_dir, config_dir_name)
        
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir, exist_ok=True)

        self.paths = {
            'server': os.path.join(self.config_dir, 'server_config.json'),
            'users': os.path.join(self.config_dir, 'users.json'),
            'client': os.path.join(self.config_dir, 'client_config.json'),
            'cert': os.path.join(self.config_dir, 'server.crt'),
            'key': os.path.join(self.config_dir, 'server.key')
        }

    def _load(self, key):
        try:
            with open(self.paths[key], 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return [] if key == 'users' else {}

    def _save(self, key, data):
        with open(self.paths[key], 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def get_server_config(self):
        config = self._load('server')
        # 기본값 설정
        if not config:
            config = {
                "port": 14729,
                "root_dir": "simftp_share", # 초기값부터 상대 경로 저장
                "use_nat": True,
                "allow_anonymous": False,
                "use_ftps": False
            }
            self.save_server_config(config)
        
        # [상대 경로 정규화] 가져온 경로가 상대 경로라면 절대 경로로 확장
        if not os.path.isabs(config.get('root_dir', '')):
            config['root_dir'] = os.path.normpath(os.path.join(self.root_dir, config.get('root_dir', 'simftp_share')))
            
        return config

    def save_server_config(self, config): self._save('server', config)
    
    def get_users(self): return self._load('users')
    def save_users(self, users): self._save('users', users)
    
    def get_client_config(self):
        config = self._load('client')
        if not config:
            config = {
                "last_host": "127.0.0.1",
                "last_port": 14729,
                "last_user": "anonymous",
                "use_ftps": False
            }
            self.save_client_config(config)
        return config

    def save_client_config(self, config): self._save('client', config)
    
    # 인증서 경로 가져오기
    def get_cert_paths(self):
        return self.paths['cert'], self.paths['key']
