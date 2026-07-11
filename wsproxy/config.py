import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List

CONFIG_DIR = Path("/etc/wsproxy")
CONFIG_FILE = CONFIG_DIR / "config.json"
CERT_DIR = Path("/etc/wsproxy/certs")

@dataclass
class Config:
    domain: str = ""
    email: str = ""
    http_ports: List[int] = None
    tls_ports: List[int] = None
    dropbear_port: int = 109
    backend_type: str = "dropbear"
    cert_path: str = ""
    key_path: str = ""
    initialized: bool = False
    cert_method: str = "le_http01"
    cf_api_token: str = ""
    cf_email: str = ""
    cf_global_api_key: str = ""

    def __post_init__(self):
        if self.http_ports is None:
            self.http_ports = []
        if self.tls_ports is None:
            self.tls_ports = []

    @classmethod
    def load(cls) -> "Config":
        if CONFIG_FILE.exists():
            data = json.loads(CONFIG_FILE.read_text())
            return cls(**data)
        return cls()

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(asdict(self), indent=2))
        os.chmod(CONFIG_FILE, 0o600)

    def require_initialized(self) -> None:
        if not self.initialized:
            raise SystemExit("wsproxy has not been set up yet. Run: sudo wsproxy init")
