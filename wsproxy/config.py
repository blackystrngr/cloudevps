"""
config.py - persisted configuration for wsproxy, read/written as
/etc/wsproxy/config.json. Single source of truth so every other
module takes a Config instead of touching disk itself.
"""
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List

CONFIG_DIR = Path("/etc/wsproxy")
CONFIG_FILE = CONFIG_DIR / "config.json"


@dataclass
class Config:
    domain: str = ""
    email: str = ""                       # optional, only for LE expiry notices
    http_ports: List[int] = None          # plain WS ports
    tls_ports: List[int] = None           # TLS WS ports
    dropbear_port: int = 109              # backend all proxies default to
    cert_path: str = ""
    key_path: str = ""
    initialized: bool = False

    # --- certificate method -----------------------------------------
    # one of: "le_http01" (Let's Encrypt, standalone HTTP-01),
    #         "le_cf_dns" (Let's Encrypt, DNS-01 via Cloudflare API),
    #         "cf_origin" (Cloudflare Origin CA cert, issued directly
    #                      by Cloudflare - no ACME/Let's Encrypt at all)
    cert_method: str = "le_http01"
    cf_api_token: str = ""                # Zone:DNS:Edit token, for le_cf_dns
    cf_origin_ca_key: str = ""            # Origin CA Key, for cf_origin

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
