from pathlib import Path
from typing import List, Optional

from .system import Shell

UNIT_DIR = Path("/etc/systemd/system")
INSTALL_DIR = Path("/opt/wsproxy")

class ServiceManager:
    def __init__(self, shell: Shell = Shell):
        self.shell = shell

    def _unit_name(self, port: int) -> str:
        return f"wsproxy-{port}.service"

    def write_unit(self, port: int, dropbear_port: int, listen_host: str = "0.0.0.0"):
        args = [
            f"--host {listen_host}",
            f"--port {port}",
            f"--default-backend-port {dropbear_port}",
        ]
        unit = f"""[Unit]
Description=wsproxy tunnel (port {port})
After=network.target dropbear.service

[Service]
Type=simple
WorkingDirectory={INSTALL_DIR}
ExecStart=/usr/bin/python3 -m wsproxy.serve {' '.join(args)}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
        path = UNIT_DIR / self._unit_name(port)
        path.write_text(unit)
        return path

    def enable_and_start(self, port: int):
        name = self._unit_name(port)
        self.shell.run(["systemctl", "daemon-reload"])
        self.shell.run(["systemctl", "enable", name])
        self.shell.run(["systemctl", "restart", name])

    def restart_all(self, ports: List[int]):
        self.shell.run(["systemctl", "daemon-reload"])
        for p in ports:
            self.shell.run(["systemctl", "restart", self._unit_name(p)], check=False)

    def status(self, port: int) -> str:
        result = self.shell.run(
            ["systemctl", "is-active", self._unit_name(port)], check=False, capture=True
        )
        return (result.stdout or "").strip()

    def remove(self, port: int):
        name = self._unit_name(port)
        self.shell.run(["systemctl", "disable", "--now", name], check=False)
        unit_path = UNIT_DIR / name
        if unit_path.exists():
            unit_path.unlink()
        self.shell.run(["systemctl", "daemon-reload"])
