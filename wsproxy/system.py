"""
system.py - thin OOP wrappers around shell/package/firewall/dropbear
operations, so nothing else in the codebase shells out directly.
"""
import os
import shutil
import subprocess
import sys
from typing import List


class Shell:
    @staticmethod
    def run(cmd: List[str], check: bool = True, capture: bool = False, input_text: str = None):
        result = subprocess.run(cmd, check=False, text=True, capture_output=capture, input=input_text)
        if check and result.returncode != 0:
            out = (result.stdout or "") + (result.stderr or "")
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{out}")
        return result

    @staticmethod
    def require_root():
        if os.geteuid() != 0:
            sys.exit("This action requires root. Re-run with: sudo ...")


class PackageManager:
    PACKAGES = ["python3", "dropbear", "curl", "socat", "cron", "ufw", "openssl"]

    def __init__(self, shell: Shell = Shell):
        self.shell = shell

    def install_all(self):
        print("[*] Updating package index...")
        self.shell.run(["apt-get", "update", "-y"])
        print(f"[*] Installing: {', '.join(self.PACKAGES)}")
        self.shell.run(["apt-get", "install", "-y", *self.PACKAGES])


class Firewall:
    def __init__(self, shell: Shell = Shell):
        self.shell = shell

    def open_ports(self, ports: List[int]):
        if not shutil.which("ufw"):
            print("[!] ufw not found, skipping firewall configuration.")
            return
        self.shell.run(["ufw", "allow", "OpenSSH"], check=False)
        for p in ports:
            print(f"[*] Opening port {p}/tcp")
            self.shell.run(["ufw", "allow", f"{p}/tcp"], check=False)
        self.shell.run(["ufw", "--force", "enable"], check=False)
        self.shell.run(["ufw", "reload"], check=False)


class Dropbear:
    """Configures the dropbear SSH daemon that wsproxy tunnels into by
    default. Kept on its own internal port (not 22) so admin SSH
    access on 22 stays independent of the tunnel service."""

    CONFIG_FILE = "/etc/default/dropbear"

    def __init__(self, port: int = 109, shell: Shell = Shell):
        self.port = port
        self.shell = shell

    def configure(self):
        print(f"[*] Configuring dropbear to listen on 127.0.0.1:{self.port} ...")
        content = (
            "NO_START=0\n"
            f'DROPBEAR_PORT="{self.port}"\n'
            f'DROPBEAR_EXTRA_ARGS="-p 127.0.0.1:{self.port}"\n'
            'DROPBEAR_BANNER=""\n'
            'DROPBEAR_RECEIVE_WINDOW=65536\n'
        )
        with open(self.CONFIG_FILE, "w") as f:
            f.write(content)
        self.shell.run(["systemctl", "enable", "dropbear"], check=False)
        self.shell.run(["systemctl", "restart", "dropbear"])
