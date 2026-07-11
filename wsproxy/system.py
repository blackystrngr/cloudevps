"""
system.py - thin OOP wrappers around shell/package/firewall/dropbear
operations, so nothing else in the codebase shells out directly.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path
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
        # IMPORTANT: Debian's dropbear init script builds its listen
        # args as "-p $DROPBEAR_PORT $DROPBEAR_EXTRA_ARGS". If we set
        # DROPBEAR_PORT to a bare port number (e.g. "109") *and* also
        # add "-p 127.0.0.1:109" via DROPBEAR_EXTRA_ARGS, dropbear ends
        # up with two separate -p flags and binds BOTH 0.0.0.0:109
        # (from DROPBEAR_PORT) and 127.0.0.1:109 (from EXTRA_ARGS) -
        # exposing raw, un-proxied SSH directly to the internet on the
        # "internal" port. Putting the loopback address straight into
        # DROPBEAR_PORT itself (dropbear accepts "host:port" there
        # too) and leaving EXTRA_ARGS empty avoids the double bind.
        content = (
            "NO_START=0\n"
            f'DROPBEAR_PORT="127.0.0.1:{self.port}"\n'
            'DROPBEAR_EXTRA_ARGS=""\n'
            'DROPBEAR_BANNER=""\n'
            'DROPBEAR_RECEIVE_WINDOW=65536\n'
        )
        with open(self.CONFIG_FILE, "w") as f:
            f.write(content)
        self._ensure_shell_allowed("/bin/false")
        self._ensure_shell_allowed("/usr/sbin/nologin")
        self.shell.run(["systemctl", "enable", "dropbear"], check=False)
        self.shell.run(["systemctl", "restart", "dropbear"])

    @staticmethod
    def _ensure_shell_allowed(shell_path: str):
        """Tunnel accounts are created with a no-login shell (see
        users.py) so they can't get an interactive shell, only port
        forwarding. But on Debian, dropbear is built with PAM support,
        and the default PAM stack for it includes pam_shells, which
        rejects any account whose shell isn't listed in /etc/shells -
        even though the account's password is 100% correct. That shows
        up to the client as a generic auth failure ("no supported
        methods remain" / "wrong username or password"), which is
        misleading since the credentials were actually fine. Fix: make
        sure the no-login shell we assign is itself an allowed shell."""
        shells_file = Path("/etc/shells")
        existing = shells_file.read_text().splitlines() if shells_file.exists() else []
        if shell_path not in existing:
            with open(shells_file, "a") as f:
                f.write(shell_path + "\n")
