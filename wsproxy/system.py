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
    def __init__(self, shell: Shell = Shell):
        self.shell = shell

    def install_all(self):
        print("[*] Updating package index...")
        self.shell.run(["apt-get", "update", "-y"])
        # Purge any old nginx packages to ensure stream module is present
        self.shell.run(["apt-get", "purge", "-y", "nginx", "nginx-common", "nginx-core"], check=False)
        self.shell.run(["apt-get", "autoremove", "-y"], check=False)
        self.shell.run(["apt-get", "install", "-y", "python3", "dropbear", "nginx-extras", "curl", "ufw", "openssl"])
        # Verify stream module
        result = self.shell.run(["nginx", "-V"], check=False, capture=True)
        if "with-stream" not in (result.stderr or ""):
            raise RuntimeError("Nginx installed without stream module. Please install nginx-extras manually.")


class Firewall:
    def __init__(self, shell: Shell = Shell):
        self.shell = shell

    def open_ports(self, ports: List[int]):
        if not shutil.which("ufw"):
            print("[!] ufw not found, skipping firewall.")
            return
        self.shell.run(["ufw", "allow", "OpenSSH"], check=False)
        for p in ports:
            print(f"[*] Opening port {p}/tcp")
            self.shell.run(["ufw", "allow", f"{p}/tcp"], check=False)
        self.shell.run(["ufw", "--force", "enable"], check=False)
        self.shell.run(["ufw", "reload"], check=False)


class Dropbear:
    CONFIG_FILE = "/etc/default/dropbear"

    def __init__(self, port: int = 109, shell: Shell = Shell):
        self.port = port
        self.shell = shell

    def configure(self):
        print(f"[*] Configuring dropbear on 127.0.0.1:{self.port} ...")
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
        shells_file = Path("/etc/shells")
        existing = shells_file.read_text().splitlines() if shells_file.exists() else []
        if shell_path not in existing:
            with open(shells_file, "a") as f:
                f.write(shell_path + "\n")


class OpenSSHBackend:
    def __init__(self, port: int = 22, shell: Shell = Shell):
        self.port = port
        self.shell = shell

    def verify(self):
        result = self.shell.run(["systemctl", "is-active", "ssh"], check=False, capture=True)
        if (result.stdout or "").strip() != "active":
            result = self.shell.run(["systemctl", "is-active", "sshd"], check=False, capture=True)
        if (result.stdout or "").strip() != "active":
            raise RuntimeError("OpenSSH server not active. Install openssh-server or use dropbear.")
        print(f"[*] Using OpenSSH on 127.0.0.1:{self.port} as backend.")


class Nginx:
    NGINX_CONF = "/etc/nginx/nginx.conf"
    STREAM_CONF = "/etc/nginx/stream.conf"

    def __init__(self, shell: Shell = Shell):
        self.shell = shell

    def configure(self, domain: str, tls_ports: List[int], cert_path: str, key_path: str):
        """Write a minimal nginx.conf (events + include stream.conf) and stream.conf."""
        if not tls_ports:
            # No TLS ports – stop nginx and remove our config (optional)
            self.shell.run(["systemctl", "stop", "nginx"], check=False)
            # Remove our stream.conf to avoid confusion
            if Path(self.STREAM_CONF).exists():
                Path(self.STREAM_CONF).unlink()
            return

        # Verify certificate files exist before writing config
        if not cert_path or not key_path or not Path(cert_path).exists() or not Path(key_path).exists():
            raise RuntimeError(f"Certificate files missing: {cert_path} or {key_path}")

        # Build stream blocks
        stream_blocks = ""
        for port in tls_ports:
            stream_blocks += f"""
server {{
    listen {port} ssl;
    proxy_pass 127.0.0.1:{port};
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
}}
"""
        # Write stream.conf
        Path(self.STREAM_CONF).write_text(f"stream {{\n{stream_blocks}\n}}")

        # Write minimal nginx.conf
        minimal_conf = """
events {
    worker_connections 1024;
}
include /etc/nginx/stream.conf;
"""
        Path(self.NGINX_CONF).write_text(minimal_conf)

        # Test the configuration
        result = self.shell.run(["nginx", "-t"], check=False, capture=True)
        if result.returncode != 0:
            raise RuntimeError(f"Nginx config test failed:\n{result.stdout}\n{result.stderr}")

        # Start nginx
        self.shell.run(["systemctl", "enable", "nginx"], check=False)
        self.shell.run(["systemctl", "restart", "nginx"], check=False)

    def reload(self):
        """Reload nginx after certificate renewal."""
        # Ensure stream.conf is up-to-date (it should already be updated by renewcert)
        self.shell.run(["nginx", "-t"], check=False, capture=True)  # test first
        self.shell.run(["systemctl", "reload", "nginx"], check=False)
