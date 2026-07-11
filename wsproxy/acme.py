"""
acme.py - obtains/renews a TLS certificate using plain Let's Encrypt
via acme.sh's --standalone mode (HTTP-01 challenge). No DNS provider
API keys needed at all - acme.sh briefly runs its own tiny HTTP server
directly on port 80 to answer Let's Encrypt's validation request, then
exits. The only requirement is that port 80 is free for a few seconds
during issuance/renewal, which ServiceManager-aware callers handle by
briefly stopping whatever wsproxy service is bound to port 80 (if any)
around the call to issue().
"""
import os
import stat
import subprocess
from pathlib import Path

ACME_HOME = Path("/root/.acme.sh")
ACME_BIN = ACME_HOME / "acme.sh"
CERT_DIR = Path("/etc/wsproxy/certs")


class LetsEncryptCertManager:
    def __init__(self, domain: str, email: str = ""):
        self.domain = domain
        self.email = email  # optional, only used for Let's Encrypt expiry notices

    def ensure_acme_installed(self):
        if ACME_BIN.exists():
            return
        print("[*] Installing acme.sh ...")
        install_cmd = "curl -s https://get.acme.sh | sh"
        if self.email:
            install_cmd += f" -s email={self.email}"
        subprocess.run(["bash", "-c", install_cmd], check=True)

    def issue(self):
        """Requests + installs the cert via HTTP-01 standalone challenge.
        Port 80 must be free when this runs. Returns (fullchain_path, key_path)."""
        self.ensure_acme_installed()
        CERT_DIR.mkdir(parents=True, exist_ok=True)

        print(f"[*] Requesting certificate for {self.domain} via Let's Encrypt (HTTP-01, standalone) ...")
        proc = subprocess.run(
            [str(ACME_BIN), "--issue", "--standalone", "-d", self.domain,
             "--httpport", "80", "--server", "letsencrypt"],
            text=True, capture_output=True,
        )
        already_valid = "Domains not changed" in (proc.stdout or "") or "Skipping" in (proc.stdout or "")
        if proc.returncode != 0 and not already_valid:
            raise RuntimeError(f"acme.sh issue failed:\n{proc.stdout}\n{proc.stderr}")

        fullchain = CERT_DIR / f"{self.domain}.fullchain.cer"
        key_path = CERT_DIR / f"{self.domain}.key"

        print("[*] Installing certificate ...")
        proc2 = subprocess.run(
            [str(ACME_BIN), "--install-cert", "-d", self.domain,
             "--cert-file", str(CERT_DIR / f"{self.domain}.cer"),
             "--key-file", str(key_path),
             "--fullchain-file", str(fullchain)],
            text=True, capture_output=True,
        )
        if proc2.returncode != 0:
            raise RuntimeError(f"acme.sh install-cert failed:\n{proc2.stdout}\n{proc2.stderr}")

        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
        return str(fullchain), str(key_path)
