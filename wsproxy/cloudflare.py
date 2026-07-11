"""
cloudflare.py - obtains a TLS certificate directly from Cloudflare's
Origin CA, with no ACME/Let's Encrypt involved at all.

How it works: we generate a private key + CSR locally with openssl,
then POST the CSR straight to Cloudflare's certificate-signing API
(`POST /certificates` on api.cloudflare.com). Cloudflare signs it with
its own Origin CA and hands back the certificate - that's the whole
protocol, no challenges, no ACME client.

Requirements / caveats (worth knowing before picking this method):
- The domain's DNS must be on Cloudflare, and for the cert to be
  trusted end-to-end, traffic normally needs to be proxied through
  Cloudflare's edge (the orange cloud) with SSL/TLS mode set to
  "Full (strict)" in the dashboard. Origin CA certs are trusted by
  Cloudflare's edge but NOT by ordinary browsers/clients connecting
  directly to the origin IP, unlike a Let's Encrypt cert.
- Auth is via an "Origin CA Key", a credential separate from normal
  Cloudflare API tokens. Get it from the Cloudflare dashboard
  (My Profile -> API Tokens -> Origin CA Key), or generate one with
  the Origin CA "create" permission. It's sent as the
  X-Auth-User-Service-Key header - regular Bearer API tokens will not
  work here even if scoped correctly.
- Certs can be issued valid for up to 15 years (5475 days).
"""
import json
import subprocess
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

CERT_DIR = Path("/etc/wsproxy/certs")
CF_API_URL = "https://api.cloudflare.com/client/v4/certificates"


class CloudflareOriginCertManager:
    needs_port80 = False

    def __init__(self, domain: str, origin_ca_key: str, valid_days: int = 5475):
        self.domain = domain
        self.origin_ca_key = origin_ca_key
        self.valid_days = valid_days

    def _generate_key_and_csr(self, key_path: Path, csr_path: Path):
        subprocess.run(
            ["openssl", "genrsa", "-out", str(key_path), "2048"],
            check=True, capture_output=True,
        )
        key_path.chmod(0o600)

        # Include both the bare domain and a wildcard for its
        # subdomains, matching what Cloudflare's own dashboard flow
        # generates by default.
        subj = f"/CN={self.domain}"
        subprocess.run(
            ["openssl", "req", "-new", "-key", str(key_path),
             "-out", str(csr_path), "-subj", subj],
            check=True, capture_output=True,
        )

    def issue(self):
        """Returns (fullchain_path, key_path)."""
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        key_path = CERT_DIR / f"{self.domain}.key"
        csr_path = CERT_DIR / f"{self.domain}.csr"
        fullchain = CERT_DIR / f"{self.domain}.fullchain.cer"

        print(f"[*] Generating private key + CSR for {self.domain} ...")
        self._generate_key_and_csr(key_path, csr_path)
        csr_pem = csr_path.read_text()

        hostnames = [self.domain]
        # add the wildcard so subdomains are covered too, same as the
        # Cloudflare dashboard's "Create Certificate" flow
        base = self.domain.split(".", 1)[-1] if self.domain.count(".") >= 1 else self.domain
        wildcard = f"*.{self.domain}" if not self.domain.startswith("*.") else self.domain
        if wildcard not in hostnames:
            hostnames.append(wildcard)

        payload = json.dumps({
            "hostnames": hostnames,
            "requested_validity": self.valid_days,
            "request_type": "origin-rsa",
            "csr": csr_pem,
        }).encode()

        print(f"[*] Requesting Origin CA certificate for {hostnames} from Cloudflare ...")
        req = urlrequest.Request(
            CF_API_URL,
            data=payload,
            method="POST",
            headers={
                "X-Auth-User-Service-Key": self.origin_ca_key,
                "Content-Type": "application/json",
            },
        )
        try:
            with urlrequest.urlopen(req) as resp:
                body = json.loads(resp.read())
        except HTTPError as e:
            err_body = e.read().decode(errors="replace")
            raise RuntimeError(f"Cloudflare Origin CA request failed ({e.code}):\n{err_body}")

        if not body.get("success"):
            raise RuntimeError(f"Cloudflare Origin CA request failed:\n{json.dumps(body, indent=2)}")

        cert_pem = body["result"]["certificate"]
        fullchain.write_text(cert_pem)
        csr_path.unlink(missing_ok=True)

        print("[+] Cloudflare Origin CA certificate issued.")
        print("    Reminder: set SSL/TLS mode to 'Full (strict)' in the Cloudflare")
        print("    dashboard for this zone, and keep the domain proxied (orange cloud)")
        print("    - this cert is only trusted by Cloudflare's edge, not by browsers")
        print("    connecting straight to the origin IP.")
        return str(fullchain), str(key_path)
