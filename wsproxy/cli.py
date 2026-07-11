import argparse
import subprocess
import sys

from .config import Config, CERT_DIR
from .system import Shell, PackageManager, Firewall, Dropbear, OpenSSHBackend, Nginx
from .services import ServiceManager
from .users import SSHUserManager
from .acme import LetsEncryptCertManager, LetsEncryptCloudflareDNSCertManager
from .cloudflare import CloudflareOriginCertManager

CERT_METHODS = {
    "1": ("le_http01", "Let's Encrypt - HTTP-01 standalone (needs port 80 briefly reachable)"),
    "2": ("le_cf_dns", "Let's Encrypt - DNS-01 via Cloudflare API (needs API Token)"),
    "3": ("cf_origin", "Cloudflare Origin CA (needs email + Global API Key)"),
}

def ask(prompt: str, default: str = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")

def ask_ports(prompt: str, default: str) -> list:
    raw = ask(prompt, default)
    try:
        return sorted({int(p.strip()) for p in raw.split(",") if p.strip()})
    except ValueError:
        print("Please enter comma-separated port numbers, e.g. 80,8880")
        return ask_ports(prompt, default)

MIN_DAYS_LEFT = 15

def find_existing_valid_cert(domain: str, min_days_left: int = MIN_DAYS_LEFT):
    fullchain = CERT_DIR / f"{domain}.fullchain.cer"
    key_path = CERT_DIR / f"{domain}.key"
    if not (fullchain.exists() and key_path.exists() and fullchain.stat().st_size > 0):
        return None
    proc = subprocess.run(
        ["openssl", "x509", "-checkend", str(min_days_left * 86400),
         "-noout", "-in", str(fullchain)],
        capture_output=True,
    )
    if proc.returncode != 0:
        return None
    return str(fullchain), str(key_path)

def choose_cert_method(cfg: Config):
    print("\nHow should wsproxy get your TLS certificate?")
    for key, (_, label) in CERT_METHODS.items():
        print(f"  {key}) {label}")
    default_key = next(k for k, (m, _) in CERT_METHODS.items() if m == cfg.cert_method)
    choice = ask("Choice", default_key)
    while choice not in CERT_METHODS:
        choice = ask("Please enter 1, 2, or 3", default_key)
    cfg.cert_method = CERT_METHODS[choice][0]

    if cfg.cert_method == "le_cf_dns":
        print("\nNeeds Cloudflare API Token (Zone:DNS:Edit).")
        cfg.cf_api_token = ask("Cloudflare API Token", cfg.cf_api_token or None)
    elif cfg.cert_method == "cf_origin":
        print("\nNeeds Cloudflare account email + Global API Key.")
        cfg.cf_email = ask("Cloudflare account email", cfg.cf_email or None)
        cfg.cf_global_api_key = ask("Cloudflare Global API Key", cfg.cf_global_api_key or None)

def build_cert_manager(cfg: Config):
    if cfg.cert_method == "le_cf_dns":
        if not cfg.cf_api_token:
            sys.exit("cert_method is le_cf_dns but no Cloudflare API Token.")
        return LetsEncryptCloudflareDNSCertManager(cfg.domain, cfg.email, cfg.cf_api_token)
    if cfg.cert_method == "cf_origin":
        if not cfg.cf_email or not cfg.cf_global_api_key:
            sys.exit("cert_method is cf_origin but Cloudflare credentials missing.")
        return CloudflareOriginCertManager(cfg.domain, cfg.cf_email, cfg.cf_global_api_key)
    return LetsEncryptCertManager(cfg.domain, cfg.email)

def stop_port_80_service(services: ServiceManager):
    """Stop wsproxy-80 if it exists, so acme.sh can bind to port 80."""
    Shell.run(["systemctl", "stop", "wsproxy-80.service"], check=False)

def start_port_80_service(services: ServiceManager):
    Shell.run(["systemctl", "start", "wsproxy-80.service"], check=False)

def issue_cert(cert_mgr, services: ServiceManager, http_ports: list, domain: str, force: bool = False):
    existing = find_existing_valid_cert(domain) if not force else None
    if existing:
        print(f"[*] Reusing existing valid certificate for {domain}.")
        return existing

    needs_port80 = getattr(cert_mgr, "needs_port80", False)
    port80_ours = needs_port80 and 80 in http_ports and services.status(80) == "active"
    if port80_ours:
        stop_port_80_service(services)
    try:
        return cert_mgr.issue()
    finally:
        if port80_ours:
            start_port_80_service(services)

class App:
    def __init__(self):
        self.cfg = Config.load()

    def cmd_init(self, _args):
        Shell.require_root()
        print("=== wsproxy setup (Nginx + Python proxy) ===")

        self.cfg.domain = ask("Domain (e.g. tunnel.example.com)", self.cfg.domain)
        self.cfg.email = ask("Contact email (optional)", self.cfg.email)

        print("\nSSH backend:")
        print("  1) dropbear (isolated, loopback)")
        print("  2) openssh (existing sshd)")
        backend_choice = ask("Choice", "1" if self.cfg.backend_type != "openssh" else "2")
        self.cfg.backend_type = "openssh" if backend_choice == "2" else "dropbear"

        if self.cfg.backend_type == "dropbear":
            self.cfg.dropbear_port = int(ask("Internal port for dropbear", str(self.cfg.dropbear_port or 109)))
        else:
            self.cfg.dropbear_port = int(ask("Port of your sshd", str(self.cfg.dropbear_port if self.cfg.dropbear_port != 109 else 22)))

        self.cfg.http_ports = ask_ports("Plain HTTP ports (Python binds 0.0.0.0)", ",".join(map(str, self.cfg.http_ports)) or "80")
        self.cfg.tls_ports = ask_ports("TLS ports (Nginx terminates TLS, Python on 127.0.0.1)", ",".join(map(str, self.cfg.tls_ports)) or "443")

        overlap = set(self.cfg.http_ports) & set(self.cfg.tls_ports)
        if overlap:
            sys.exit(f"Overlap: {overlap}")

        # 1) Packages
        PackageManager().install_all()

        # 2) Backend
        if self.cfg.backend_type == "openssh":
            OpenSSHBackend(port=self.cfg.dropbear_port).verify()
        else:
            Dropbear(port=self.cfg.dropbear_port).configure()

        # 3) Firewall
        all_ports = self.cfg.http_ports + self.cfg.tls_ports
        Firewall().open_ports(all_ports)

        # 4) Certificate (if TLS ports exist)
        services = ServiceManager()
        if self.cfg.tls_ports:
            existing = find_existing_valid_cert(self.cfg.domain)
            if existing:
                self.cfg.cert_path, self.cfg.key_path = existing
            else:
                choose_cert_method(self.cfg)
                cert_mgr = build_cert_manager(self.cfg)
                fullchain, key_path = issue_cert(cert_mgr, services, self.cfg.http_ports, self.cfg.domain)
                self.cfg.cert_path, self.cfg.key_path = fullchain, key_path

        # 5) Nginx configuration
        Nginx().configure(self.cfg.domain, self.cfg.tls_ports, self.cfg.cert_path, self.cfg.key_path)

        # 6) Systemd services
        for port in self.cfg.http_ports:
            services.write_unit(port, self.cfg.dropbear_port, listen_host="0.0.0.0")
            services.enable_and_start(port)
        for port in self.cfg.tls_ports:
            services.write_unit(port, self.cfg.dropbear_port, listen_host="127.0.0.1")
            services.enable_and_start(port)

        self.cfg.initialized = True
        self.cfg.save()

        print("\n=== Done ===")
        print(f"Domain:        {self.cfg.domain}")
        print(f"HTTP ports:    {self.cfg.http_ports} (Python direct)")
        print(f"TLS ports:     {self.cfg.tls_ports} (Nginx -> Python on 127.0.0.1)")
        print(f"Backend port:  {self.cfg.dropbear_port} (127.0.0.1)")
        print("\nAdd users: sudo wsproxy adduser <name> --days 30")

    def cmd_addport(self, args):
        Shell.require_root()
        self.cfg.require_initialized()
        services = ServiceManager()
        port = args.port
        is_tls = getattr(args, "tls", False)

        if is_tls:
            # Ensure we have a certificate
            if not self.cfg.cert_path:
                existing = find_existing_valid_cert(self.cfg.domain)
                if existing:
                    self.cfg.cert_path, self.cfg.key_path = existing
                else:
                    choose_cert_method(self.cfg)
                    cert_mgr = build_cert_manager(self.cfg)
                    fullchain, key_path = issue_cert(cert_mgr, services, self.cfg.http_ports, self.cfg.domain)
                    self.cfg.cert_path, self.cfg.key_path = fullchain, key_path
            self.cfg.tls_ports = sorted(set(self.cfg.tls_ports) | {port})
            Nginx().configure(self.cfg.domain, self.cfg.tls_ports, self.cfg.cert_path, self.cfg.key_path)
            services.write_unit(port, self.cfg.dropbear_port, listen_host="127.0.0.1")
        else:
            self.cfg.http_ports = sorted(set(self.cfg.http_ports) | {port})
            services.write_unit(port, self.cfg.dropbear_port, listen_host="0.0.0.0")

        services.enable_and_start(port)
        Firewall().open_ports([port])
        self.cfg.save()
        print(f"[+] Port {port} ({'TLS' if is_tls else 'plain'}) added.")

    def cmd_removeport(self, args):
        Shell.require_root()
        port = args.port
        services = ServiceManager()
        services.remove(port)
        self.cfg.http_ports = [p for p in self.cfg.http_ports if p != port]
        self.cfg.tls_ports = [p for p in self.cfg.tls_ports if p != port]
        self.cfg.save()
        if self.cfg.tls_ports:
            Nginx().configure(self.cfg.domain, self.cfg.tls_ports, self.cfg.cert_path, self.cfg.key_path)
        else:
            Nginx().configure(self.cfg.domain, [], "", "")  # stops nginx
        print(f"[-] Port {port} removed.")

    def cmd_renewcert(self, args):
        Shell.require_root()
        self.cfg.require_initialized()
        services = ServiceManager()
        if not self.cfg.tls_ports:
            print("No TLS ports configured – nothing to renew.")
            return

        force = getattr(args, "force", False)
        if not force:
            existing = find_existing_valid_cert(self.cfg.domain)
            if existing:
                print("[*] Certificate still valid – no renewal needed.")
                return

        cert_mgr = build_cert_manager(self.cfg)
        fullchain, key_path = issue_cert(cert_mgr, services, self.cfg.http_ports, self.cfg.domain, force=force)
        self.cfg.cert_path, self.cfg.key_path = fullchain, key_path
        self.cfg.save()
        Nginx().configure(self.cfg.domain, self.cfg.tls_ports, self.cfg.cert_path, self.cfg.key_path)
        services.restart_all(self.cfg.tls_ports)
        print("[+] Certificate renewed and Nginx reloaded.")

    def cmd_adduser(self, args):
        Shell.require_root()
        self.cfg.require_initialized()
        SSHUserManager().add_user(args.username, days_valid=args.days, password=args.password)

    def cmd_deluser(self, args):
        Shell.require_root()
        SSHUserManager().delete_user(args.username)

    def cmd_extend(self, args):
        Shell.require_root()
        SSHUserManager().extend_user(args.username, args.days)

    def cmd_lock(self, args):
        Shell.require_root()
        SSHUserManager().lock_user(args.username)

    def cmd_unlock(self, args):
        Shell.require_root()
        SSHUserManager().unlock_user(args.username)

    def cmd_listusers(self, _args):
        users = SSHUserManager().list_users()
        if not users:
            print("No accounts yet.")
            return
        print(f"{'USERNAME':<20}{'EXPIRES':<15}")
        for u in users:
            print(f"{u.username:<20}{u.expiry_date:<15}")

    def cmd_status(self, _args):
        if not self.cfg.initialized:
            print("wsproxy not set up. Run: sudo wsproxy init")
            return
        services = ServiceManager()
        print(f"Domain:        {self.cfg.domain}")
        print(f"Backend port:  {self.cfg.dropbear_port} (127.0.0.1)")
        print("HTTP ports (Python direct):")
        for p in self.cfg.http_ports:
            print(f"  {p:<8} {services.status(p)}")
        print("TLS ports (Nginx -> Python on 127.0.0.1):")
        for p in self.cfg.tls_ports:
            print(f"  {p:<8} {services.status(p)}")
        if self.cfg.cert_path:
            print(f"Certificate:   {self.cfg.cert_path}")
        print(f"Accounts: {len(SSHUserManager().list_users())}")

    def cmd_menu(self, _args):
        actions = {
            "1": ("Add tunnel account", self._menu_adduser),
            "2": ("List accounts", lambda: self.cmd_listusers(None)),
            "3": ("Extend account", self._menu_extend),
            "4": ("Delete account", self._menu_deluser),
            "5": ("Lock/unlock", self._menu_lock_unlock),
            "6": ("Add port", self._menu_addport),
            "7": ("Remove port", self._menu_removeport),
            "8": ("Renew certificate", lambda: self.cmd_renewcert(None)),
            "9": ("Show status", lambda: self.cmd_status(None)),
            "10": ("Change certificate method", self._menu_change_cert_method),
            "0": ("Exit", None),
        }
        while True:
            print("\n=== wsproxy menu ===")
            for key, (label, _) in actions.items():
                print(f"  {key}) {label}")
            choice = input("Choose: ").strip()
            if choice == "0":
                return
            if choice not in actions:
                print("Invalid choice.")
                continue
            try:
                actions[choice][1]()
            except Exception as e:
                print(f"Error: {e}")

    def _menu_adduser(self):
        name = ask("Username")
        days = int(ask("Days valid", "30"))
        SSHUserManager().add_user(name, days_valid=days)

    def _menu_extend(self):
        SSHUserManager().extend_user(ask("Username"), int(ask("Extra days", "30")))

    def _menu_deluser(self):
        SSHUserManager().delete_user(ask("Username"))

    def _menu_lock_unlock(self):
        name = ask("Username")
        action = ask("lock or unlock", "lock")
        mgr = SSHUserManager()
        mgr.lock_user(name) if action == "lock" else mgr.unlock_user(name)

    def _menu_addport(self):
        port = int(ask("Port number"))
        tls = ask("TLS? (y/n)", "n").lower().startswith("y")
        self.cmd_addport(argparse.Namespace(port=port, tls=tls))

    def _menu_removeport(self):
        self.cmd_removeport(argparse.Namespace(port=int(ask("Port to remove"))))

    def _menu_change_cert_method(self):
        self.cfg.require_initialized()
        if not self.cfg.tls_ports:
            print("No TLS ports configured – nothing to change.")
            return
        choose_cert_method(self.cfg)
        services = ServiceManager()
        cert_mgr = build_cert_manager(self.cfg)
        fullchain, key_path = issue_cert(cert_mgr, services, self.cfg.http_ports, self.cfg.domain, force=True)
        self.cfg.cert_path, self.cfg.key_path = fullchain, key_path
        self.cfg.save()
        Nginx().configure(self.cfg.domain, self.cfg.tls_ports, self.cfg.cert_path, self.cfg.key_path)
        services.restart_all(self.cfg.tls_ports)
        print("[+] Certificate method updated.")

def build_parser():
    parser = argparse.ArgumentParser(prog="wsproxy")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Interactive first-time setup")
    sub.add_parser("menu", help="Interactive menu")
    sub.add_parser("status", help="Show status")
    sub.add_parser("listusers", help="List tunnel accounts")
    p = sub.add_parser("renewcert", help="Renew TLS certificate")
    p.add_argument("--force", action="store_true", help="Force renewal even if valid")

    p = sub.add_parser("adduser", help="Create tunnel account")
    p.add_argument("username")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--password", default=None)

    p = sub.add_parser("deluser", help="Delete tunnel account")
    p.add_argument("username")

    p = sub.add_parser("extend", help="Extend account expiry")
    p.add_argument("username")
    p.add_argument("days", type=int)

    p = sub.add_parser("lock", help="Lock account")
    p.add_argument("username")
    p = sub.add_parser("unlock", help="Unlock account")
    p.add_argument("username")

    p = sub.add_parser("addport", help="Add a port")
    p.add_argument("port", type=int)
    p.add_argument("--tls", action="store_true")

    p = sub.add_parser("removeport", help="Remove a port")
    p.add_argument("port", type=int)

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()
    app = App()

    dispatch = {
        "init": app.cmd_init, "menu": app.cmd_menu, "status": app.cmd_status,
        "listusers": app.cmd_listusers, "renewcert": app.cmd_renewcert,
        "adduser": app.cmd_adduser, "deluser": app.cmd_deluser,
        "extend": app.cmd_extend, "lock": app.cmd_lock, "unlock": app.cmd_unlock,
        "addport": app.cmd_addport, "removeport": app.cmd_removeport,
    }

    if not args.command:
        app.cmd_menu(args)
        return
    dispatch[args.command](args)

if __name__ == "__main__":
    main()
