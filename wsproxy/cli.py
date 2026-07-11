"""
cli.py - the `wsproxy` command. Thin orchestration only: every real
piece of logic lives in its own class (Config, PackageManager,
Firewall, Dropbear, LetsEncryptCertManager, ServiceManager,
SSHUserManager). This file wires them together and talks to the human.
"""
import argparse
import sys

from .config import Config
from .system import Shell, PackageManager, Firewall, Dropbear
from .acme import LetsEncryptCertManager, LetsEncryptCloudflareDNSCertManager
from .cloudflare import CloudflareOriginCertManager
from .services import ServiceManager
from .users import SSHUserManager

CERT_METHODS = {
    "1": ("le_http01", "Let's Encrypt - HTTP-01 standalone (needs port 80 briefly reachable, no credentials)"),
    "2": ("le_cf_dns", "Let's Encrypt - DNS-01 via Cloudflare API (no port 80 needed, needs a Cloudflare API Token)"),
    "3": ("cf_origin", "Cloudflare Origin CA certificate (issued directly by Cloudflare, no ACME - needs your Cloudflare account email + Global API Key, domain must be proxied through Cloudflare)"),
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


def choose_cert_method(cfg: Config) -> None:
    """Ask which of the 3 certificate methods to use, and collect
    whatever credentials that method needs. Mutates cfg in place."""
    print("\nHow should wsproxy get your TLS certificate? Pick one:")
    for key, (_, label) in CERT_METHODS.items():
        print(f"  {key}) {label}")
    default_key = next(k for k, (m, _) in CERT_METHODS.items() if m == cfg.cert_method)
    choice = ask("Choice", default_key)
    while choice not in CERT_METHODS:
        choice = ask("Please enter 1, 2, or 3", default_key)
    cfg.cert_method = CERT_METHODS[choice][0]

    if cfg.cert_method == "le_cf_dns":
        print("\nNeeds a Cloudflare API Token (not the legacy Global API Key) scoped")
        print("with at least Zone:DNS:Edit on the zone for this domain.")
        print("Create one at: https://dash.cloudflare.com/profile/api-tokens\n")
        cfg.cf_api_token = ask("Cloudflare API Token", cfg.cf_api_token or None)

    elif cfg.cert_method == "cf_origin":
        print("\nNeeds your Cloudflare account email + Global API Key (the older")
        print("account-wide key, not a scoped API Token). Find it at: My Profile ->")
        print("API Tokens -> Global API Key -> View (dash.cloudflare.com/profile/api-tokens).")
        print("Your domain's DNS must be on Cloudflare and proxied (orange cloud) for")
        print("this cert to be trusted end to end.\n")
        cfg.cf_email = ask("Cloudflare account email", cfg.cf_email or None)
        cfg.cf_global_api_key = ask("Cloudflare Global API Key", cfg.cf_global_api_key or None)


def build_cert_manager(cfg: Config):
    """Factory: returns the right cert manager instance for cfg.cert_method."""
    if cfg.cert_method == "le_cf_dns":
        if not cfg.cf_api_token:
            sys.exit("cert_method is le_cf_dns but no Cloudflare API Token is configured. Run 'wsproxy init' again.")
        return LetsEncryptCloudflareDNSCertManager(cfg.domain, cfg.email, cfg.cf_api_token)
    if cfg.cert_method == "cf_origin":
        if not cfg.cf_email or not cfg.cf_global_api_key:
            sys.exit("cert_method is cf_origin but Cloudflare email/Global API Key aren't configured. Run 'wsproxy init' again.")
        return CloudflareOriginCertManager(cfg.domain, cfg.cf_email, cfg.cf_global_api_key)
    return LetsEncryptCertManager(cfg.domain, cfg.email)


def issue_cert(cert_mgr, services: ServiceManager, http_ports: list):
    """Issues/renews the cert. Only the HTTP-01 standalone method needs
    port 80 briefly free; the two Cloudflare-based methods don't touch
    port 80 at all, since they prove domain ownership (or skip proving
    it entirely, for the Origin CA method) via the Cloudflare API instead."""
    needs_port80 = getattr(cert_mgr, "needs_port80", False)
    port80_ours = needs_port80 and 80 in http_ports and services.status(80) == "active"
    if port80_ours:
        print("[*] Briefly stopping the port 80 tunnel service for certificate validation ...")
        Shell.run(["systemctl", "stop", "wsproxy-80.service"], check=False)
    try:
        return cert_mgr.issue()
    finally:
        if port80_ours:
            print("[*] Restarting the port 80 tunnel service ...")
            Shell.run(["systemctl", "start", "wsproxy-80.service"], check=False)


class App:
    def __init__(self):
        self.cfg = Config.load()

    # ---------------------------------------------------------------
    def cmd_init(self, _args):
        Shell.require_root()
        print("=== wsproxy setup ===")
        print("This installs dropbear (the SSH backend all tunnels connect")
        print("to), starts one WS proxy process per port you choose, gets a")
        print("Let's Encrypt TLS cert for your domain (no DNS provider API")
        print("keys needed), and opens the firewall for exactly those ports.\n")

        self.cfg.domain = ask("Domain (e.g. tunnel.example.com) - must already point at this VPS's IP", self.cfg.domain)
        self.cfg.email = ask("Contact email (optional, for Let's Encrypt renewal notices)", self.cfg.email)
        self.cfg.dropbear_port = int(ask("Internal port for dropbear (backend)", str(self.cfg.dropbear_port or 109)))
        self.cfg.http_ports = ask_ports("Plain-HTTP WS port(s), comma-separated", ",".join(map(str, self.cfg.http_ports)) or "80")
        self.cfg.tls_ports = ask_ports("TLS WS port(s), comma-separated", ",".join(map(str, self.cfg.tls_ports)) or "443")

        overlap = set(self.cfg.http_ports) & set(self.cfg.tls_ports)
        if overlap:
            sys.exit(f"HTTP and TLS port lists overlap: {overlap}")

        if self.cfg.tls_ports:
            choose_cert_method(self.cfg)
            if self.cfg.cert_method == "le_http01" and 80 not in self.cfg.http_ports:
                print("\nNote: certificate issuance needs port 80 briefly reachable")
                print("from the internet (Let's Encrypt's HTTP-01 challenge), even")
                print("though 80 isn't one of your chosen WS ports. Make sure your")
                print("firewall / cloud provider security rules allow inbound 80.\n")

        # 1) packages + dropbear
        PackageManager().install_all()
        Dropbear(port=self.cfg.dropbear_port).configure()

        # 2) certificate (only needed if any TLS ports were requested)
        services = ServiceManager()
        if self.cfg.tls_ports:
            cert_mgr = build_cert_manager(self.cfg)
            fullchain, key_path = issue_cert(cert_mgr, services, self.cfg.http_ports)
            self.cfg.cert_path, self.cfg.key_path = fullchain, key_path

        # 3) one systemd service per port
        for port in self.cfg.http_ports:
            services.write_unit(port, self.cfg.dropbear_port, tls=False)
            services.enable_and_start(port)
        for port in self.cfg.tls_ports:
            services.write_unit(port, self.cfg.dropbear_port, tls=True,
                                 cert_path=self.cfg.cert_path, key_path=self.cfg.key_path)
            services.enable_and_start(port)

        # 4) firewall
        all_ports = list(self.cfg.http_ports) + list(self.cfg.tls_ports)
        Firewall().open_ports(all_ports)

        self.cfg.initialized = True
        self.cfg.save()

        print("\n=== Done ===")
        print(f"Domain:        {self.cfg.domain}")
        print(f"HTTP WS ports: {self.cfg.http_ports}")
        print(f"TLS WS ports:  {self.cfg.tls_ports}")
        print(f"Dropbear port: {self.cfg.dropbear_port} (internal only, not exposed)")
        print("\nAdd tunnel accounts with: sudo wsproxy adduser <name> --days 30")

    # ---------------------------------------------------------------
    def cmd_addport(self, args):
        Shell.require_root()
        self.cfg.require_initialized()
        services = ServiceManager()
        if args.tls:
            if not self.cfg.cert_path:
                choose_cert_method(self.cfg)
                cert_mgr = build_cert_manager(self.cfg)
                self.cfg.cert_path, self.cfg.key_path = issue_cert(
                    cert_mgr, services, self.cfg.http_ports)
            services.write_unit(args.port, self.cfg.dropbear_port, tls=True,
                                 cert_path=self.cfg.cert_path, key_path=self.cfg.key_path)
            self.cfg.tls_ports = sorted(set(self.cfg.tls_ports) | {args.port})
        else:
            services.write_unit(args.port, self.cfg.dropbear_port, tls=False)
            self.cfg.http_ports = sorted(set(self.cfg.http_ports) | {args.port})
        services.enable_and_start(args.port)
        Firewall().open_ports([args.port])
        self.cfg.save()
        print(f"[+] Port {args.port} ({'TLS' if args.tls else 'plain'}) is now active.")

    def cmd_removeport(self, args):
        Shell.require_root()
        ServiceManager().remove(args.port)
        self.cfg.http_ports = [p for p in self.cfg.http_ports if p != args.port]
        self.cfg.tls_ports = [p for p in self.cfg.tls_ports if p != args.port]
        self.cfg.save()
        print(f"[-] Port {args.port} removed.")

    # ---------------------------------------------------------------
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
            print("No accounts yet. Add one with: sudo wsproxy adduser <name>")
            return
        print(f"{'USERNAME':<20}{'EXPIRES':<15}")
        for u in users:
            print(f"{u.username:<20}{u.expiry_date:<15}")

    def cmd_renewcert(self, _args):
        Shell.require_root()
        self.cfg.require_initialized()
        services = ServiceManager()
        cert_mgr = build_cert_manager(self.cfg)
        self.cfg.cert_path, self.cfg.key_path = issue_cert(
            cert_mgr, services, self.cfg.http_ports)
        self.cfg.save()
        services.restart_all(self.cfg.tls_ports)
        print("[+] Certificate renewed and TLS services restarted.")

    def cmd_status(self, _args):
        c = self.cfg
        if not c.initialized:
            print("wsproxy is not set up yet. Run: sudo wsproxy init")
            return
        services = ServiceManager()
        print(f"Domain:        {c.domain}")
        print(f"Dropbear port: {c.dropbear_port} (127.0.0.1 only)")
        print("HTTP WS ports:")
        for p in c.http_ports:
            print(f"  {p:<8} {services.status(p)}")
        print("TLS WS ports:")
        for p in c.tls_ports:
            print(f"  {p:<8} {services.status(p)}")
        print(f"Accounts: {len(SSHUserManager().list_users())}")

    # ---------------------------------------------------------------
    def cmd_menu(self, _args):
        actions = {
            "1": ("Add tunnel account", self._menu_adduser),
            "2": ("List tunnel accounts", lambda: self.cmd_listusers(None)),
            "3": ("Extend an account", self._menu_extend),
            "4": ("Delete an account", self._menu_deluser),
            "5": ("Lock / unlock an account", self._menu_lock_unlock),
            "6": ("Add a WS port", self._menu_addport),
            "7": ("Remove a WS port", self._menu_removeport),
            "8": ("Renew TLS certificate", lambda: self.cmd_renewcert(None)),
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
            entry = actions.get(choice)
            if not entry:
                print("Invalid choice.")
                continue
            try:
                entry[1]()
            except Exception as e:
                print(f"Error: {e}")

    def _menu_adduser(self):
        name = ask("Username")
        days = int(ask("Valid for how many days", "30"))
        SSHUserManager().add_user(name, days_valid=days)

    def _menu_extend(self):
        SSHUserManager().extend_user(ask("Username"), int(ask("Extend by how many days", "30")))

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
        self.cmd_removeport(argparse.Namespace(port=int(ask("Port number to remove"))))

    def _menu_change_cert_method(self):
        self.cfg.require_initialized()
        choose_cert_method(self.cfg)
        services = ServiceManager()
        cert_mgr = build_cert_manager(self.cfg)
        self.cfg.cert_path, self.cfg.key_path = issue_cert(cert_mgr, services, self.cfg.http_ports)
        self.cfg.save()
        services.restart_all(self.cfg.tls_ports)
        print("[+] Certificate method updated and new certificate installed.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wsproxy", description="SSH-over-WebSocket tunnel toolkit")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Interactive first-time setup")
    sub.add_parser("menu", help="Interactive menu")
    sub.add_parser("status", help="Show current configuration")
    sub.add_parser("listusers", help="List tunnel accounts")
    sub.add_parser("renewcert", help="Renew the TLS certificate now")

    p = sub.add_parser("adduser", help="Create a tunnel account")
    p.add_argument("username")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--password", default=None)

    p = sub.add_parser("deluser", help="Delete a tunnel account")
    p.add_argument("username")

    p = sub.add_parser("extend", help="Extend a tunnel account's expiry")
    p.add_argument("username")
    p.add_argument("days", type=int)

    p = sub.add_parser("lock", help="Lock a tunnel account")
    p.add_argument("username")
    p = sub.add_parser("unlock", help="Unlock a tunnel account")
    p.add_argument("username")

    p = sub.add_parser("addport", help="Add another WS port")
    p.add_argument("port", type=int)
    p.add_argument("--tls", action="store_true")

    p = sub.add_parser("removeport", help="Remove a WS port")
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
