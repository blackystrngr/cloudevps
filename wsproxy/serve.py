"""
serve.py - `python3 -m wsproxy.serve ...` - runs exactly one
ProxyServer instance bound to one port, blocking forever. This is
what each systemd service (ws-http.service, ws-tls.service, ...)
actually execs. Kept separate from cli.py (the human-facing menu/
management tool) on purpose - single responsibility.
"""
import argparse
import logging
import sys

from .proxy import ProxyServer, ProxySettings


def main():
    parser = argparse.ArgumentParser(description="Run one WS-SSH tunnel proxy instance")
    parser.add_argument("--host", default="0.0.0.0", help="address to listen on")
    parser.add_argument("--port", type=int, required=True, help="public port to listen on")
    parser.add_argument("--default-backend-host", default="127.0.0.1")
    parser.add_argument("--default-backend-port", type=int, default=109,
                         help="backend used when the client sends no X-Real-Host header "
                              "(default: 109, dropbear)")
    parser.add_argument("--tls-cert", default=None)
    parser.add_argument("--tls-key", default=None)
    parser.add_argument("--shared-pass", default=None,
                         help="optional shared secret required for clients that ask for a "
                              "non-localhost X-Real-Host backend")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )

    settings = ProxySettings(
        listen_host=args.host,
        listen_port=args.port,
        default_backend_host=args.default_backend_host,
        default_backend_port=args.default_backend_port,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        shared_pass=args.shared_pass,
    )
    ProxyServer(settings).start()


if __name__ == "__main__":
    main()
