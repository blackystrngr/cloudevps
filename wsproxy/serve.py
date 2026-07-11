import argparse
import logging
import sys

from .proxy import ProxyServer, ProxySettings

def main():
    parser = argparse.ArgumentParser(description="Run one WS-SSH tunnel proxy instance")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--default-backend-host", default="127.0.0.1")
    parser.add_argument("--default-backend-port", type=int, default=109)
    parser.add_argument("--shared-pass", default=None)
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
        shared_pass=args.shared_pass,
    )
    ProxyServer(settings).start()

if __name__ == "__main__":
    main()
