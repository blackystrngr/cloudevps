import logging
import select
import socket
import threading
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("wsproxy")

BUFLEN = 4096 * 4
IDLE_TIMEOUT_ROUNDS = 60
SELECT_TIMEOUT = 3
INITIAL_READ_TIMEOUT = 20
HEADER_SETTLE_TIMEOUT = 0.3

FAKE_UPGRADE_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
    b"Content-Length: 104857600000\r\n\r\n"
)
CONNECT_RESPONSE = b"HTTP/1.1 200 Connection Established\r\n\r\n"
REJECT_RESPONSE = b"HTTP/1.1 403 Forbidden\r\n\r\n"

REAL_HOST_HEADER_NAMES = (b"X-Real-Host", b"X-Online-Host", b"X-Forward-Host")
SHARED_PASS_HEADER_NAMES = (b"X-Pass", b"X-Password")

@dataclass
class ProxySettings:
    listen_host: str = "0.0.0.0"
    listen_port: int = 80
    default_backend_host: str = "127.0.0.1"
    default_backend_port: int = 109
    shared_pass: Optional[str] = None


class ConnectionHandler(threading.Thread):
    def __init__(self, client_sock: socket.socket, addr, settings: ProxySettings):
        super().__init__(daemon=True)
        self.client = client_sock
        self.addr = addr
        self.settings = settings
        self.target: Optional[socket.socket] = None

    @staticmethod
    def _find_header(raw: bytes, name: bytes) -> Optional[bytes]:
        lowered = raw.lower()
        marker = name.lower() + b":"
        idx = lowered.find(marker)
        if idx == -1:
            return None
        start = idx + len(marker)
        end = raw.find(b"\r\n", start)
        if end == -1:
            end = raw.find(b"\n", start)
        if end == -1:
            return None
        return raw[start:end].strip()

    def _read_headers(self) -> bytes:
        raw = b""
        self.client.settimeout(INITIAL_READ_TIMEOUT)
        try:
            chunk = self.client.recv(BUFLEN)
        except (socket.timeout, OSError):
            return b""
        if not chunk:
            return b""
        raw += chunk

        self.client.settimeout(HEADER_SETTLE_TIMEOUT)
        while len(raw) < BUFLEN and not (b"\r\n\r\n" in raw or b"\n\n" in raw):
            try:
                chunk = self.client.recv(BUFLEN - len(raw))
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            raw += chunk
        self.client.settimeout(None)
        return raw

    def _find_any_header(self, raw: bytes, names) -> Optional[bytes]:
        for name in names:
            val = self._find_header(raw, name)
            if val is not None:
                return val
        return None

    def _resolve_backend(self, raw_request: bytes):
        real_host = self._find_any_header(raw_request, REAL_HOST_HEADER_NAMES)
        shared_pass = self._find_any_header(raw_request, SHARED_PASS_HEADER_NAMES)

        if real_host:
            host_port = real_host.decode(errors="ignore")
            host, _, port_str = host_port.partition(":")
            port = int(port_str) if port_str.isdigit() else self.settings.default_backend_port

            allowed = host in ("127.0.0.1", "localhost")
            if not allowed and self.settings.shared_pass:
                allowed = shared_pass and shared_pass.decode(errors="ignore") == self.settings.shared_pass

            if not allowed:
                return None
            return host, port

        return self.settings.default_backend_host, self.settings.default_backend_port

    def run(self):
        try:
            raw = self._read_headers()
            if not raw:
                return

            backend = self._resolve_backend(raw)
            if backend is None:
                self._safe_send(self.client, REJECT_RESPONSE)
                return

            if b"\r\n\r\n" in raw:
                idx = raw.find(b"\r\n\r\n")
                leftover = raw[idx + 4:]
                had_header = True
            elif b"\n\n" in raw:
                idx = raw.find(b"\n\n")
                leftover = raw[idx + 2:]
                had_header = True
            else:
                leftover = raw
                had_header = False

            host, port = backend
            try:
                self.target = socket.create_connection((host, port), timeout=10)
            except OSError as e:
                logger.warning("backend connect failed %s:%s - %s", host, port, e)
                self._safe_send(self.client, REJECT_RESPONSE)
                return

            first_line = raw.split(b"\n", 1)[0].strip(b"\r")
            if raw.startswith(b"SSH-") or (not had_header and not first_line.upper().startswith(
                (b"GET", b"POST", b"HEAD", b"PUT", b"CONNECT", b"OPTIONS")
            )):
                response = None
            elif first_line.upper().startswith(b"CONNECT "):
                response = CONNECT_RESPONSE
            else:
                response = FAKE_UPGRADE_RESPONSE

            if response is not None:
                self._safe_send(self.client, response)
            if leftover:
                self._safe_send(self.target, leftover)

            logger.info("tunnel open: %s -> %s:%s", self.addr, host, port)
            self._relay()
        except Exception as e:
            logger.debug("connection error from %s: %s", self.addr, e)
        finally:
            self._close_all()

    @staticmethod
    def _safe_send(sock: socket.socket, data: bytes):
        try:
            sock.sendall(data)
        except OSError:
            pass

    def _relay(self):
        socs = [self.client, self.target]
        idle_rounds = 0
        while True:
            try:
                readable, _, errored = select.select(socs, [], socs, SELECT_TIMEOUT)
            except (OSError, ValueError):
                break
            if errored:
                break
            if readable:
                idle_rounds = 0
                closed = False
                for s in readable:
                    try:
                        data = s.recv(BUFLEN)
                    except OSError:
                        closed = True
                        break
                    if not data:
                        closed = True
                        break
                    dest = self.target if s is self.client else self.client
                    try:
                        dest.sendall(data)
                    except OSError:
                        closed = True
                        break
                if closed:
                    break
            else:
                idle_rounds += 1
                if idle_rounds >= IDLE_TIMEOUT_ROUNDS:
                    break

    def _close_all(self):
        for s in (self.client, self.target):
            if s is None:
                continue
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


class ProxyServer:
    def __init__(self, settings: ProxySettings):
        self.settings = settings
        self._sock: Optional[socket.socket] = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.settings.listen_host, self.settings.listen_port))
        self._sock.listen(128)

        logger.info(
            "wsproxy listening on %s:%s, backend %s:%s",
            self.settings.listen_host, self.settings.listen_port,
            self.settings.default_backend_host, self.settings.default_backend_port,
        )

        try:
            while True:
                client, addr = self._sock.accept()
                handler = ConnectionHandler(client, addr, self.settings)
                handler.start()
        except KeyboardInterrupt:
            pass
        finally:
            self._sock.close()
