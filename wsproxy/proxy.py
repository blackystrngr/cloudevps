"""
proxy.py - the actual tunneling engine.

Two classes, one job each:

  ProxyServer        - owns the listening socket, accepts connections,
                        hands each one to its own ConnectionHandler
                        thread. Optionally wraps accepted sockets in
                        TLS if constructed with a cert/key.

  ConnectionHandler   - one per client connection. Reads the fake
                         HTTP upgrade request, decides which backend
                         to connect to (X-Real-Host header if present
                         and safe, otherwise a server-configured
                         default - dropbear), sends the fake 101
                         response, then relays raw bytes both ways
                         until either side closes.

This intentionally does not implement real RFC6455 WebSocket framing.
The client apps this is built for (HTTP Injector and similar) don't
either - they just want to see an HTTP Upgrade response before they
start speaking SSH on the same TCP connection. See README.md for the
full protocol explanation.
"""
import logging
import select
import socket
import ssl
import threading
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger("wsproxy")

BUFLEN = 4096 * 4
IDLE_TIMEOUT_ROUNDS = 60   # * 3s select timeout below = ~180s idle cutoff
SELECT_TIMEOUT = 3

FAKE_UPGRADE_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
    b"Content-Length: 104857600000\r\n\r\n"
)
REJECT_RESPONSE = b"HTTP/1.1 403 Forbidden\r\n\r\n"


@dataclass
class ProxySettings:
    listen_host: str = "0.0.0.0"
    listen_port: int = 80
    default_backend_host: str = "127.0.0.1"
    default_backend_port: int = 109      # dropbear, not OpenSSH:22
    tls_cert: Optional[str] = None       # set both to enable TLS
    tls_key: Optional[str] = None
    shared_pass: Optional[str] = None    # optional X-Pass shared secret

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_cert and self.tls_key)


class ConnectionHandler(threading.Thread):
    """Handles exactly one client connection end-to-end."""

    def __init__(self, client_sock: socket.socket, addr, settings: ProxySettings):
        super().__init__(daemon=True)
        self.client = client_sock
        self.addr = addr
        self.settings = settings
        self.target: Optional[socket.socket] = None

    # ---- header parsing (deliberately not a real HTTP parser) --------
    # Case-insensitive and tolerant of any method/version line, extra
    # or duplicate headers, and whatever specific payload template a
    # given client app (HTTP Injector, NPV Tunnel, custom CDN payloads,
    # etc.) happens to use - none of that matters here since we only
    # ever look for two optional header names, never validate the rest.
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
        """Reads from the client until a full fake-HTTP header block
        (terminated by a blank line) has arrived, or until BUFLEN is
        hit. A single recv() is usually enough, but some clients split
        their payload across more than one TCP write - looping here
        instead of assuming one read is complete makes that split
        style work too, on top of whatever payload/method/header
        combination the client chooses to send."""
        raw = b""
        while len(raw) < BUFLEN:
            chunk = self.client.recv(BUFLEN - len(raw))
            if not chunk:
                break
            raw += chunk
            if b"\r\n\r\n" in raw or b"\n\n" in raw:
                break
        return raw

    def _resolve_backend(self, raw_request: bytes):
        """Returns (host, port) to connect to for this client."""
        real_host = self._find_header(raw_request, b"X-Real-Host")
        shared_pass = self._find_header(raw_request, b"X-Pass")

        if real_host:
            host_port = real_host.decode(errors="ignore")
            host, _, port_str = host_port.partition(":")
            port = int(port_str) if port_str.isdigit() else self.settings.default_backend_port

            allowed = host in ("127.0.0.1", "localhost")
            if not allowed and self.settings.shared_pass:
                allowed = shared_pass and shared_pass.decode(errors="ignore") == self.settings.shared_pass

            if not allowed:
                return None  # caller rejects
            return host, port

        # No X-Real-Host at all -> just use the server's configured
        # default backend (dropbear). This is what makes a plain SSH
        # client work with zero special headers.
        return self.settings.default_backend_host, self.settings.default_backend_port

    # ---- main handler --------------------------------------------------
    def run(self):
        try:
            raw = self._read_headers()
            if not raw:
                return

            backend = self._resolve_backend(raw)
            if backend is None:
                self._safe_send(self.client, REJECT_RESPONSE)
                return

            # Some clients (notably plain-HTTP tunnel apps, since there's
            # no TLS handshake to naturally separate the writes) push the
            # fake-HTTP header block *and* the first bytes of the real
            # SSH stream in the same TCP write. A single recv() above can
            # therefore capture both. Anything after the blank line that
            # ends the fake headers is real payload, not header text -
            # it must be replayed to the backend, or the client's initial
            # SSH version banner silently vanishes and the handshake
            # never completes.
            header_end = raw.find(b"\r\n\r\n")
            leftover = raw[header_end + 4:] if header_end != -1 else b""

            host, port = backend
            try:
                self.target = socket.create_connection((host, port), timeout=10)
            except OSError as e:
                logger.warning("backend connect failed %s:%s - %s", host, port, e)
                self._safe_send(self.client, REJECT_RESPONSE)
                return

            self._safe_send(self.client, FAKE_UPGRADE_RESPONSE)
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
    """Owns the listening socket for one port. Run start() to block
    forever accepting connections (intended to be the whole lifetime
    of one systemd service / OS process)."""

    def __init__(self, settings: ProxySettings):
        self.settings = settings
        self._sock: Optional[socket.socket] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._handlers: List[ConnectionHandler] = []
        self._lock = threading.Lock()

        if settings.tls_enabled:
            self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ssl_context.load_cert_chain(settings.tls_cert, settings.tls_key)
            self._ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.settings.listen_host, self.settings.listen_port))
        self._sock.listen(128)

        mode = "TLS" if self.settings.tls_enabled else "plain"
        logger.info(
            "wsproxy listening on %s:%s (%s), default backend %s:%s",
            self.settings.listen_host, self.settings.listen_port, mode,
            self.settings.default_backend_host, self.settings.default_backend_port,
        )

        try:
            while True:
                client, addr = self._sock.accept()
                if self._ssl_context:
                    try:
                        client = self._ssl_context.wrap_socket(client, server_side=True)
                    except ssl.SSLError as e:
                        logger.warning("TLS handshake failed from %s: %s", addr, e)
                        client.close()
                        continue
                handler = ConnectionHandler(client, addr, self.settings)
                self._track(handler)
                handler.start()
        except KeyboardInterrupt:
            pass
        finally:
            self._sock.close()

    def _track(self, handler: ConnectionHandler):
        with self._lock:
            self._handlers = [h for h in self._handlers if h.is_alive()]
            self._handlers.append(handler)

    def active_connections(self) -> int:
        with self._lock:
            self._handlers = [h for h in self._handlers if h.is_alive()]
            return len(self._handlers)
