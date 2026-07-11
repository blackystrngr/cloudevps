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
        """Reads whatever the client sends before it goes quiet.

        Most fake-HTTP/WebSocket payloads end in a blank line, so we
        stop as soon as one shows up. But a large share of real-world
        "SSH payloads" never send one at all - a bare SSH client just
        writes its identification banner (a single "SSH-2.0-...\r\n",
        no second CRLF) and then waits for the server's banner back.
        Blocking until a blank line arrives means blocking forever on
        those, so after the *first* bytes land we switch to a short
        settle timeout: if no more data shows up within that window,
        whatever we've got is treated as the complete opening burst,
        blank line or not. A generous timeout covers clients that
        never send anything at all (idle probes, scanners)."""
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
                break  # client's opening burst is done for now
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
        """Returns (host, port) to connect to for this client."""
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
            #
            # Payloads that never sent a blank line at all (a bare SSH
            # client's identification banner, or any other headerless
            # payload) have *nothing* to strip - the entire buffer is
            # real payload and must be replayed in full, not dropped.
            if b"\r\n\r\n" in raw:
                idx = raw.find(b"\r\n\r\n")
                leftover = raw[idx + 4:]
                had_header_block = True
            elif b"\n\n" in raw:
                idx = raw.find(b"\n\n")
                leftover = raw[idx + 2:]
                had_header_block = True
            else:
                leftover = raw
                had_header_block = False

            host, port = backend
            try:
                self.target = socket.create_connection((host, port), timeout=10)
            except OSError as e:
                logger.warning("backend connect failed %s:%s - %s", host, port, e)
                self._safe_send(self.client, REJECT_RESPONSE)
                return

            # What we send back before relaying depends entirely on what
            # the client actually sent us:
            #  - a bare SSH banner (no HTTP-ish wrapper at all) gets no
            #    response of our own - injecting fake HTTP text in front
            #    of a raw SSH stream corrupts the handshake outright, the
            #    client just wants the backend's real banner.
            #  - an HTTP CONNECT-style payload gets the "200 Connection
            #    Established" it's checking for.
            #  - anything else (GET/POST + Upgrade, or any other fake-HTTP
            #    request) gets the fake WebSocket 101, same as before.
            first_line = raw.split(b"\n", 1)[0].strip(b"\r")
            if raw.startswith(b"SSH-") or not had_header_block and not first_line.upper().startswith(
                (b"GET", b"POST", b"HEAD", b"PUT", b"CONNECT", b"OPTIONS")
            ):
                response = None
            elif first_line.upper().startswith(b"CONNECT "):
                response = CONNECT_RESPONSE
            else:
                response = FAKE_UPGRADE_RESPONSE

            if response is not None:
                self._safe_send(self.client, response)
            if leftover:
                self._safe_send(self.target, leftover)
            logger.info(
                "tunnel open: %s -> %s:%s (%s)",
                self.addr, host, port,
                "raw" if response is None else ("connect" if response is CONNECT_RESPONSE else "ws"),
            )
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
