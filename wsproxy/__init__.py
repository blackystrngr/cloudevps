"""
wsproxy - a from-scratch SSH-over-fake-WebSocket tunnel proxy.

Architecture (see README.md for the full explanation):

  [client app] --TCP--> [ProxyServer on a public port] --TCP--> [dropbear/sshd]

Each ProxyServer instance is one OS process bound to one port (plain
HTTP or TLS). It performs a fake HTTP "Upgrade: websocket" handshake
so client apps that expect a WebSocket response are satisfied, then
relays raw bytes bidirectionally between the client and a backend
service (dropbear by default) until either side disconnects.

No third-party dependencies - stdlib only, so it runs anywhere Python
3 runs without pip installs on the VPS.
"""

__version__ = "1.0.0"
