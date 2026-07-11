# wsproxy — SSH-over-WebSocket tunnel, built from scratch

This is a real, from-scratch implementation of the SSH-over-fake-
WebSocket tunneling technique used by autoscripts like NevermoreSSH's
`hop` — not a wrapper around nginx, and not the same code, just the
same underlying mechanism, written clean and organized (OOP Python,
stdlib only) so it's easy to understand, extend, and hand to another
developer or AI.

## How it works (the actual mechanism)

```
[client app]  --TCP-->  [wsproxy, one process per port]  --TCP-->  [dropbear]
 (HTTP Injector)          e.g. port 80 (plain) or 443 (TLS)        127.0.0.1:109
```

1. The client opens a TCP connection and sends something that looks
   like an HTTP request with `Upgrade: websocket`.
2. wsproxy doesn't run a real HTTP parser — it just does a plain
   string search for an optional `X-Real-Host: host:port` header. If
   present (and it targets localhost), that's the backend to connect
   to. If absent, it falls back to a **server-configured default —
   dropbear**, so a plain SSH client doesn't need to send anything
   backend-specific at all.
3. wsproxy opens its own connection to that backend, then sends back
   `HTTP/1.1 101 Switching Protocols\r\n\r\n` (plus some harmless
   padding text, purely cosmetic, to vary the payload shape).
4. From that point on, wsproxy stops treating the connection as HTTP
   entirely — it's a byte-for-byte relay both directions, using
   `select()`, until either side disconnects.

No real WebSocket framing (opcodes, masking, ping/pong) is
implemented, because none of the client apps this is built for need
it — they just want to see something that looks like a successful
Upgrade response before they start speaking raw SSH.

This has been functionally tested (not just syntax-checked): a local
smoke test proves the 101 handshake, the `X-Real-Host` override, the
default-backend fallback, the localhost-only security check, and the
TLS path all work correctly.

## What's included

```
wsproxy_pkg/
├── install.sh              # one-time bootstrap
└── wsproxy/                 # the OOP Python package
    ├── proxy.py             # ProxyServer + ConnectionHandler — the actual tunnel engine
    ├── serve.py              # `python3 -m wsproxy.serve` — runs one instance, one port
    ├── services.py          # ServiceManager — generates/manages one systemd unit per port
    ├── config.py            # Config — reads/writes /etc/wsproxy/config.json
    ├── system.py            # Shell, PackageManager, Firewall, Dropbear
    ├── acme.py                # LetsEncryptCertManager — plain acme.sh HTTP-01, no API keys
    ├── users.py              # SSHUserManager — add/extend/lock/delete tunnel accounts
    └── cli.py                # `wsproxy` command + interactive menu
```

Each proxy port is its own systemd service (`wsproxy-<port>.service`),
running `python3 -m wsproxy.serve --port <port> ...` directly — no
nginx, no extra layer, systemd supervises it exactly like it
supervises dropbear.

## Before you start

1. A VPS running Debian or Ubuntu, root access.
2. A domain/subdomain pointed (A record) at your VPS's IP — needed
   only if you want TLS ports. Any DNS provider works; no API access
   is required.
3. Port 80 reachable from the internet, at least briefly, whenever a
   certificate is issued or renewed (see "Certificates" below).

## Install

```bash
cd wsproxy_pkg
sudo bash install.sh
sudo wsproxy init
```

`init` will ask for your domain, an optional contact email, which
internal port dropbear should use (default 109), and — this is the
part you asked for — **which HTTP ports and which TLS ports you
want, as comma-separated lists** (e.g. `80,8880` for HTTP and `443`
for TLS). It installs dropbear, gets your certificate if you asked for
any TLS ports, creates and starts one systemd service per port, and
opens exactly those ports in the firewall.

## Certificates

Certificates come from **plain Let's Encrypt via `acme.sh`, using the
HTTP-01 "standalone" challenge** — no Cloudflare account, no DNS
provider API keys, nothing to paste in beyond your domain name.

How it works: for a few seconds during issuance/renewal, `acme.sh`
binds directly to port 80 and answers Let's Encrypt's validation
request itself. If your port 80 is currently one of your own wsproxy
WS ports, `wsproxy` automatically stops that service, gets the
certificate, and restarts it — you don't need to do anything manually.
If port 80 isn't one of your chosen WS ports, just make sure your
firewall/cloud security rules allow inbound port 80 (even if nothing
normally listens there) so the brief validation request can get
through.

Renewal runs daily via cron (`sudo wsproxy renewcert`, installed
automatically by `install.sh`) — `acme.sh` only actually renews when
the cert is within its renewal window, so this is a safe no-op most
days.

## Day to day

```bash
sudo wsproxy menu                    # interactive menu
sudo wsproxy adduser johndoe --days 30
sudo wsproxy listusers
sudo wsproxy extend johndoe 30
sudo wsproxy lock johndoe
sudo wsproxy unlock johndoe
sudo wsproxy deluser johndoe
sudo wsproxy addport 8880            # add another plain WS port later
sudo wsproxy addport 8443 --tls      # add another TLS WS port later
sudo wsproxy removeport 8880
sudo wsproxy renewcert
sudo wsproxy status
```

Client apps (HTTP Injector etc.) just need your domain and whichever
port you configured — no `X-Real-Host` header needed for plain SSH,
since the proxy already defaults to dropbear.

## Why dropbear, not OpenSSH:22

Keeping the tunnel backend on its own internal dropbear instance
(bound to `127.0.0.1` only, e.g. port 109) means:
- your real admin SSH access on port 22 stays completely separate
  from tunnel traffic
- dropbear is lighter-weight and well suited to being the target of
  many short-lived tunneled connections
- if you ever want tunnel accounts to have different restrictions
  than your admin account, that's a natural place to enforce it
  (dropbear supports its own `/etc/dropbear` config independent of
  `sshd_config`)

## Security note

`X-Real-Host` deliberately only allows connecting to `127.0.0.1`/
`localhost` targets unless a shared secret (`--shared-pass`) is
configured and provided by the client. This stops the proxy from
being usable as an open relay to arbitrary internet hosts by anyone
who discovers the port.

## Extending this

Because each concern is its own class, adding features later is
additive, not a rewrite:
- another backend type (e.g. OpenVPN) → point another port's
  `--default-backend-port` at it, no code changes needed
- bandwidth limits, connection caps, IP allow-lists → add checks in
  `ConnectionHandler._resolve_backend` or `_relay`
- a status dashboard → new class reading `ServiceManager.status()`
  and `SSHUserManager.list_users()`
