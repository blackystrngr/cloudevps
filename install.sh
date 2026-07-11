#!/usr/bin/env bash
# wsproxy installer
# Run as root on a fresh Debian/Ubuntu VPS:
#   sudo bash install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo bash install.sh"
  exit 1
fi

INSTALL_DIR="/opt/wsproxy"

echo "[*] Copying wsproxy to ${INSTALL_DIR} ..."
mkdir -p "${INSTALL_DIR}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "${SCRIPT_DIR}/wsproxy" "${INSTALL_DIR}/wsproxy"

echo "[*] Installing base package (python3) ..."
apt-get update -y
apt-get install -y python3

echo "[*] Installing launcher: /usr/local/bin/wsproxy ..."
cat > /usr/local/bin/wsproxy <<EOF
#!/usr/bin/env bash
cd "${INSTALL_DIR}" && exec python3 -m wsproxy.cli "\$@"
EOF
chmod +x /usr/local/bin/wsproxy

echo "[*] Installing daily cert-renewal cron job (Let's Encrypt HTTP-01, no API keys needed) ..."
cat > /etc/cron.d/wsproxy-renew <<'EOF'
12 3 * * * root /usr/local/bin/wsproxy renewcert > /var/log/wsproxy-renew.log 2>&1
EOF
chmod 644 /etc/cron.d/wsproxy-renew

echo
echo "=== Installed ==="
echo "Next step - run the interactive setup:"
echo "    sudo wsproxy init"
echo
echo "After that, manage ports and accounts any time with:"
echo "    sudo wsproxy menu"
