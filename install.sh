#!/usr/bin/env bash
# wsproxy installer - Nginx + Python raw proxy architecture
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo bash install.sh"
  exit 1
fi

INSTALL_DIR="/opt/wsproxy"

echo "[*] Copying wsproxy to ${INSTALL_DIR} ..."
mkdir -p "${INSTALL_DIR}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rm -rf "${INSTALL_DIR}/wsproxy"
cp -r "${SCRIPT_DIR}/wsproxy" "${INSTALL_DIR}/wsproxy"

echo "[*] Installing base packages (python3, nginx-extras, dropbear, ufw) ..."
apt-get update -y
# Purge old nginx packages to avoid binary conflicts
apt-get purge -y nginx nginx-common nginx-core || true
apt-get autoremove -y || true
apt-get install -y python3 nginx-extras dropbear ufw curl openssl

# Verify stream module is available
if ! nginx -V 2>&1 | grep -q with-stream; then
  echo "[!] ERROR: Nginx does not have the stream module. Please install nginx-extras manually."
  exit 1
fi

echo "[*] Installing launcher: /usr/local/bin/wsproxy ..."
cat > /usr/local/bin/wsproxy <<EOF
#!/usr/bin/env bash
cd "${INSTALL_DIR}" && exec python3 -m wsproxy.cli "\$@"
EOF
chmod +x /usr/local/bin/wsproxy

echo "[*] Installing daily cert-renewal cron job (using wsproxy renewcert) ..."
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
