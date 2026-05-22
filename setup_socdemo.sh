#!/bin/bash
# =========================================================
# Setup Demo SSH User for SOC Day 4
# Owner: Sharaf (Environment/Admin)
# Purpose:
#   - Create dedicated demo user
#   - Enable SSH password login
#   - Optional sudo access
#   - Ensure home/.ssh exists
#   - Unban Kali IP from fail2ban
#   - Print final readiness summary
# =========================================================

set -euo pipefail

# ---------- CONFIG ----------
DEMO_USER="${1:-socdemo}"              # default username if not passed
KALI_IP="${2:-192.168.88.206}"         # attacker IP
ENABLE_SUDO="${3:-no}"                 # yes / no
SSH_CONFIG="/etc/ssh/sshd_config"
# ----------------------------

echo "========================================================="
echo " SOC Demo User Setup"
echo " Demo User : $DEMO_USER"
echo " Kali IP   : $KALI_IP"
echo " Sudo      : $ENABLE_SUDO"
echo "========================================================="

if [[ $EUID -ne 0 ]]; then
  echo "[!] Run this script with sudo."
  echo "    Example: sudo bash setup_socdemo.sh socdemo 192.168.88.206 no"
  exit 1
fi

echo
echo "[1/8] Checking required services..."
systemctl is-enabled ssh >/dev/null 2>&1 || true
systemctl start ssh
echo "  [✓] ssh service is running"

if systemctl list-unit-files | grep -q '^fail2ban\.service'; then
  systemctl start fail2ban || true
  echo "  [✓] fail2ban checked"
else
  echo "  [!] fail2ban service not found. Continuing..."
fi

echo
echo "[2/8] Creating demo user if missing..."
if id "$DEMO_USER" >/dev/null 2>&1; then
  echo "  [=] User '$DEMO_USER' already exists"
else
  adduser --gecos "" "$DEMO_USER"
  echo "  [✓] User '$DEMO_USER' created"
fi

echo
echo "[3/8] Setting password for '$DEMO_USER'..."
echo "  Enter password for $DEMO_USER:"
passwd "$DEMO_USER"
echo "  [✓] Password set"

echo
echo "[4/8] Ensuring SSH password authentication is enabled..."
if grep -qi '^PasswordAuthentication' "$SSH_CONFIG"; then
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$SSH_CONFIG"
else
  echo 'PasswordAuthentication yes' >> "$SSH_CONFIG"
fi

if grep -qi '^UsePAM' "$SSH_CONFIG"; then
  sed -i 's/^#\?UsePAM.*/UsePAM yes/' "$SSH_CONFIG"
else
  echo 'UsePAM yes' >> "$SSH_CONFIG"
fi

systemctl restart ssh
echo "  [✓] SSH password login enabled and ssh restarted"

echo
echo "[5/8] Preparing home and .ssh path..."
USER_HOME=$(eval echo "~$DEMO_USER")
mkdir -p "$USER_HOME/.ssh"
chown -R "$DEMO_USER:$DEMO_USER" "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"
echo "  [✓] $USER_HOME/.ssh ready"

echo
echo "[6/8] Optional sudo access..."
if [[ "$ENABLE_SUDO" == "yes" ]]; then
  usermod -aG sudo "$DEMO_USER"
  echo "  [✓] '$DEMO_USER' added to sudo group"
else
  echo "  [=] Sudo not granted"
fi

echo
echo "[7/8] Unbanning Kali IP from fail2ban if needed..."
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client set sshd unbanip "$KALI_IP" >/dev/null 2>&1 || true
  echo "  [✓] Unban attempted for $KALI_IP"
else
  echo "  [!] fail2ban-client not found. Skipping..."
fi

echo
echo "[8/8] Final readiness checks..."
echo "---------------------------------------------------------"
echo "User exists:"
id "$DEMO_USER" || true

echo
echo "SSH config lines:"
grep -Ei '^(PasswordAuthentication|UsePAM)' "$SSH_CONFIG" || true

echo
echo "SSH service:"
systemctl --no-pager --full status ssh | sed -n '1,10p' || true

echo
echo "fail2ban sshd status:"
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client status sshd || true
else
  echo "fail2ban not installed"
fi

echo
echo "Home path:"
echo "  $USER_HOME"

echo
echo "========================================================="
echo " READY"
echo " Demo user prepared: $DEMO_USER"
echo " Next steps for Yussef on Kali:"
echo "   1) Change USERNAME in redteam.py to: $DEMO_USER"
echo "   2) Test manually: ssh $DEMO_USER@192.168.88.208"
echo "   3) Run the tool again"
echo "========================================================="
