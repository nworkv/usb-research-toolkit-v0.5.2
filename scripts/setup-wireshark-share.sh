#!/usr/bin/env bash
set -euo pipefail

# Configure a restricted Samba share on Raspberry Pi for Wireshark capture files.
# Run as: sudo bash scripts/setup-wireshark-share.sh [share-path] [samba-user]
SHARE_PATH="${1:-/srv/usb-captures}"
SAMBA_USER="${2:-${SUDO_USER:-}}"
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo bash $0 [share-path] [samba-user]" >&2
  exit 1
fi
if [[ -z "$SAMBA_USER" || "$SAMBA_USER" == "root" ]]; then
  echo "Specify an existing non-root Linux account, e.g. sudo bash $0 /srv/usb-captures piuser" >&2
  exit 1
fi
if ! id "$SAMBA_USER" >/dev/null 2>&1; then
  echo "Linux user '$SAMBA_USER' does not exist." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y samba tshark
install -d -o "$SAMBA_USER" -g "$SAMBA_USER" -m 2770 "$SHARE_PATH"

CONF=/etc/samba/smb.conf
cp -a "$CONF" "${CONF}.usb-research-backup.$(date +%Y%m%d%H%M%S)"
if grep -q '^\[usb-captures\]' "$CONF"; then
  echo "A [usb-captures] share already exists in $CONF. Review it manually; no duplicate section was added." >&2
  exit 2
fi
cat >> "$CONF" <<EOF

[usb-captures]
   comment = USB Research Wireshark captures
   path = $SHARE_PATH
   browseable = yes
   read only = no
   guest ok = no
   valid users = $SAMBA_USER
   force user = $SAMBA_USER
   create mask = 0660
   directory mask = 2770
   hosts allow = 127.0.0.1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
EOF

if ! testparm -s >/dev/null; then
  echo "Samba configuration validation failed. Restore the backup and inspect $CONF." >&2
  exit 1
fi
systemctl enable --now smbd
systemctl restart smbd
printf '\nSamba share configured: \\\\%s\\usb-captures\n' "$(hostname -I | awk '{print $1}')"
echo "Now set the Samba password for the existing user '$SAMBA_USER':"
smbpasswd -a "$SAMBA_USER"
echo "Keep the share on an isolated lab network; do not forward TCP/445 from the Internet."
