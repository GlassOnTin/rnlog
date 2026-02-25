#!/bin/sh
# Install script for Reticulum LoRa Gateway on OpenWrt router (192.168.0.2)
#
# Services:
#   rnsd       - Reticulum transport node (TCP server on :4242, RNode on /dev/ttyACM0)
#   lxmd       - LXMF propagation node + telemetry collector
#
# Addresses:
#   Transport ID:           61514e1d8cc27242bec8bd647c076f87
#   Propagation node:       d68a4b62ab7b2ad72cd4fa44a36b1257
#   LXMF delivery (telem):  761aef52bdf6f08e88fd08be47769278
#
# Prerequisites: pip3 install rns lxmf
#
# Usage: scp -O -r router/ root@192.168.0.2:/tmp/rns-install && \
#        ssh root@192.168.0.2 "sh /tmp/rns-install/install.sh"

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Reticulum LoRa Gateway installer ==="

# Reticulum config
mkdir -p /root/.reticulum/storage
cp "$SCRIPT_DIR/reticulum.conf" /root/.reticulum/config
echo "  Installed /root/.reticulum/config"

# Restore transport identity (preserves transport address across reinstalls)
if [ ! -f /root/.reticulum/storage/transport_identity ]; then
    python3 -c "
import base64
data = base64.b64decode('TRANSPORT_IDENTITY_B64_REMOVED==')
open('/root/.reticulum/storage/transport_identity','wb').write(data)
"
    echo "  Restored transport identity"
else
    echo "  Transport identity already exists, skipping"
fi

# lxmd config
mkdir -p /root/.lxmd/storage
cp "$SCRIPT_DIR/lxmd.conf" /root/.lxmd/config
echo "  Installed /root/.lxmd/config"

# Restore lxmd identity (preserves propagation + delivery addresses)
if [ ! -f /root/.lxmd/identity ]; then
    python3 -c "
import base64
data = base64.b64decode('LXMD_IDENTITY_B64_REMOVED==')
open('/root/.lxmd/identity','wb').write(data)
"
    echo "  Restored lxmd identity"
else
    echo "  lxmd identity already exists, skipping"
fi

# Telemetry inbound handler
mkdir -p /usr/local/bin
cp "$SCRIPT_DIR/lxmf_on_inbound" /usr/local/bin/lxmf_on_inbound
chmod +x /usr/local/bin/lxmf_on_inbound
echo "  Installed /usr/local/bin/lxmf_on_inbound"

# Init scripts
cp "$SCRIPT_DIR/init.d/rnsd" /etc/init.d/rnsd
chmod +x /etc/init.d/rnsd
/etc/init.d/rnsd enable
echo "  Installed and enabled rnsd service"

cp "$SCRIPT_DIR/init.d/lxmd" /etc/init.d/lxmd
chmod +x /etc/init.d/lxmd
/etc/init.d/lxmd enable
echo "  Installed and enabled lxmd service"

echo ""
echo "=== Done ==="
echo ""
echo "Start services:"
echo "  /etc/init.d/rnsd start"
echo "  /etc/init.d/lxmd start"
echo ""
echo "Verify:"
echo "  rnstatus"
echo "  lxmd --status"
