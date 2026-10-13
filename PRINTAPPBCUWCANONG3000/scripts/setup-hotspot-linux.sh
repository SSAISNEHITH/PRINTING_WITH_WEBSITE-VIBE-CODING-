#!/usr/bin/env bash
# =============================================================================
#  setup-hotspot-linux.sh
#  Configures a Linux Wi-Fi Access Point + captive portal DNS for the
#  Captive Portal Print Server.
#
#  Dependencies (install before running):
#    sudo apt install hostapd dnsmasq iptables iw wireless-tools
#
#  Architecture:
#    wlan0 → hostapd (AP mode, WPA2-PSK, AP isolation enabled)
#    dnsmasq → DHCP server + DNS hijacking (all A queries → 192.168.100.1)
#    iptables → blocks internet, client-to-client, and host filesystem access
#    Spring Boot → runs on :8080, handles all HTTP including NCSI/Apple probes
#
#  Run as root: sudo bash setup-hotspot-linux.sh
# =============================================================================

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────
WLAN_IF="wlan0"          # Wi-Fi interface to use as AP
WAN_IF="eth0"            # WAN interface (for isolation — no internet routing)
HOTSPOT_IP="192.168.100.1"
HOTSPOT_SUBNET="192.168.100.0/24"
DHCP_RANGE_START="192.168.100.10"
DHCP_RANGE_END="192.168.100.50"
SSID="SecurePrint"
WPA_PASSPHRASE="PrintPortal2024!"
PORTAL_PORT="8080"
COUNTRY_CODE="IN"        # Change to your 2-letter ISO country code

HOSTAPD_CONF="/tmp/captive_hostapd.conf"
DNSMASQ_CONF="/tmp/captive_dnsmasq.conf"

# ─── Privilege check ──────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root." >&2
    exit 1
fi

echo ""
echo "========================================================"
echo "  Captive Portal Print Server — Linux Hotspot Setup"
echo "========================================================"
echo ""

# ─── Step 1: Bring up the wireless interface in AP mode ──────────────────────
echo "[1/8] Configuring $WLAN_IF..."
ip link set "$WLAN_IF" down
iw "$WLAN_IF" set type __ap 2>/dev/null || true
ip addr flush dev "$WLAN_IF"
ip addr add "$HOTSPOT_IP/24" dev "$WLAN_IF"
ip link set "$WLAN_IF" up

# ─── Step 2: Write hostapd config ────────────────────────────────────────────
echo "[2/8] Writing hostapd config (AP isolation enabled)..."
cat > "$HOSTAPD_CONF" << EOF
interface=$WLAN_IF
driver=nl80211
ssid=$SSID
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$WPA_PASSPHRASE
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
country_code=$COUNTRY_CODE

# AP ISOLATION: prevents clients from communicating with each other
ap_isolate=1

# Deauthenticate clients on bridge removal (cleanup)
bridge=
EOF

# ─── Step 3: Write dnsmasq config (DNS hijacking) ────────────────────────────
echo "[3/8] Writing dnsmasq config (DNS → $HOTSPOT_IP)..."
cat > "$DNSMASQ_CONF" << EOF
# Only listen on the hotspot interface
interface=$WLAN_IF
bind-interfaces

# DHCP pool
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,255.255.255.0,10m

# This machine as the default gateway and DNS resolver
dhcp-option=option:router,$HOTSPOT_IP
dhcp-option=option:dns-server,$HOTSPOT_IP

# DNS hijacking: resolve ALL domain queries to this machine
# Clients' captive-portal probes (generate_204, hotspot-detect.html, ncsi.txt)
# will all hit our Spring Boot controller.
address=/#/$HOTSPOT_IP

# Increase cache size to avoid upstream DNS leakage
cache-size=0

# Log queries (useful for debugging)
log-queries
log-dhcp
EOF

# ─── Step 4: Kill any existing hostapd/dnsmasq processes ─────────────────────
echo "[4/8] Stopping existing hostapd/dnsmasq..."
pkill hostapd  2>/dev/null || true
pkill dnsmasq  2>/dev/null || true
sleep 1

# ─── Step 5: Start hostapd ───────────────────────────────────────────────────
echo "[5/8] Starting hostapd..."
hostapd -B "$HOSTAPD_CONF" -f /tmp/hostapd.log
sleep 2

# ─── Step 6: Start dnsmasq ───────────────────────────────────────────────────
echo "[6/8] Starting dnsmasq..."
dnsmasq --conf-file="$DNSMASQ_CONF" --pid-file=/tmp/dnsmasq_captive.pid

# ─── Step 7: iptables — AP isolation + portal-only access ────────────────────
echo "[7/8] Configuring iptables rules..."

# Flush existing rules
iptables -F FORWARD
iptables -F INPUT
iptables -F OUTPUT

# Allow loopback
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established/related
iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow DHCP (UDP 67/68) on hotspot interface
iptables -A INPUT -i "$WLAN_IF" -p udp --dport 67 -j ACCEPT

# Allow DNS on hotspot interface (dnsmasq handles it, hijacks to portal IP)
iptables -A INPUT -i "$WLAN_IF" -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i "$WLAN_IF" -p tcp --dport 53 -j ACCEPT

# Allow HTTP/HTTPS to portal (Spring Boot)
iptables -A INPUT -i "$WLAN_IF" -p tcp --dport "$PORTAL_PORT" -j ACCEPT

# AP ISOLATION: drop packets forwarded between clients on same subnet
iptables -A FORWARD -i "$WLAN_IF" -o "$WLAN_IF" -j DROP

# Block WAN forwarding (no internet for hotspot clients)
iptables -A FORWARD -i "$WLAN_IF" -o "$WAN_IF" -j DROP
iptables -A FORWARD -i "$WAN_IF" -o "$WLAN_IF" -j DROP

# Block access to SMB/NFS/host filesystem ports from hotspot clients
iptables -A INPUT -i "$WLAN_IF" -p tcp --dport 445  -j DROP   # SMB
iptables -A INPUT -i "$WLAN_IF" -p tcp --dport 139  -j DROP   # NetBIOS
iptables -A INPUT -i "$WLAN_IF" -p udp --dport 137  -j DROP   # NetBIOS
iptables -A INPUT -i "$WLAN_IF" -p udp --dport 138  -j DROP   # NetBIOS
iptables -A INPUT -i "$WLAN_IF" -p tcp --dport 2049 -j DROP   # NFS
iptables -A INPUT -i "$WLAN_IF" -p tcp --dport 22   -j DROP   # SSH
iptables -A INPUT -i "$WLAN_IF" -p tcp --dport 3306 -j DROP   # MySQL
iptables -A INPUT -i "$WLAN_IF" -p tcp --dport 5432 -j DROP   # PostgreSQL

# Redirect all HTTP (port 80) from clients to Spring Boot portal (port-forward)
iptables -t nat -A PREROUTING -i "$WLAN_IF" -p tcp --dport 80 \
    -j DNAT --to-destination "$HOTSPOT_IP:$PORTAL_PORT"

# Redirect all HTTPS (port 443) to portal (client sees SSL error — by design;
# use a self-signed cert for production deployments)
iptables -t nat -A PREROUTING -i "$WLAN_IF" -p tcp --dport 443 \
    -j DNAT --to-destination "$HOTSPOT_IP:$PORTAL_PORT"

# Masquerade for NAT (not strictly needed since we block WAN, but for portal redirects)
iptables -t nat -A POSTROUTING -o "$WLAN_IF" -j MASQUERADE

echo "[7/8] iptables rules applied."

# ─── Step 8: Start Spring Boot server ────────────────────────────────────────
echo "[8/8] Launching Spring Boot print server..."
JAR_PATH="$(dirname "$0")/../target/print-server-1.0.0.jar"

if [[ -f "$JAR_PATH" ]]; then
    java -Djava.awt.headless=false \
         -Xmx256m \
         -jar "$JAR_PATH" \
         --server.port="$PORTAL_PORT" \
         --captive-portal.portal-ip="$HOTSPOT_IP" \
         --captive-portal.hotspot-interface="$WLAN_IF" &
    echo "[OK] Print server launched (PID $!)."
else
    echo "[WARN] JAR not found at $JAR_PATH"
    echo "       Run: mvn package -DskipTests"
    echo "       Then restart this script or launch manually."
fi

echo ""
echo "========================================================"
echo "  Setup complete."
echo "  SSID       : $SSID"
echo "  Password   : $WPA_PASSPHRASE"
echo "  Portal URL : http://$HOTSPOT_IP:$PORTAL_PORT/portal"
echo "  DNS hijack : ALL queries → $HOTSPOT_IP (dnsmasq)"
echo "========================================================"
