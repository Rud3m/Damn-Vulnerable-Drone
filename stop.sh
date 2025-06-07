#!/usr/bin/env bash
#
# Gracefully stop the Damn Vulnerable Drone lab

set -euo pipefail

# ─────────────────────────  Pretty logging helpers  ────────────────────────────
NC='\033[0m'; CYAN='\033[0;36m'; RED='\033[0;31m'; GRN='\033[0;32m'
log()  { echo -e "${CYAN}[+]${NC} $*"; }
warn() { echo -e "${RED}[!]${NC} $*"; }
ok()   { echo -e "${GRN}[✓]${NC} $*"; }

# ───────────────────────────  Root check  ──────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  warn "This script must be run with sudo/root."
  warn "Try: sudo ./stop.sh"
  exit 1
fi

log "Stopping Damn Vulnerable Drone Lab – $(date)"

# ─────────────────────  Helper: is a WLAN interface virtual?  ──────────────────
is_hwsim_iface() {
  local iface="$1"
  local phy
  phy=$(readlink -f "/sys/class/net/$iface/device/ieee80211" 2>/dev/null || true)
  [[ -n "$phy" && "$phy" =~ mac80211_hwsim ]]
}

# ───────────────────── 1. Drain Docker Compose  ───────────────────────────────
log "Stopping Docker Compose services..."
docker compose down --remove-orphans
ok  "Docker stack stopped"

# ───────────────────── 2. Quiet networking daemons  ───────────────────────────
log "Pausing NetworkManager / wpa_supplicant"
if command -v systemctl &>/dev/null; then
  systemctl stop NetworkManager 2>/dev/null || true
  systemctl stop wpa_supplicant 2>/dev/null || true
else
  service NetworkManager stop 2>/dev/null || true
  pkill -TERM wpa_supplicant 2>/dev/null || true
fi

# ───────────────────── 3. Delete virtual WLAN interfaces  ─────────────────────
log "Removing mac80211_hwsim interfaces..."
mapfile -t ifaces < <(iw dev | awk '$1=="Interface"{print $2}' | tac)
for iface in "${ifaces[@]}"; do
  if is_hwsim_iface "$iface"; then
    ip link set "$iface" down 2>/dev/null || true
    log "  • $iface"
    iw dev "$iface" del 2>/dev/null || true
  fi
done
ok "Virtual WLAN cleanup complete"

# ───────────────────── 4. Unload hwsim kernel module  ─────────────────────────
if lsmod | grep -q '^mac80211_hwsim'; then
  log "Attempting to unload mac80211_hwsim..."
  if modprobe -r mac80211_hwsim 2>/dev/null; then
    ok "mac80211_hwsim unloaded"
  else
    warn "Module still in use – leaving it loaded"
  fi
fi

# ───────────────────── 5. Resume networking services  ─────────────────────────-
log "Restarting networking"
if command -v systemctl &>/dev/null; then
  systemctl start NetworkManager 2>/dev/null || true
else
  service NetworkManager start 2>/dev/null || true
fi
service networking restart 2>/dev/null || true

ok "System ready. Lab is fully stopped."
exit 0
