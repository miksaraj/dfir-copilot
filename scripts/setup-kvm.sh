#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────
# DFIR Copilot — KVM/libvirt Setup for TuxedoOS
# ──────────────────────────────────────────────────────────────────
#
# Creates a host-only network for REMnux and FLARE-VM.
# Idempotent — safe to re-run.
#
# Usage:
#   chmod +x scripts/setup-kvm.sh
#   sudo ./scripts/setup-kvm.sh
#
# After running:
#   - Import your REMnux and FLARE-VM OVA/QCOW2 images via virt-manager
#   - Attach both VMs to the "dfir-isolated" network
#   - REMnux will get 192.168.56.10 via DHCP reservation (or set static)
#   - FLARE-VM will get 192.168.56.11 via DHCP reservation (or set static)
# ──────────────────────────────────────────────────────────────────

NETWORK_NAME="dfir-isolated"
BRIDGE_NAME="virbr-dfir"
HOST_IP="192.168.56.1"
NETMASK="255.255.255.0"
DHCP_START="192.168.56.10"
DHCP_END="192.168.56.50"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; }

# ── Check root ────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root (sudo)."
    exit 1
fi

echo "DFIR Copilot — KVM/libvirt Setup"
echo "================================="
echo ""

# ── Install packages if missing ───────────────────────────────────

PACKAGES=(qemu-kvm libvirt-daemon-system libvirt-clients virt-manager bridge-utils)
MISSING=()

for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -l "$pkg" &>/dev/null; then
        MISSING+=("$pkg")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "Installing missing packages: ${MISSING[*]}"
    apt-get update -qq
    apt-get install -y -qq "${MISSING[@]}"
    ok "Packages installed"
else
    ok "All required packages already installed"
fi

# ── Enable and start libvirtd ─────────────────────────────────────

if ! systemctl is-active --quiet libvirtd; then
    systemctl enable libvirtd
    systemctl start libvirtd
    ok "libvirtd started and enabled"
else
    ok "libvirtd already running"
fi

# ── Add current user to libvirt group ─────────────────────────────

REAL_USER="${SUDO_USER:-$USER}"
if [[ "$REAL_USER" != "root" ]]; then
    if ! groups "$REAL_USER" | grep -q libvirt; then
        usermod -aG libvirt "$REAL_USER"
        usermod -aG kvm "$REAL_USER"
        warn "Added ${REAL_USER} to libvirt and kvm groups — log out and back in for this to take effect"
    else
        ok "${REAL_USER} already in libvirt group"
    fi
fi

# ── Create isolated network ──────────────────────────────────────

if virsh net-info "$NETWORK_NAME" &>/dev/null; then
    ok "Network '${NETWORK_NAME}' already exists"

    # Make sure it's active and autostarted
    if ! virsh net-info "$NETWORK_NAME" 2>/dev/null | grep -q "Active:.*yes"; then
        virsh net-start "$NETWORK_NAME"
        ok "Network started"
    fi

    if ! virsh net-info "$NETWORK_NAME" 2>/dev/null | grep -q "Autostart:.*yes"; then
        virsh net-autostart "$NETWORK_NAME"
        ok "Network set to autostart"
    fi
else
    echo "Creating isolated network '${NETWORK_NAME}'..."

    NETXML=$(cat <<EOF
<network>
  <name>${NETWORK_NAME}</name>
  <bridge name="${BRIDGE_NAME}"/>
  <ip address="${HOST_IP}" netmask="${NETMASK}">
    <dhcp>
      <range start="${DHCP_START}" end="${DHCP_END}"/>
    </dhcp>
  </ip>
</network>
EOF
)

    echo "$NETXML" | virsh net-define /dev/stdin
    virsh net-start "$NETWORK_NAME"
    virsh net-autostart "$NETWORK_NAME"
    ok "Network '${NETWORK_NAME}' created, started, and set to autostart"
fi

# ── Verify ────────────────────────────────────────────────────────

echo ""
echo "Network details:"
virsh net-info "$NETWORK_NAME" 2>/dev/null | grep -E "Name|UUID|Active|Autostart|Bridge" | sed 's/^/  /'
echo "  Host IP:    ${HOST_IP}"
echo "  DHCP range: ${DHCP_START} – ${DHCP_END}"

# ── Check KVM acceleration ────────────────────────────────────────

echo ""
if [[ -e /dev/kvm ]]; then
    ok "KVM acceleration available (/dev/kvm exists)"
else
    warn "KVM acceleration NOT available — VMs will run slowly"
    warn "Check BIOS: enable Intel VT-x / AMD-V"
fi

# ── Summary ───────────────────────────────────────────────────────

echo ""
echo "Next steps:"
echo "  1. Import REMnux VM:  use virt-manager or virt-install"
echo "  2. Import FLARE-VM:   use virt-manager or virt-install"
echo "  3. Attach both VMs to network: ${NETWORK_NAME}"
echo "  4. Set static IPs or note DHCP assignments:"
echo "     REMnux:   192.168.56.10"
echo "     FLARE-VM: 192.168.56.11"
echo "  5. Run: php dfirbus.php test-connections"
echo ""

# ── Optional: import helpers ──────────────────────────────────────
# Uncomment and adjust paths if you have OVA/QCOW2 files ready:
#
# echo "Importing REMnux..."
# virt-install \
#   --name remnux \
#   --memory 4096 \
#   --vcpus 2 \
#   --disk path=/var/lib/libvirt/images/remnux.qcow2 \
#   --import \
#   --os-variant ubuntu22.04 \
#   --network network=${NETWORK_NAME} \
#   --noautoconsole
#
# echo "Importing FLARE-VM..."
# virt-install \
#   --name flare-vm \
#   --memory 4096 \
#   --vcpus 2 \
#   --disk path=/var/lib/libvirt/images/flare-vm.qcow2 \
#   --import \
#   --os-variant win10 \
#   --network network=${NETWORK_NAME} \
#   --noautoconsole