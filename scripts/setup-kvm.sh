#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────
# DFIR Copilot — KVM/libvirt Setup for TuxedoOS
# ──────────────────────────────────────────────────────────────────
#
# Sets up the full VM infrastructure:
#   1. Installs qemu-kvm, libvirt, virt-manager, qemu-utils
#   2. Creates a host-only "dfir-isolated" network
#   3. Converts the REMnux OVA (gzip-compressed VMDK) to QCOW2
#   4. Registers REMnux via virt-install --import
#   5. Creates a blank QCOW2 + boots FLARE-VM from Windows ISO
#
# Idempotent — safe to re-run. Each step checks for prior completion.
#
# Prerequisites:
#   /var/lib/libvirt/images/remnux-noble-amd64.ova   (REMnux OVA)
#   /var/lib/libvirt/images/Win10_22H2_ENInt_x64v1.iso  (Windows ISO)
#
# Usage:
#   chmod +x scripts/setup-kvm.sh
#   sudo ./scripts/setup-kvm.sh
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

PACKAGES=(qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients virt-manager bridge-utils)
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
    # Use virsh net-list (not net-info text parsing) — immune to locale-mangled output
    if ! virsh net-list --name 2>/dev/null | grep -qx "$NETWORK_NAME"; then
        virsh net-start "$NETWORK_NAME"
        ok "Network started"
    fi

    if ! virsh net-list --autostart --name 2>/dev/null | grep -qx "$NETWORK_NAME"; then
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

# ── REMnux: OVA → QCOW2 conversion + import ──────────────────────
# virt-install --import cannot drive an OVA directly. We extract the
# VMDK from the archive and convert it to QCOW2 first.

REMNUX_OVA="/var/lib/libvirt/images/remnux-noble-amd64.ova"
REMNUX_QCOW2="/var/lib/libvirt/images/remnux.qcow2"
REMNUX_NAME="remnux"

if [[ -f "$REMNUX_QCOW2" ]]; then
    ok "REMnux QCOW2 already exists — skipping conversion"
elif [[ -f "$REMNUX_OVA" ]]; then
    # /tmp is tmpfs (RAM-backed) — not large enough for a ~40 GB VMDK.
    # Work entirely within /var/lib/libvirt/images/ (real disk, ~350 GB free).
    WORK_DIR="/var/lib/libvirt/images/.remnux-extract"
    mkdir -p "$WORK_DIR"

    echo "Extracting OVA archive into $WORK_DIR..."
    tar xf "$REMNUX_OVA" -C "$WORK_DIR"

    # REMnux OVAs ship with a gzip-compressed VMDK (.vmdk.gz) — handle both
    VMDK_GZ=$(find "$WORK_DIR" -name "*.vmdk.gz" | head -1)
    VMDK=$(find "$WORK_DIR" -name "*.vmdk" ! -name "*.vmdk.gz" | head -1)

    if [[ -n "$VMDK_GZ" ]]; then
        # VMDK format requires seekable access — pipe via stdin won't work.
        # gunzip in-place is fine here because WORK_DIR is on the real disk
        # (/var/lib/libvirt/images/), not on the /tmp tmpfs.
        echo "Decompressing $(basename "$VMDK_GZ") (this will take a few minutes)..."
        gunzip "$VMDK_GZ"
        VMDK="${VMDK_GZ%.gz}"
        echo "Converting $(basename "$VMDK") → remnux.qcow2 (this will take several minutes)..."
        qemu-img convert -f vmdk -O qcow2 -p "$VMDK" "$REMNUX_QCOW2"
    elif [[ -n "$VMDK" ]]; then
        echo "Converting $(basename "$VMDK") → remnux.qcow2 (this will take several minutes)..."
        qemu-img convert -f vmdk -O qcow2 -p "$VMDK" "$REMNUX_QCOW2"
    else
        fail "No .vmdk or .vmdk.gz found inside $REMNUX_OVA"
        rm -rf "$WORK_DIR"
        exit 1
    fi

    rm -rf "$WORK_DIR"
    ok "REMnux disk converted to QCOW2"
else
    warn "REMnux OVA not found at $REMNUX_OVA — skipping REMnux setup"
fi

if virsh dominfo "$REMNUX_NAME" &>/dev/null; then
    ok "VM '$REMNUX_NAME' already registered — skipping import"
elif [[ -f "$REMNUX_QCOW2" ]]; then
    echo "Importing REMnux into libvirt..."
    virt-install \
      --name "$REMNUX_NAME" \
      --memory 4096 \
      --vcpus 2 \
      --disk path="$REMNUX_QCOW2",format=qcow2 \
      --import \
      --os-variant ubuntu24.04 \
      --network network=${NETWORK_NAME} \
      --noautoconsole
    ok "REMnux imported — start it with: virsh start $REMNUX_NAME"
fi

# ── FLARE-VM: Windows installer ISO + blank disk ──────────────────
# This is an install ISO, not an importable image. virt-install boots
# from the ISO and writes to a blank QCOW2. Complete setup in
# virt-manager (VNC) or: virt-viewer --connect qemu:///system flare-vm

FLARE_ISO="/var/lib/libvirt/images/Win10_22H2_ENInt_x64v1.iso"
FLARE_QCOW2="/var/lib/libvirt/images/flare-vm.qcow2"
FLARE_NAME="flare-vm"

if virsh dominfo "$FLARE_NAME" &>/dev/null; then
    ok "VM '$FLARE_NAME' already registered — skipping"
elif [[ -f "$FLARE_ISO" ]]; then
    echo "Creating FLARE-VM with Windows installer..."
    # Create the target disk if it doesn't exist yet
    if [[ ! -f "$FLARE_QCOW2" ]]; then
        qemu-img create -f qcow2 "$FLARE_QCOW2" 100G
        ok "Created blank 100 GB disk for FLARE-VM"
    fi
    virt-install \
      --name "$FLARE_NAME" \
      --memory 8192 \
      --vcpus 4 \
      --disk path="$FLARE_QCOW2",format=qcow2 \
      --cdrom "$FLARE_ISO" \
      --os-variant win10 \
      --network network=${NETWORK_NAME} \
      --graphics vnc,listen=127.0.0.1,port=5910 \
      --video vga \
      --noautoconsole
    ok "FLARE-VM registered — complete Windows setup via:"
    ok "  virt-manager   (GUI, recommended)"
    ok "  virt-viewer --connect qemu:///system $FLARE_NAME"
else
    warn "FLARE-VM ISO not found at $FLARE_ISO — skipping FLARE-VM setup"
fi