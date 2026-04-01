#!/bin/bash
# quick_scan.sh - Fast targeted scan of a single host
#
# Performs a rapid four-step assessment: port discovery, service detection,
# OS fingerprinting, and vulnerability checking on a single target.
#
# Usage: sudo ./quick_scan.sh <target_ip>
# Example: sudo ./quick_scan.sh 10.0.2.4

set -euo pipefail

TARGET="${1:?Usage: sudo $0 <target_ip>}"

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script requires root privileges."
    echo "Usage: sudo $0 <target_ip>"
    exit 1
fi

if ! command -v nmap &> /dev/null; then
    echo "Error: nmap is not installed. Install with: sudo apt install nmap"
    exit 1
fi

echo "========================================"
echo "  Quick Scan: $TARGET"
echo "========================================"
echo "  Start time: $(date)"
echo ""

# Step 1: Fast port scan
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[1/4] Top 100 ports (SYN scan)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
nmap -sS --top-ports 100 -T4 "$TARGET" --open
echo ""

# Extract open ports for targeted scanning
OPEN_PORTS=$(nmap -sS --top-ports 100 -T4 "$TARGET" --open \
  -oG - 2>/dev/null | grep "Ports:" | grep -oP '\d+/open' | cut -d'/' -f1 | \
  tr '\n' ',' | sed 's/,$//')

if [ -z "$OPEN_PORTS" ]; then
    echo "No open ports found in top 100. Try a full scan with: sudo nmap -sS -p- $TARGET"
    exit 0
fi

echo "Open ports found: $OPEN_PORTS"
echo ""

# Step 2: Service versions
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[2/4] Service version detection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
nmap -sV -p "$OPEN_PORTS" "$TARGET"
echo ""

# Step 3: OS detection
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[3/4] OS fingerprinting"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
nmap -O --osscan-guess "$TARGET"
echo ""

# Step 4: Quick vulnerability check
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[4/4] Vulnerability check (NSE vuln scripts)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
nmap --script vuln -p "$OPEN_PORTS" "$TARGET"
echo ""

echo "========================================"
echo "  Quick Scan Complete"
echo "========================================"
echo "  End time: $(date)"
echo ""
echo "  For a more thorough assessment, use:"
echo "  sudo ./network_scan.sh $TARGET ./results"
echo "========================================"
