#!/bin/bash
# network_scan.sh - Automated network assessment workflow
#
# Performs a complete four-phase assessment: discovery, port scanning,
# service detection, and vulnerability checking with structured output.
#
# Usage: sudo ./network_scan.sh <target_subnet> [output_dir]
# Example: sudo ./network_scan.sh 10.0.2.0/24 ./scan_results
# Example: sudo ./network_scan.sh 10.0.2.4 ./scan_results

set -euo pipefail

TARGET="${1:?Usage: sudo $0 <target_or_subnet> [output_dir]}"
OUTPUT_DIR="${2:-./scan_results}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script requires root privileges for SYN scanning and OS detection."
    echo "Usage: sudo $0 <target_or_subnet> [output_dir]"
    exit 1
fi

# Verify nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "Error: nmap is not installed. Install with: sudo apt install nmap"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "========================================"
echo "  Automated Network Assessment"
echo "========================================"
echo "Target:    $TARGET"
echo "Output:    $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
echo "Nmap:      $(nmap --version | head -1)"
echo ""

# Phase 1: Host Discovery
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 1/4] Host Discovery"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Techniques: ARP + ICMP echo + TCP SYN (80,443,22)"
echo ""

nmap -sn -PE -PS80,443,22 "$TARGET" \
  -oN "$OUTPUT_DIR/${TIMESTAMP}_discovery.txt" \
  -oX "$OUTPUT_DIR/${TIMESTAMP}_discovery.xml" 2>/dev/null

LIVE_HOSTS=$(grep -c "Host is up" "$OUTPUT_DIR/${TIMESTAMP}_discovery.txt" || echo "0")
echo "  Result: $LIVE_HOSTS live host(s) discovered."
echo ""

if [ "$LIVE_HOSTS" -eq 0 ]; then
    echo "No live hosts found. Check your target specification and network connectivity."
    exit 0
fi

# Extract live host IPs for subsequent phases
LIVE_IPS=$(grep "Nmap scan report for" "$OUTPUT_DIR/${TIMESTAMP}_discovery.txt" | \
  grep -oP '\d+\.\d+\.\d+\.\d+' | tr '\n' ' ')
echo "  Live hosts: $LIVE_IPS"
echo ""

# Phase 2: Port Scanning
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 2/4] Port Scanning (top 1000 TCP ports)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Technique: TCP SYN scan (-sS)"
echo ""

nmap -sS --top-ports 1000 -T4 $LIVE_IPS \
  -oN "$OUTPUT_DIR/${TIMESTAMP}_ports.txt" \
  -oX "$OUTPUT_DIR/${TIMESTAMP}_ports.xml" 2>/dev/null

OPEN_PORTS=$(grep -c "open" "$OUTPUT_DIR/${TIMESTAMP}_ports.txt" || echo "0")
echo "  Result: $OPEN_PORTS open port(s) found across all hosts."
echo ""

# Phase 3: Service Detection
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 3/4] Service & Version Detection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Techniques: Version probes + default NSE scripts"
echo ""

nmap -sV --version-intensity 5 -sC -O $LIVE_IPS \
  -oN "$OUTPUT_DIR/${TIMESTAMP}_services.txt" \
  -oX "$OUTPUT_DIR/${TIMESTAMP}_services.xml" 2>/dev/null

echo "  Result: Service detection complete."
echo ""

# Phase 4: Vulnerability Scan
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 4/4] NSE Vulnerability Scanning"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Scripts: vuln category"
echo ""

nmap --script vuln $LIVE_IPS \
  -oN "$OUTPUT_DIR/${TIMESTAMP}_vulns.txt" \
  -oX "$OUTPUT_DIR/${TIMESTAMP}_vulns.xml" 2>/dev/null

VULN_COUNT=$(grep -c "VULNERABLE" "$OUTPUT_DIR/${TIMESTAMP}_vulns.txt" || echo "0")
echo "  Result: $VULN_COUNT vulnerability indicator(s) found."
echo ""

# Generate HTML Reports
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Report] Generating HTML reports"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for xml_file in "$OUTPUT_DIR"/${TIMESTAMP}_*.xml; do
    html_file="${xml_file%.xml}.html"
    if command -v xsltproc &> /dev/null; then
        xsltproc "$xml_file" -o "$html_file" 2>/dev/null && \
          echo "  Generated: $(basename "$html_file")"
    fi
done

echo ""
echo "========================================"
echo "  Assessment Complete"
echo "========================================"
echo ""
echo "Summary:"
echo "  Live hosts:      $LIVE_HOSTS"
echo "  Open ports:      $OPEN_PORTS"
echo "  Vulnerabilities: $VULN_COUNT"
echo ""
echo "Output files:"
ls -lh "$OUTPUT_DIR"/${TIMESTAMP}_* 2>/dev/null | awk '{print "  " $NF " (" $5 ")"}'
echo ""
echo "========================================"
