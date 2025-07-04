#!/bin/bash

# Color test script for CTF-Recon

# Source the configuration and utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../utils.sh"

echo "Testing CTF-Recon color system..."
echo ""

# Initialize colors
init_colors

# Test basic colors
echo "=== Basic Colors ==="
echo -e "${RED}Red text${RESET}"
echo -e "${GREEN}Green text${RESET}"
echo -e "${YELLOW}Yellow text${RESET}"
echo -e "${BLUE}Blue text${RESET}"
echo -e "${PURPLE}Purple text${RESET}"
echo -e "${CYAN}Cyan text${RESET}"
echo -e "${WHITE}White text${RESET}"
echo ""

# Test logging functions
echo "=== Logging Functions ==="
LOG_FILE="/tmp/test.log"
FINDINGS_FILE="/tmp/findings.txt"

log "SUCCESS" "This is a success message"
log "INFO" "This is an info message"
log "WARN" "This is a warning message"
log "ERROR" "This is an error message"
log "FINDING" "This is a finding message"
log "FLAG" "This is a flag message"
echo ""

# Test banner
echo "=== Banner Test ==="
print_banner
echo ""

# Test progress indicator
echo "=== Progress Test ==="
for i in {1..5}; do
    show_progress $i 5 "Testing"
    sleep 0.5
done
echo ""

# Test color variables
echo "=== Color Variable Test ==="
echo "RED variable: '$RED'"
echo "GREEN variable: '$GREEN'"
echo "RESET variable: '$RESET'"
echo ""

# Test terminal detection
echo "=== Terminal Detection ==="
if [[ -t 1 ]]; then
    echo "Terminal supports colors: YES"
else
    echo "Terminal supports colors: NO"
fi

# Test tput availability
echo ""
echo "=== Tput Availability ==="
if command -v tput &>/dev/null; then
    echo "tput command: AVAILABLE"
    echo "tput colors: $(tput colors 2>/dev/null || echo 'unknown')"
else
    echo "tput command: NOT AVAILABLE"
fi

echo ""
echo "Color test completed!"

# Cleanup
rm -f /tmp/test.log /tmp/findings.txt
