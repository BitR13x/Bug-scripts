#!/bin/bash

# Demo script for CTF-Recon

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../utils.sh"

echo "CTF-Recon Demo - Color and Functionality Test"
echo "=============================================="
echo ""

# Initialize colors
init_colors

# Test banner
print_banner

# Test logging with colors
echo "Testing logging functions:"
log "INFO" "Starting CTF-Recon demo"
log "SUCCESS" "Colors are working properly"
log "WARN" "This is a warning message"
log "ERROR" "This is an error message (don't worry, it's just a test)"
log "FINDING" "Found an interesting service on port 80"
log "FLAG" "flag{demo_flag_found}"

echo ""
echo "Testing progress indicator:"
for i in {1..10}; do
    show_progress $i 10 "Demo Progress"
    sleep 0.2
done

echo ""
echo "Testing platform detection:"
echo "10.10.10.100 -> $(detect_platform "10.10.10.100")"
echo "10.10.50.100 -> $(detect_platform "10.10.50.100")"
echo "192.168.1.100 -> $(detect_platform "192.168.1.100")"

echo ""
echo -e "${GREEN}Demo completed successfully!${RESET}"
echo -e "${CYAN}The CTF-Recon tool is ready to use.${RESET}"
echo ""
echo "Try running:"
echo -e "${YELLOW}./ctf-recon.sh -t <target_ip>${RESET}"
echo ""
