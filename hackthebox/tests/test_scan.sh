#!/bin/bash

# Test script to verify CTF-Recon functionality

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../utils.sh"
source "$SCRIPT_DIR/../port_scan.sh"

echo "CTF-Recon Test Script"
echo "===================="
echo ""

# Initialize colors
init_colors

# Test target (using localhost for testing)
TARGET="127.0.0.1"

log "INFO" "Testing CTF-Recon functionality with target: $TARGET"

# Test directory creation
log "INFO" "Testing directory creation..."
SCAN_DIR=$(setup_scan_dir "$TARGET")

if [[ -d "$SCAN_DIR" ]]; then
    log "SUCCESS" "Main scan directory created: $SCAN_DIR"
else
    log "ERROR" "Failed to create main scan directory"
    exit 1
fi

# Check subdirectories
for dir in nmap web services exploits notes; do
    if [[ -d "$SCAN_DIR/$dir" ]]; then
        log "SUCCESS" "Subdirectory created: $dir"
    else
        log "ERROR" "Failed to create subdirectory: $dir"
    fi
done

# Test nmap scan (quick test on localhost)
log "INFO" "Testing nmap scan functionality..."

# Create a simple test to verify nmap works
if command -v nmap &>/dev/null; then
    log "SUCCESS" "nmap command is available"
    
    # Test basic nmap functionality
    if nmap -sn "$TARGET" &>/dev/null; then
        log "SUCCESS" "nmap can reach target"
    else
        log "WARN" "nmap cannot reach target (this is normal for localhost)"
    fi
    
    # Test file creation
    test_output="$SCAN_DIR/nmap/test_scan.txt"
    if nmap -p 22,80,443 --open "$TARGET" -oN "$test_output" 2>/dev/null; then
        if [[ -f "$test_output" ]]; then
            log "SUCCESS" "nmap output file created successfully"
            log "INFO" "Output file size: $(wc -l < "$test_output") lines"
        else
            log "ERROR" "nmap output file was not created"
        fi
    else
        log "WARN" "nmap scan failed (this may be normal for localhost)"
    fi
else
    log "ERROR" "nmap command not found"
fi

# Test file permissions
log "INFO" "Testing file permissions..."
if [[ -w "$SCAN_DIR" ]]; then
    log "SUCCESS" "Scan directory is writable"
else
    log "ERROR" "Scan directory is not writable"
fi

# Test log file creation
if [[ -f "$LOG_FILE" ]]; then
    log "SUCCESS" "Log file created: $LOG_FILE"
else
    log "ERROR" "Log file not created"
fi

# Test findings file
if [[ -f "$FINDINGS_FILE" ]]; then
    log "SUCCESS" "Findings file created: $FINDINGS_FILE"
else
    log "ERROR" "Findings file not created"
fi

echo ""
log "SUCCESS" "Test completed. Check the scan directory: $SCAN_DIR"
echo ""
echo "Directory structure:"
find "$SCAN_DIR" -type d | sort
echo ""
echo "Files created:"
find "$SCAN_DIR" -type f | sort

# Cleanup option
echo ""
read -p "Remove test directory? [y/N]: " cleanup
if [[ $cleanup =~ ^[Yy] ]]; then
    rm -rf "$SCAN_DIR"
    log "INFO" "Test directory cleaned up"
fi
