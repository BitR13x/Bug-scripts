#!/bin/bash

# Port scanning module for CTF environments

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# Quick port scan for common CTF ports
quick_scan() {
    local target=$1
    local output_file="$SCAN_DIR/nmap/quick_scan.txt"
    local xml_file="$SCAN_DIR/nmap/quick_scan.xml"
    
    log "INFO" "Running quick port scan on $target..."
    log "INFO" "Output will be saved to: $output_file"
    start_timer
    
    # Ensure directory exists
    if [[ ! -d "$SCAN_DIR/nmap" ]]; then
        mkdir -p "$SCAN_DIR/nmap"
        log "INFO" "Created nmap directory: $SCAN_DIR/nmap"
    fi
    
    # Run nmap scan
    if nmap -sS -T4 -sV --min-rate 1000 -p "$COMMON_PORTS" \
         --open --reason \
         -oN "$output_file" \
         -oX "$xml_file" \
         "$target" 2>/dev/null; then
        
        if [[ -f "$output_file" ]]; then
            local open_ports=$(grep "^[0-9]" "$output_file" | grep "open" | wc -l)
            log "SUCCESS" "Quick scan completed - found $open_ports open ports"
            
            # Extract and log open ports
            grep "^[0-9]" "$output_file" | grep "open" | while read line; do
                local port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
                local service=$(echo "$line" | awk '{print $3}')
                log "FINDING" "Port $port ($service) is open"
            done
        else
            log "ERROR" "Nmap output file not created: $output_file"
            return 1
        fi
    else
        log "ERROR" "Nmap scan failed for target $target"
        return 1
    fi
    
    end_timer "Quick port scan"
}

# Full port scan (for thorough enumeration)
full_scan() {
    local target=$1
    local output_file="$SCAN_DIR/nmap/full_scan.txt"
    local xml_file="$SCAN_DIR/nmap/full_scan.xml"
    
    log "INFO" "Running full port scan on $target (this may take a while)..."
    start_timer
    
    # Ensure directory exists
    if [[ ! -d "$SCAN_DIR/nmap" ]]; then
        mkdir -p "$SCAN_DIR/nmap"
    fi
    
    if nmap -sS -T4 --min-rate 1000 -p- \
         --open --reason \
         -oN "$output_file" \
         -oX "$xml_file" \
         "$target" 2>/dev/null; then
        
        if [[ -f "$output_file" ]]; then
            local open_ports=$(grep "^[0-9]" "$output_file" | grep "open" | wc -l)
            log "SUCCESS" "Full scan completed - found $open_ports open ports"
        else
            log "ERROR" "Full scan output file not created"
            return 1
        fi
    else
        log "ERROR" "Full port scan failed"
        return 1
    fi
    
    end_timer "Full port scan"
}

# Service and version detection
service_scan() {
    local target=$1
    local ports=$2
    local output_file="$SCAN_DIR/nmap/service_scan.txt"
    local xml_file="$SCAN_DIR/nmap/service_scan.xml"
    
    log "INFO" "Running service detection on ports: $ports"
    start_timer
    
    # Ensure directory exists
    if [[ ! -d "$SCAN_DIR/nmap" ]]; then
        mkdir -p "$SCAN_DIR/nmap"
    fi
    
    if nmap -sS -sV -sC -T4 \
         -p "$ports" \
         --script=default,vuln \
         --script-timeout=30s \
         -oN "$output_file" \
         -oX "$xml_file" \
         "$target" 2>/dev/null; then
        
        if [[ -f "$output_file" ]]; then
            log "SUCCESS" "Service detection completed"
            
            # Extract service information
            extract_service_info "$output_file" "$target"
            
            # Look for vulnerabilities
            if grep -q "VULNERABLE" "$output_file"; then
                log "FINDING" "Potential vulnerabilities found in service scan!"
                grep "VULNERABLE" "$output_file" | while read vuln; do
                    log "FINDING" "Vulnerability: $vuln"
                done
            fi
        else
            log "ERROR" "Service scan output file not created"
            return 1
        fi
    else
        log "ERROR" "Service detection failed"
        return 1
    fi
    
    end_timer "Service detection"
}

# UDP scan for common CTF services
udp_scan() {
    local target=$1
    local output_file="$SCAN_DIR/nmap/udp_scan.txt"
    
    log "INFO" "Running UDP scan on common ports..."
    start_timer
    
    # Ensure directory exists
    if [[ ! -d "$SCAN_DIR/nmap" ]]; then
        mkdir -p "$SCAN_DIR/nmap"
    fi
    
    # Common UDP ports in CTF
    local udp_ports="53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353"
    
    if nmap -sU -T4 --min-rate 1000 \
         -p "$udp_ports" \
         --open \
         -oN "$output_file" \
         "$target" 2>/dev/null; then
        
        if [[ -f "$output_file" ]]; then
            local open_ports=$(grep "^[0-9]" "$output_file" | grep "open" | wc -l)
            if [[ $open_ports -gt 0 ]]; then
                log "SUCCESS" "UDP scan found $open_ports open ports"
            else
                log "INFO" "No open UDP ports found"
            fi
        else
            log "WARN" "UDP scan output file not created"
        fi
    else
        log "WARN" "UDP scan failed or no results"
    fi
    
    end_timer "UDP scan"
}

# Extract service information from nmap output
extract_service_info() {
    local nmap_file=$1
    local target=$2
    
    # Parse nmap output for services
    while IFS= read -r line; do
        if [[ $line =~ ^([0-9]+)/tcp.*open.*([a-zA-Z0-9-]+) ]]; then
            local port="${BASH_REMATCH[1]}"
            local service="${BASH_REMATCH[2]}"
            
            # Extract version if available
            local version=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?')
            
            add_finding "$service" "$port" "Service detected: $service${version:+ version $version}"
            suggest_exploits "$service" "$version" "$port"
        fi
    done < "$nmap_file"
    
    # Extract additional information
    extract_info "$(cat "$nmap_file")" "nmap scan"
}

# Get open ports from scan results
get_open_ports() {
    local scan_file=$1
    
    if [[ -f "$scan_file" ]]; then
        grep "^[0-9]" "$scan_file" | grep "open" | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//'
    fi
}

# Targeted port scan based on CTF platform
platform_specific_scan() {
    local target=$1
    local platform=$2
    
    case $platform in
        "HackTheBox")
            log "INFO" "Running HackTheBox-optimized scan..."
            # HTB often has web services, SSH, and Windows services
            local htb_ports="21,22,23,25,53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389"
            nmap -sS -T4 --min-rate 2000 -p "$htb_ports" --open "$target" \
                -oN "$SCAN_DIR/nmap/htb_scan.txt" 2>/dev/null
            ;;
        "TryHackMe")
            log "INFO" "Running TryHackMe-optimized scan..."
            # THM often has web services, SSH, and various CTF services
            local thm_ports="21,22,80,139,443,445,3389,8080,8000,9999,10000"
            nmap -sS -T4 --min-rate 2000 -p "$thm_ports" --open "$target" \
                -oN "$SCAN_DIR/nmap/thm_scan.txt" 2>/dev/null
            ;;
        *)
            log "INFO" "Running generic CTF scan..."
            quick_scan "$target"
            ;;
    esac
}

# Aggressive scan with all NSE scripts
aggressive_scan() {
    local target=$1
    local ports=$2
    local output_file="$SCAN_DIR/nmap/aggressive_scan.txt"
    
    log "INFO" "Running aggressive scan with all scripts..."
    start_timer
    
    nmap -A -T4 --min-rate 1000 \
         -p "$ports" \
         --script=all \
         --script-timeout=60s \
         -oN "$output_file" \
         -oX "$SCAN_DIR/nmap/aggressive_scan.xml" \
         "$target" 2>/dev/null
    
    if [[ -f "$output_file" ]]; then
        extract_info "$(cat "$output_file")" "aggressive scan"
    fi
    
    end_timer "Aggressive scan"
}

# Main port scanning function
run_port_scan() {
    local target=$1
    local scan_type=${2:-"quick"}
    
    log "INFO" "Starting port scanning phase for $target"
    
    # Detect platform for optimized scanning
    local platform=$(detect_platform "$target")
    log "INFO" "Detected platform: $platform"
    
    case $scan_type in
        "quick")
            quick_scan "$target"
            ;;
        "full")
            full_scan "$target"
            ;;
        "platform")
            platform_specific_scan "$target" "$platform"
            ;;
        "all")
            quick_scan "$target"
            local quick_ports=$(get_open_ports "$SCAN_DIR/nmap/quick_scan.txt")
            
            if [[ -n "$quick_ports" ]]; then
                service_scan "$target" "$quick_ports"
                udp_scan "$target"
                
                if [[ "$AGGRESSIVE_MODE" == "true" ]]; then
                    aggressive_scan "$target" "$quick_ports"
                fi
            fi
            
            # Run full scan in background if requested
            if [[ "$platform" == "HackTheBox" ]]; then
                log "INFO" "Starting background full scan for HTB..."
                full_scan "$target" &
            fi
            ;;
    esac
    
    # Generate port scan summary
    generate_port_summary "$target"
}

# Generate port scan summary
generate_port_summary() {
    local target=$1
    local summary_file="$SCAN_DIR/port_summary.txt"
    
    echo "Port Scan Summary for $target" > "$summary_file"
    echo "================================" >> "$summary_file"
    echo "Scan Date: $(date)" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Combine all scan results
    for scan_file in "$SCAN_DIR/nmap"/*.txt; do
        if [[ -f "$scan_file" ]]; then
            echo "=== $(basename "$scan_file") ===" >> "$summary_file"
            grep "^[0-9]" "$scan_file" | grep "open" >> "$summary_file" 2>/dev/null
            echo "" >> "$summary_file"
        fi
    done
    
    log "SUCCESS" "Port scan summary saved to $summary_file"
}
