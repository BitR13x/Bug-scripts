#!/bin/bash

# AutoRecon - Enhanced Automated Reconnaissance Tool
# Version 2.0

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source modules
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/utils.sh"
source "$SCRIPT_DIR/subdomain_enum.sh"
source "$SCRIPT_DIR/web_enum.sh"
source "$SCRIPT_DIR/vulnerability_scan.sh"
source "$SCRIPT_DIR/report_generator.sh"

# Global variables
DOMAIN=""
SCAN_DIR=""
ENABLE_ALT=false
ENABLE_BRUTE=false
ENABLE_VULN_SCAN=""

# Usage function
usage() {
    cat << EOF
AutoRecon v2.0 - Enhanced Automated Reconnaissance Tool

Usage: $0 -d domain.com [options]

Required:
    -d, --domain DOMAIN     Target domain to scan

Options:
    -a, --alt              Enable subdomain permutation with dnsgen
    -b, --brute            Enable directory bruteforcing
    -v, --vuln TYPES       Enable vulnerability scanning (comma-separated)
                          Types: nuclei,ssrf,xss,cors,prototype,sqli,port
    -o, --output DIR       Custom output directory (default: ./scans)
    -t, --threads NUM      Number of threads (default: $MAX_THREADS)
    -r, --rate NUM         Requests per second (default: $REQUEST_PER_SEC)
    --verbose              Enable verbose logging
    --config FILE          Use custom config file
    -h, --help             Show this help message

Examples:
    $0 -d example.com
    $0 -d example.com -a -b
    $0 -d example.com -v nuclei,xss,ssrf
    $0 -d example.com -a -v nuclei,xss,cors,sqli -o /tmp/scans

Vulnerability Scan Types:
    nuclei      - Comprehensive vulnerability scanner
    ssrf        - Server-Side Request Forgery testing
    xss         - Cross-Site Scripting testing
    cors        - CORS misconfiguration testing
    prototype   - Prototype pollution testing
    sqli        - Basic SQL injection testing
    port        - Port scanning

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -a|--alt)
                ENABLE_ALT=true
                shift
                ;;
            -b|--brute)
                ENABLE_BRUTE=true
                shift
                ;;
            -v|--vuln)
                ENABLE_VULN_SCAN="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -t|--threads)
                MAX_THREADS="$2"
                shift 2
                ;;
            -r|--rate)
                REQUEST_PER_SEC="$2"
                shift 2
                ;;
            --verbose)
                ENABLE_VERBOSE=true
                LOG_LEVEL="DEBUG"
                shift
                ;;
            --config)
                if [[ -f "$2" ]]; then
                    source "$2"
                else
                    log "ERROR" "Config file not found: $2"
                    exit 1
                fi
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Validate arguments
validate_arguments() {
    if [[ -z "$DOMAIN" ]]; then
        log "ERROR" "Domain is required. Use -d or --domain"
        usage
        exit 1
    fi
    
    if ! validate_domain "$DOMAIN"; then
        exit 1
    fi
    
    # Validate vulnerability scan types
    if [[ -n "$ENABLE_VULN_SCAN" ]]; then
        local valid_types=("nuclei" "ssrf" "xss" "cors" "prototype" "sqli" "port")
        IFS=',' read -ra SCAN_TYPES <<< "$ENABLE_VULN_SCAN"
        
        for scan_type in "${SCAN_TYPES[@]}"; do
            if [[ ! " ${valid_types[@]} " =~ " ${scan_type} " ]]; then
                log "ERROR" "Invalid vulnerability scan type: $scan_type"
                log "INFO" "Valid types: ${valid_types[*]}"
                exit 1
            fi
        done
    fi
}

# Setup scan environment
setup_scan_environment() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    SCAN_DIR="$OUTPUT_DIR/$DOMAIN/$timestamp"
    
    log "INFO" "Setting up scan environment for $DOMAIN"
    
    # Create directory structure
    safe_mkdir "$SCAN_DIR"
    safe_mkdir "$SCAN_DIR/$BACKUP_DIR"
    safe_mkdir "$SCAN_DIR/$REPORTS_DIR"
    safe_mkdir "$SCAN_DIR/$SCREENSHOTS_DIR"
    
    # Create required files
    local required_files=(
        "$DOMAIN.txt"
        "shuffledns.txt"
        "subdomain_live.txt"
        "gau_output.txt"
        "interesting.txt"
        "nuclei.txt"
        "xss_results.txt"
        "cors_results.txt"
        "prototype_pollution_results.txt"
        "technologies.txt"
        "port_scan.txt"
    )
    
    for file in "${required_files[@]}"; do
        safe_touch "$SCAN_DIR/$file"
    done
    
    # Initialize log file
    LOG_FILE="$SCAN_DIR/autorecon.log"
    log "INFO" "Scan directory created: $SCAN_DIR"
    log "INFO" "Log file: $LOG_FILE"
}

# Main scanning pipeline
run_scan_pipeline() {
    local domain=$1
    local scan_dir=$2
    
    log "INFO" "Starting AutoRecon pipeline for $domain"
    start_timer
    
    # Phase 1: Subdomain Enumeration
    log "INFO" "Phase 1: Subdomain Enumeration"
    if ! run_subdomain_enumeration "$domain" "$scan_dir" "$ENABLE_ALT"; then
        log "ERROR" "Subdomain enumeration failed"
        return 1
    fi
    
    # Phase 2: Web Service Enumeration
    log "INFO" "Phase 2: Web Service Enumeration"
    if ! run_web_enumeration "$domain" "$scan_dir" "$ENABLE_BRUTE"; then
        log "WARN" "Web enumeration had issues, continuing..."
    fi
    
    # Phase 3: Vulnerability Scanning (if enabled)
    if [[ -n "$ENABLE_VULN_SCAN" ]]; then
        log "INFO" "Phase 3: Vulnerability Scanning"
        if ! run_vulnerability_scan "$domain" "$scan_dir" "$ENABLE_VULN_SCAN"; then
            log "WARN" "Vulnerability scanning had issues, continuing..."
        fi
    fi
    
    # Phase 4: Report Generation
    log "INFO" "Phase 4: Report Generation"
    generate_reports "$domain" "$scan_dir"
    
    end_timer "Complete AutoRecon pipeline"
}

# Print scan summary
print_scan_summary() {
    local domain=$1
    local scan_dir=$2
    
    echo ""
    echo "${GREEN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo "${GREEN}║                    AUTORECON SCAN COMPLETE                   ║${RESET}"
    echo "${GREEN}╠══════════════════════════════════════════════════════════════╣${RESET}"
    echo "${GREEN}║${RESET} Target Domain: ${BLUE}$domain${RESET}"
    echo "${GREEN}║${RESET} Scan Directory: ${BLUE}$scan_dir${RESET}"
    echo "${GREEN}║${RESET} Total Runtime: ${BLUE}$((SECONDS / 60))m $((SECONDS % 60))s${RESET}"
    echo "${GREEN}║${RESET}"
    
    # Statistics
    local subdomains=$(wc -l < "$scan_dir/$domain.txt" 2>/dev/null || echo "0")
    local live_hosts=$(wc -l < "$scan_dir/subdomain_live.txt" 2>/dev/null || echo "0")
    local vulnerabilities=$(wc -l < "$scan_dir/nuclei.txt" 2>/dev/null || echo "0")
    
    echo "${GREEN}║${RESET} Results Summary:"
    echo "${GREEN}║${RESET}   • Subdomains Found: ${YELLOW}$subdomains${RESET}"
    echo "${GREEN}║${RESET}   • Live Web Services: ${YELLOW}$live_hosts${RESET}"
    echo "${GREEN}║${RESET}   • Vulnerabilities: ${YELLOW}$vulnerabilities${RESET}"
    echo "${GREEN}║${RESET}"
    echo "${GREEN}║${RESET} Generated Reports:"
    echo "${GREEN}║${RESET}   • HTML Report: ${BLUE}$scan_dir/html_report.html${RESET}"
    echo "${GREEN}║${RESET}   • JSON Report: ${BLUE}$scan_dir/report.json${RESET}"
    echo "${GREEN}║${RESET}   • Scan Summary: ${BLUE}$scan_dir/scan_summary.txt${RESET}"
    
    if [[ -d "$scan_dir/$SCREENSHOTS_DIR" ]]; then
        echo "${GREEN}║${RESET}   • Screenshots: ${BLUE}$scan_dir/$SCREENSHOTS_DIR/${RESET}"
        echo "${GREEN}║${RESET}"
        echo "${GREEN}║${RESET} Start Screenshot Server:"
        echo "${GREEN}║${RESET}   ${BLUE}cd $scan_dir && gowitness server -a $SERVER_IP:$SCREENSHOT_PORT${RESET}"
    fi
    
    echo "${GREEN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# Main function
main() {
    # Print banner
    echo "${GREEN}"
    echo "  ╔═══════════════════════════════════════════════════════════════╗"
    echo "  ║                        AutoRecon v2.0                        ║"
    echo "  ║              Enhanced Automated Reconnaissance Tool           ║"
    echo "  ║                                                               ║"
    echo "  ║  Features: Subdomain Enum • Web Discovery • Vuln Scanning    ║"
    echo "  ║           Screenshots • Smart Reporting • Rate Limiting       ║"
    echo "  ╚═══════════════════════════════════════════════════════════════╝"
    echo "${RESET}"
    
    # Check if no arguments provided
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi
    
    # Parse arguments
    parse_arguments "$@"
    
    # Validate arguments
    validate_arguments
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Setup scan environment
    setup_scan_environment
    
    # Start scan
    log "INFO" "Starting AutoRecon scan for $DOMAIN"
    notify_user "AutoRecon scan started for $DOMAIN"
    
    # Run the main scanning pipeline
    if run_scan_pipeline "$DOMAIN" "$SCAN_DIR"; then
        print_scan_summary "$DOMAIN" "$SCAN_DIR"
        notify_user "AutoRecon scan completed successfully for $DOMAIN"
        
        # Optional: Start Discord notification if configured
        if [[ -f "$SCRIPT_DIR/../discordBot.py" ]]; then
            python3 "$SCRIPT_DIR/../discordBot.py" "$DOMAIN" "$(basename "$SCAN_DIR")" 2>/dev/null || true
        fi
        
        exit 0
    else
        log "ERROR" "Scan pipeline failed"
        notify_user "AutoRecon scan failed for $DOMAIN" "ERROR"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
