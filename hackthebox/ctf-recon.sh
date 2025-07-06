#!/bin/bash

# CTF-Recon - Specialized reconnaissance tool for HackTheBox and TryHackMe
# Lightweight, fast, and CTF-optimized

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source modules
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/utils.sh"
source "$SCRIPT_DIR/port_scan.sh"
source "$SCRIPT_DIR/service_enum.sh"
source "$SCRIPT_DIR/exploit_search.sh"
source "$SCRIPT_DIR/report_gen.sh"

# Global variables
TARGET=""
SCAN_TYPE="quick"
ENABLE_EXPLOITS=false
ENABLE_WEB_SCAN=false
ENABLE_FULL_SCAN=false
CUSTOM_PORTS=""

# Usage function
usage() {
    cat << EOF
CTF-Recon v1.0 - HackTheBox & TryHackMe Specialized Tool

Usage: $0 -t TARGET [options]

Required:
    -t, --target IP         Target IP address

Scan Types:
    -q, --quick            Quick scan (common ports) [default]
    -f, --full             Full port scan (1-65535)
    -p, --ports PORTS      Custom port range (e.g., 80,443,8080)
    -a, --all              All scans (quick + services + exploits)

Options:
    -e, --exploits         Enable exploit search and vulnerability assessment
    -w, --web              Enable web application scanning
    -s, --stealth          Enable stealth mode (slower but quieter)
    -A, --aggressive       Aggressive mode (faster, more threads)
    -o, --output DIR       Custom output directory
    --platform PLATFORM    Force platform detection (htb/thm)
    --timeout SECONDS      Set timeout for operations (default: 30)
    -v, --verbose          Enable verbose output
    -n, --nuclei           Enable nuclei scans
    -h, --help             Show this help

Examples:
    $0 -t 10.10.10.100                    # Quick scan
    $0 -t 10.10.10.100 -a                 # Full reconnaissance
    $0 -t 10.10.10.100 -e -w              # Quick scan with exploits and web
    $0 -t 10.10.10.100 -f -A              # Full aggressive scan
    $0 -t 10.10.10.100 -p 80,443,8080     # Custom ports

CTF-Optimized Features:
    🎯 Platform detection (HTB/THM)
    🚀 Fast scanning with CTF-specific ports
    🔍 Automatic service enumeration
    💥 Exploit suggestions and Metasploit commands
    📝 CTF-style reporting with findings
    🚩 Flag detection in responses
    🛠️ Default credential testing

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -q|--quick)
                SCAN_TYPE="quick"
                shift
                ;;
            -n|--nuclei)
                ALLOW_NUCLEI="nuclei"
                shift
                ;;
            -f|--full)
                SCAN_TYPE="full"
                ENABLE_FULL_SCAN=true
                shift
                ;;
            -p|--ports)
                CUSTOM_PORTS="$2"
                SCAN_TYPE="custom"
                shift 2
                ;;
            -a|--all)
                SCAN_TYPE="all"
                ENABLE_EXPLOITS=true
                ENABLE_WEB_SCAN=true
                shift
                ;;
            -e|--exploits)
                ENABLE_EXPLOITS=true
                shift
                ;;
            -w|--web)
                ENABLE_WEB_SCAN=true
                shift
                ;;
            -s|--stealth)
                STEALTH_MODE=true
                AGGRESSIVE_MODE=false
                NMAP_THREADS=10
                GOBUSTER_THREADS=10
                shift
                ;;
            -A|--aggressive)
                AGGRESSIVE_MODE=true
                STEALTH_MODE=false
                NMAP_THREADS=200
                GOBUSTER_THREADS=100
                shift
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --platform)
                FORCE_PLATFORM="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -v|--verbose)
                ENABLE_VERBOSE=true
                LOG_LEVEL="DEBUG"
                shift
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
    if [[ -z "$TARGET" ]]; then
        log "ERROR" "Target IP is required. Use -t or --target"
        usage
        exit 1
    fi
    
    if ! validate_ip "$TARGET"; then
        exit 1
    fi
}

# Setup scan environment
setup_environment() {
    log "INFO" "Setting up scan environment for $TARGET"
    
    # Create scan directory
    setup_scan_dir "$TARGET"

    # Detect platform
    local platform=${FORCE_PLATFORM:-$(detect_platform "$TARGET")}
    PLATFORM="$platform"
    
    log "INFO" "Detected platform: $platform"
    log "INFO" "Scan directory: $SCAN_DIR"
    
    # Adjust settings based on platform
    case $platform in
        "HackTheBox")
            # HTB often has more complex services
            TIMEOUT=60
            ;;
        "TryHackMe")
            # THM is usually more straightforward
            TIMEOUT=30
            ;;
    esac
}

# Main scanning pipeline
run_ctf_pipeline() {
    local target=$1
    
    log "INFO" "Starting CTF reconnaissance pipeline for $target"
    print_scan_info
    
    # Phase 1: Port Scanning
    log "INFO" "Phase 1: Port Discovery"
    case $SCAN_TYPE in
        "quick")
            run_port_scan "$target" "quick"
            ;;
        "full")
            run_port_scan "$target" "full"
            ;;
        "custom")
            # Custom port scan
            log "INFO" "Running custom port scan on ports: $CUSTOM_PORTS"
            nmap -sS -T4 --min-rate 1000 -p "$CUSTOM_PORTS" --open \
                 -oN "$SCAN_DIR/nmap/custom_scan.txt" "$target" 2>/dev/null
            ;;
        "all")
            run_port_scan "$target" "all"
            ;;
        "platform")
            run_port_scan "$target" "platform"
            ;;
        *)
            run_port_scan "$target" "quick"
            ;;
    esac
    
    # Phase 2: Service Enumeration
    log "INFO" "Phase 2: Service Enumeration"
    run_service_enumeration "$target"
    
    # Phase 3: Vulnerability Scanning (if enabled)
    if [[ "$ALLOW_NUCLEI" == "true" ]]; then
        log "INFO" "Phase 3: Vulnerability Scanning"
        run_nuclei_scan "$target"
    fi
    
    # Phase 4: Exploit Search (if enabled)
    if [[ "$ENABLE_EXPLOITS" == "true" ]]; then
        log "INFO" "Phase 4: Exploit Search & Assessment"
        run_exploit_search "$target"
    fi
    
    # Phase 5: Report Generation
    log "INFO" "Phase 5: Report Generation"
    generate_ctf_reports "$target" "$PLATFORM"
    
    log "SUCCESS" "CTF reconnaissance pipeline completed!"
}

# Print scan information
print_scan_info() {
    init_colors  # Ensure colors are initialized
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║                    SCAN CONFIGURATION                        ║${RESET}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${CYAN}║${RESET} Target: ${WHITE}$TARGET${RESET}"
    echo -e "${CYAN}║${RESET} Platform: ${WHITE}$PLATFORM${RESET}"
    echo -e "${CYAN}║${RESET} Scan Type: ${WHITE}$SCAN_TYPE${RESET}"
    echo -e "${CYAN}║${RESET} Exploits: ${WHITE}$([ "$ENABLE_EXPLOITS" == "true" ] && echo "Enabled" || echo "Disabled")${RESET}"
    echo -e "${CYAN}║${RESET} Web Scan: ${WHITE}$([ "$ENABLE_WEB_SCAN" == "true" ] && echo "Enabled" || echo "Disabled")${RESET}"
    echo -e "${CYAN}║${RESET} Mode: ${WHITE}$([ "$AGGRESSIVE_MODE" == "true" ] && echo "Aggressive" || echo "Normal")${RESET}"
    echo -e "${CYAN}║${RESET} Output: ${WHITE}$SCAN_DIR${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# Print final summary
print_final_summary() {
    local target=$1
    local start_time=$2
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    init_colors  # Ensure colors are initialized
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║                    SCAN COMPLETED                            ║${RESET}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${GREEN}║${RESET} Target: ${BLUE}$target${RESET}"
    echo -e "${GREEN}║${RESET} Duration: ${BLUE}${minutes}m ${seconds}s${RESET}"
    echo -e "${GREEN}║${RESET} Platform: ${BLUE}$PLATFORM${RESET}"
    echo -e "${GREEN}║${RESET}"
    
    # Statistics
    local open_ports=$(grep -c "open" "$SCAN_DIR/nmap/quick_scan.txt" 2>/dev/null || echo "0")
    local findings=$(wc -l < "$FINDINGS_FILE" 2>/dev/null || echo "0")
    local exploits=$(find "$SCAN_DIR/exploits" -name "*.rc" 2>/dev/null | wc -l)
    
    echo -e "${GREEN}║${RESET} Results:"
    echo -e "${GREEN}║${RESET}   • Open Ports: ${YELLOW}$open_ports${RESET}"
    echo -e "${GREEN}║${RESET}   • Findings: ${YELLOW}$findings${RESET}"
    echo -e "${GREEN}║${RESET}   • Exploit Scripts: ${YELLOW}$exploits${RESET}"
    echo -e "${GREEN}║${RESET}"
    echo -e "${GREEN}║${RESET} Reports Generated:"
    echo -e "${GREEN}║${RESET}   • HTML Report: ${BLUE}$SCAN_DIR/ctf_report.html${RESET}"
    echo -e "${GREEN}║${RESET}   - ${BLUE}file://$(realpath $SCAN_DIR/ctf_report.html)${RESET}"
    echo -e "${GREEN}║${RESET}   • Markdown Notes: ${BLUE}$SCAN_DIR/ctf_notes.md${RESET}"
    echo -e "${GREEN}║${RESET}   • Text Summary: ${BLUE}$SCAN_DIR/summary.txt${RESET}"
    
    if [[ $exploits -gt 0 ]]; then
        echo -e "${GREEN}║${RESET}"
        echo -e "${GREEN}║${RESET} Quick Start Commands:"
        echo -e "${GREEN}║${RESET}   ${BLUE}cd $SCAN_DIR/exploits${RESET}"
        echo -e "${GREEN}║${RESET}   ${BLUE}msfconsole -r *.rc${RESET}"
    fi
    
    # Check for flags
    if [[ -f "$FINDINGS_FILE" ]] && grep -q "FLAG" "$FINDINGS_FILE"; then
        echo -e "${GREEN}║${RESET}"
        echo -e "${GREEN}║${RESET} ${CYAN}🚩 FLAGS DETECTED! Check the findings section.${RESET}"
    fi
    
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${WHITE}Next Steps:${RESET}"
    echo -e "1. Open ${BLUE}$SCAN_DIR/ctf_report.html${RESET} in your browser"
    echo -e "2. Review findings and exploit opportunities"
    echo -e "3. Test default credentials on identified services"
    echo -e "4. Perform manual testing based on discoveries"
    echo ""
}

# Quick start function for common CTF scenarios
quick_start() {
    local target=$1
    
    log "INFO" "Running CTF quick start for $target"
    
    # Quick port scan
    run_port_scan "$target" "quick"
    
    # Basic service enumeration
    run_service_enumeration "$target"
    
    # Generate basic report
    generate_text_summary "$target"
    
    log "SUCCESS" "Quick start completed. Check $SCAN_DIR/summary.txt"
}

# Interactive mode
interactive_mode() {
    echo "${CYAN}Welcome to CTF-Recon Interactive Mode!${RESET}"
    echo ""
    
    # Get target
    read -p "Enter target IP: " TARGET
    if ! validate_ip "$TARGET"; then
        log "ERROR" "Invalid IP address"
        exit 1
    fi
    
    # Get scan type
    echo ""
    echo "Select scan type:"
    echo "1) Quick scan (recommended)"
    echo "2) Full scan"
    echo "3) All scans (comprehensive)"
    echo "4) Custom ports"
    read -p "Choice [1-4]: " choice
    
    case $choice in
        1) SCAN_TYPE="quick" ;;
        2) SCAN_TYPE="full"; ENABLE_FULL_SCAN=true ;;
        3) SCAN_TYPE="all"; ENABLE_EXPLOITS=true; ENABLE_WEB_SCAN=true ;;
        4) 
            read -p "Enter ports (e.g., 80,443,8080): " CUSTOM_PORTS
            SCAN_TYPE="custom"
            ;;
        *) SCAN_TYPE="quick" ;;
    esac
    
    # Additional options
    echo ""
    read -p "Enable exploit search? [y/N]: " enable_exploits
    if [[ $enable_exploits =~ ^[Yy] ]]; then
        ENABLE_EXPLOITS=true
    fi
    
    read -p "Enable aggressive mode? [y/N]: " aggressive
    if [[ $aggressive =~ ^[Yy] ]]; then
        AGGRESSIVE_MODE=true
    fi
    
    echo ""
    log "INFO" "Starting scan with selected options..."
}

# Main function
main() {
    local start_time=$(date +%s)
    
    # Initialize colors first
    init_colors
    
    # Print banner
    print_banner
    
    # Handle special cases
    if [[ $# -eq 0 ]]; then
        interactive_mode
    elif [[ $1 == "--quick-start" && -n $2 ]]; then
        TARGET="$2"
        validate_ip "$TARGET" || exit 1
        setup_environment
        quick_start "$TARGET"
        exit 0
    else
        # Parse arguments
        parse_arguments "$@"
        validate_arguments
    fi
    
    # Check dependencies
    if ! check_ctf_dependencies; then
        exit 1
    fi
    
    # Setup environment
    setup_environment
    
    # Check if target is alive
    if ! check_target_alive "$TARGET"; then
        read -p "Target may be down. Continue anyway? [y/N]: " continue_scan
        if [[ ! $continue_scan =~ ^[Yy] ]]; then
            log "INFO" "Scan cancelled by user"
            exit 0
        fi
    fi
    
    # Run the main pipeline
    if run_ctf_pipeline "$TARGET"; then
        print_final_summary "$TARGET" "$start_time"
        exit 0
    else
        log "ERROR" "Scan pipeline failed"
        exit 1
    fi
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Scan interrupted by user${RESET}"; cleanup; exit 130' INT

# Run main function with all arguments
main "$@"
