#!/bin/bash

# Utility functions for CTF-Recon

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

# Initialize colors (call this early in the script)
init_colors() {
    # Force color initialization
    if [[ -z "$RED" ]]; then
        export RED=$(tput setaf 1 2>/dev/null || echo '\033[0;31m')
        export GREEN=$(tput setaf 2 2>/dev/null || echo '\033[0;32m')
        export YELLOW=$(tput setaf 3 2>/dev/null || echo '\033[1;33m')
        export BLUE=$(tput setaf 4 2>/dev/null || echo '\033[0;34m')
        export PURPLE=$(tput setaf 5 2>/dev/null || echo '\033[0;35m')
        export CYAN=$(tput setaf 6 2>/dev/null || echo '\033[0;36m')
        export WHITE=$(tput setaf 7 2>/dev/null || echo '\033[1;37m')
        export RESET=$(tput sgr0 2>/dev/null || echo '\033[0m')
        export BOLD=$(tput bold 2>/dev/null || echo '\033[1m')
    fi
}

# Color test function
test_colors() {
    echo "Testing color output:"
    echo -e "${RED}Red text${RESET}"
    echo -e "${GREEN}Green text${RESET}"
    echo -e "${YELLOW}Yellow text${RESET}"
    echo -e "${BLUE}Blue text${RESET}"
    echo -e "${PURPLE}Purple text${RESET}"
    echo -e "${CYAN}Cyan text${RESET}"
    echo -e "${WHITE}White text${RESET}"
    echo -e "${BOLD}Bold text${RESET}"
    echo "Color test complete"
}

# Logging with CTF-specific formatting
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%H:%M:%S')
    
    case $level in
        "SUCCESS")
            echo -e "[$timestamp] [${GREEN}✓${RESET}] $message" | tee -a "$LOG_FILE"
            ;;
        "INFO")
            echo -e "[$timestamp] [${BLUE}i${RESET}] $message" | tee -a "$LOG_FILE"
            ;;
        "WARN")
            echo -e "[$timestamp] [${YELLOW}!${RESET}] $message" | tee -a "$LOG_FILE"
            ;;
        "ERROR")
            echo -e "[$timestamp] [${RED}✗${RESET}] $message" | tee -a "$LOG_FILE"
            ;;
        "FINDING")
            echo -e "[$timestamp] [${PURPLE}★${RESET}] $message" | tee -a "$LOG_FILE"
            echo "$message" >> "$FINDINGS_FILE"
            ;;
        "FLAG")
            echo -e "[$timestamp] [${CYAN}🚩${RESET}] $message" | tee -a "$LOG_FILE"
            echo "FLAG FOUND: $message" >> "$FINDINGS_FILE"
            ;;
    esac
}

# CTF-specific progress indicator
show_progress() {
    local current=$1
    local total=$2
    local task=${3:-"Scanning"}
    local percent=$((current * 100 / total))
    
    printf "\r${CYAN}[%s]${RESET} %s: %d%% (%d/%d)" "$(date '+%H:%M:%S')" "$task" $percent $current $total
    
    if [ $current -eq $total ]; then
        echo ""
    fi
}

# Validate IP address (CTF targets are usually IPs)
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        log "ERROR" "Invalid IP address format: $ip"
        return 1
    fi
}

# Detect CTF platform based on IP range
detect_platform() {
    local target=$1
    
    if [[ $target =~ ^10\.10\.1[01]\. ]]; then
        echo "HackTheBox"
    elif [[ $target =~ ^10\.10\. ]]; then
        echo "TryHackMe"
    elif [[ $target =~ ^10\.129\. ]]; then
        echo "HackTheBox"
    else
        echo "Unknown"
    fi
}

# Check if target is alive
check_target_alive() {
    local target=$1
    
    log "INFO" "Checking if target $target is alive..."
    
    if ping -c 1 -W 2 "$target" &>/dev/null; then
        log "SUCCESS" "Target $target is alive"
        return 0
    else
        log "WARN" "Target $target may be down or blocking ping"
        return 1
    fi
}

# Create scan directory structure
setup_scan_dir() {
    local target=$1
    # Clean timestamp without any potential color codes
    local clean_timestamp
    clean_timestamp=$(date +%Y%m%d_%H%M%S)
    local scan_dir="$OUTPUT_DIR/${target}_${clean_timestamp}"
    
    # Create all necessary directories
    mkdir -p "$scan_dir"/{nmap,web,services,exploits,notes}
    
    # Verify directories were created
    for dir in nmap web services exploits notes; do
        if [[ ! -d "$scan_dir/$dir" ]]; then
            echo "ERROR: Failed to create directory $scan_dir/$dir"
            return 1
        fi
    done
    
    # Create initial files
    touch "$scan_dir/notes.md" 2>/dev/null
    touch "$scan_dir/findings.txt" 2>/dev/null
    
    # Set global variables FIRST before any logging
    SCAN_DIR="$scan_dir"
    LOG_FILE="$scan_dir/ctf-recon.log"
    FINDINGS_FILE="$scan_dir/findings.txt"
    NOTES_FILE="$scan_dir/notes.md"
    
    # Initialize log file
    echo "CTF-Recon Log - $(date)" > "$LOG_FILE"
    echo "Target: $target" >> "$LOG_FILE"
    echo "Scan Directory: $scan_dir" >> "$LOG_FILE"
    echo "===========================================" >> "$LOG_FILE"
    
    # Now we can safely use the log function
    log "INFO" "Scan directory created: $scan_dir"
    log "INFO" "Directory structure verified"
}

# Add finding to notes
add_finding() {
    local service=$1
    local port=$2
    local finding=$3
    
    echo "## $service (Port $port)" >> "$NOTES_FILE"
    echo "- $finding" >> "$NOTES_FILE"
    echo "" >> "$NOTES_FILE"
    
    log "FINDING" "$service:$port - $finding"
}

# Search for flags in content
search_flags() {
    local content=$1
    local source=${2:-"unknown"}
    
    if echo "$content" | grep -Eo "$FLAG_PATTERNS" &>/dev/null; then
        local flags=$(echo "$content" | grep -Eo "$FLAG_PATTERNS")
        while IFS= read -r flag; do
            if [[ -n "$flag" ]]; then
                log "FLAG" "Found flag in $source: $flag"
            fi
        done <<< "$flags"
    fi
}

# Extract interesting information from text
extract_info() {
    local text=$1
    local source=${2:-"scan"}
    
    # Look for usernames
    local users=$(echo "$text" | grep -Eio '\b[a-z][a-z0-9_-]{2,15}\b' | sort -u | head -10)
    if [[ -n "$users" ]]; then
        log "FINDING" "Potential usernames found in $source: $(echo $users | tr '\n' ' ')"
    fi
    
    # Look for passwords/hashes
    if echo "$text" | grep -Eiq 'password|passwd|pwd|hash'; then
        log "FINDING" "Password-related content found in $source"
    fi
    
    # Look for version information
    local versions=$(echo "$text" | grep -Eio '[a-z]+[[:space:]]*[0-9]+\.[0-9]+(\.[0-9]+)?' | head -5)
    if [[ -n "$versions" ]]; then
        log "FINDING" "Version information in $source: $(echo $versions | tr '\n' ' ')"
    fi
    
    # Search for flags
    search_flags "$text" "$source"
}

# Check if port is open
is_port_open() {
    local target=$1
    local port=$2
    
    timeout 3 bash -c "</dev/tcp/$target/$port" &>/dev/null
    return $?
}

# Get service name from port
get_service_name() {
    local port=$1
    
    case $port in
        21) echo "FTP" ;;
        22) echo "SSH" ;;
        23) echo "Telnet" ;;
        25) echo "SMTP" ;;
        53) echo "DNS" ;;
        80) echo "HTTP" ;;
        110) echo "POP3" ;;
        135) echo "RPC" ;;
        139|445) echo "SMB" ;;
        143) echo "IMAP" ;;
        443) echo "HTTPS" ;;
        993) echo "IMAPS" ;;
        995) echo "POP3S" ;;
        1433) echo "MSSQL" ;;
        3306) echo "MySQL" ;;
        3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;;
        5900) echo "VNC" ;;
        *) echo "Unknown" ;;
    esac
}

# Generate exploit suggestions
suggest_exploits() {
    local service=$1
    local version=$2
    local port=$3
    
    log "INFO" "Searching for exploits for $service $version"
    
    # Common CTF exploits
    case $service in
        "SSH")
            if [[ $version =~ "OpenSSH" ]]; then
                log "FINDING" "SSH service detected - try user enumeration, weak passwords, or SSH key attacks"
            fi
            ;;
        "FTP")
            log "FINDING" "FTP service detected - check for anonymous login, directory traversal, or file upload"
            ;;
        "HTTP"|"HTTPS")
            log "FINDING" "Web service detected - run web enumeration, check for common vulnerabilities"
            ;;
        "SMB")
            log "FINDING" "SMB service detected - check for null sessions, share enumeration, or SMB vulnerabilities"
            ;;
        "MySQL"|"PostgreSQL"|"MSSQL")
            log "FINDING" "Database service detected - check for default credentials or SQL injection"
            ;;
    esac
}

# Clean up on exit
cleanup() {
    log "INFO" "Cleaning up..."
    
    # Kill any background processes
    # jobs -p | xargs -r kill &>/dev/null
    log "INFO" "jobs running:"
    jobs -p
    
    # Compress scan results
    if [[ -n "$SCAN_DIR" && -d "$SCAN_DIR" ]]; then
        tar -czf "${SCAN_DIR}.tar.gz" -C "$(dirname "$SCAN_DIR")" "$(basename "$SCAN_DIR")" 2>/dev/null
        log "INFO" "Scan results compressed to ${SCAN_DIR}.tar.gz"
    fi
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Banner for CTF tools
print_banner() {
    # Initialize colors first
    init_colors
    
    # Check if terminal supports colors
    if [[ -t 1 ]]; then
        echo -e "${CYAN}"
        echo "  ╔═══════════════════════════════════════════════════════════════╗"
        echo "  ║                        CTF-Recon v1.0                        ║"
        echo "  ║              HackTheBox & TryHackMe Specialized Tool          ║"
        echo "  ║                                                               ║"
        echo "  ║  Fast • Lightweight • CTF-Optimized • Auto-Enumeration       ║"
        echo "  ╚═══════════════════════════════════════════════════════════════╝"
        echo -e "${RESET}"
    else
        echo "CTF-Recon v1.0 - HackTheBox & TryHackMe Specialized Tool"
        echo "Fast • Lightweight • CTF-Optimized • Auto-Enumeration"
        echo ""
    fi
}

# Check CTF-specific dependencies
check_ctf_dependencies() {
    local tools=("nmap" "ffuf" "nikto" "whatweb" "smbclient" "enum4linux")
    local missing=()
    
    log "INFO" "Checking CTF tool dependencies..."
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "WARN" "Missing tools: ${missing[*]}"
        log "INFO" "Install with: sudo apt install ${missing[*]}"
        return 1
    fi
    
    log "SUCCESS" "All required tools are available"
    return 0
}

# Timer functions
start_timer() {
    TIMER_START=$SECONDS
}

end_timer() {
    local task=${1:-"Task"}
    local duration=$((SECONDS - TIMER_START))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    log "SUCCESS" "$task completed in ${minutes}m ${seconds}s"
}

# URL encoding for web requests
url_encode() {
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o
    
    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="${c}" ;;
            * ) printf -v o '%%%02x' "'$c" ;;
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}

# Generate wordlist combinations for CTF
generate_ctf_wordlist() {
    local target=$1
    local custom_wordlist="$SCAN_DIR/custom_wordlist.txt"

    # Common CTF directories and files
    cat > "$custom_wordlist" << 'EOF'
admin
administrator
backup
config
database
db
dev
development
flag
flags
hidden
private
secret
test
tmp
upload
uploads
user
users
www
api
assets
css
js
images
img
files
docs
documentation
login
panel
dashboard
phpmyadmin
mysql
sql
backup.sql
config.php
database.sql
flag.txt
user.txt
root.txt
proof.txt
.htaccess
.htpasswd
robots.txt
sitemap.xml
crossdomain.xml
EOF
    
    # Add target-specific words
    echo "$target" >> "$custom_wordlist"
    echo "${target%%.*}" >> "$custom_wordlist"
    
    log "INFO" "Generated custom CTF wordlist: $custom_wordlist"
    wordlist="$custom_wordlist"
}
