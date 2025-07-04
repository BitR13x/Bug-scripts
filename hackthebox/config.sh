#!/bin/bash

# CTF-Recon Configuration for HackTheBox/TryHackMe
# Optimized for CTF environments and single targets

# Tool paths (adjust according to your system)
export NMAP_PATH="/usr/bin/nmap"
export GOBUSTER_PATH="/usr/bin/gobuster"
export FFUF_PATH="/usr/bin/ffuf"
export NIKTO_PATH="/usr/bin/nikto"
export ENUM4LINUX_PATH="/usr/bin/enum4linux"
export SMBCLIENT_PATH="/usr/bin/smbclient"
export WHATWEB_PATH="/usr/bin/whatweb"

# Wordlists (common CTF wordlists)
export COMMON_WORDLIST="/usr/share/wordlists/dirb/common.txt"
export BIG_WORDLIST="/usr/share/wordlists/dirb/big.txt"
export SECLISTS_DIR="/usr/share/seclists"
export ROCKYOU_WORDLIST="/usr/share/wordlists/rockyou.txt"

# CTF-specific wordlists
export CTF_DIRS="$SECLISTS_DIR/Discovery/Web-Content/common.txt"
export CTF_FILES="$SECLISTS_DIR/Discovery/Web-Content/raft-medium-files.txt"
export CTF_SUBDOMAINS="$SECLISTS_DIR/Discovery/DNS/subdomains-top1million-5000.txt"

# Scanning parameters (optimized for CTF speed)
export NMAP_THREADS=100
export GOBUSTER_THREADS=50
export FFUF_THREADS=40
export SCAN_DELAY=0
export TIMEOUT=30

# Port ranges
export COMMON_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,6000,6001,6002,6003,6004,6005,6006,6007,6008,6009"
export FULL_PORT_RANGE="1-65535"
export TOP_PORTS="1000"

# Output configuration
export OUTPUT_DIR="./ctf-scans"
export NOTES_FILE="notes.md"
export FINDINGS_FILE="findings.txt"

# Colors for output (using tput for better compatibility)
export RED=$(tput setaf 1 2>/dev/null || echo '\033[0;31m')
export GREEN=$(tput setaf 2 2>/dev/null || echo '\033[0;32m')
export YELLOW=$(tput setaf 3 2>/dev/null || echo '\033[1;33m')
export BLUE=$(tput setaf 4 2>/dev/null || echo '\033[0;34m')
export PURPLE=$(tput setaf 5 2>/dev/null || echo '\033[0;35m')
export CYAN=$(tput setaf 6 2>/dev/null || echo '\033[0;36m')
export WHITE=$(tput setaf 7 2>/dev/null || echo '\033[1;37m')
export RESET=$(tput sgr0 2>/dev/null || echo '\033[0m')

# Bold colors
export BOLD=$(tput bold 2>/dev/null || echo '\033[1m')
export DIM=$(tput dim 2>/dev/null || echo '\033[2m')

# CTF platform detection
export HACKTHEBOX_RANGE="10.10.10.0/24,10.10.11.0/24,10.129.0.0/16"
export TRYHACKME_RANGE="10.10.0.0/16"

# Stealth settings (for CTF environments)
export STEALTH_MODE=false
export AGGRESSIVE_MODE=true
export SKIP_PING=true

# Service enumeration settings
export ENUM_SMB=true
export ENUM_FTP=true
export ENUM_SSH=true
export ENUM_HTTP=true
export ENUM_HTTPS=true
export ENUM_DNS=true
export ENUM_SNMP=true
export ENUM_LDAP=true

# Web enumeration settings
export SPIDER_DEPTH=3
export INCLUDE_EXTENSIONS="php,html,txt,js,css,xml,json,bak,old,backup,zip,tar,gz"
export EXCLUDE_EXTENSIONS="png,jpg,jpeg,gif,ico,svg,woff,woff2,ttf,eot"

# Vulnerability scanning
export ENABLE_VULN_SCAN=true
export ENABLE_EXPLOIT_SEARCH=true
export ENABLE_CVE_SEARCH=true

# Logging
export LOG_LEVEL="INFO"
export ENABLE_VERBOSE=false
export LOG_FILE="ctf-recon.log"

# CTF-specific flags and hints
export SEARCH_FLAGS=true
export FLAG_PATTERNS="flag{.*}|FLAG{.*}|HTB{.*}|THM{.*}|ctf{.*}|CTF{.*}"
export COMMON_PATHS="/flag,/flag.txt,/root.txt,/user.txt,/proof.txt"

# Notification settings
export ENABLE_NOTIFICATIONS=false
export DISCORD_WEBHOOK=""

# Auto-exploitation settings (use with caution)
export AUTO_EXPLOIT=false
export METASPLOIT_PATH="/usr/bin/msfconsole"
