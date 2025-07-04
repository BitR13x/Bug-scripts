#!/bin/bash

# Utility functions for AutoRecon

# Source configuration
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

# Logging functions with timestamps
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "DEBUG")
            [[ "$LOG_LEVEL" == "DEBUG" ]] && echo "[$timestamp] [DEBUG] $message" | tee -a "$LOG_FILE"
            ;;
        "INFO")
            [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && echo "[$timestamp] [${GREEN}INFO${RESET}] $message" | tee -a "$LOG_FILE"
            ;;
        "WARN")
            [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO|WARN)$ ]] && echo "[$timestamp] [${YELLOW}WARN${RESET}] $message" | tee -a "$LOG_FILE"
            ;;
        "ERROR")
            echo "[$timestamp] [${RED}ERROR${RESET}] $message" | tee -a "$LOG_FILE"
            ;;
    esac
}

# Progress tracking function
show_progress() {
    local current=$1
    local total=$2
    local task_name=${3:-"Processing"}
    local percent=$((current * 100 / total))
    local bar_length=50
    local filled_length=$((percent * bar_length / 100))
    
    printf "\r${task_name}: ["
    printf "%*s" $filled_length | tr ' ' '='
    printf "%*s" $((bar_length - filled_length)) | tr ' ' '-'
    printf "] %d%% (%d/%d)" $percent $current $total
    
    if [ $current -eq $total ]; then
        echo ""
    fi
}

# Input validation functions
validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        log "ERROR" "Invalid domain format: $domain"
        return 1
    fi
    return 0
}

validate_ip() {
    local ip=$1
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log "ERROR" "Invalid IP format: $ip"
        return 1
    fi
    return 0
}

# Dependency checking
check_dependencies() {
    local tools=("crobat" "amass" "subfinder" "assetfinder" "httpx" "nuclei" "gowitness" "gau" "waybackurls" "shuffledns" "dnsgen" "ffuf" "dalfox" "naabu")
    local missing_tools=()
    
    log "INFO" "Checking tool dependencies..."
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
            log "WARN" "Missing tool: $tool"
        else
            log "DEBUG" "Found tool: $tool"
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log "ERROR" "Missing required tools: ${missing_tools[*]}"
        log "INFO" "Please install missing tools before running AutoRecon"
        return 1
    fi
    
    log "INFO" "All dependencies satisfied"
    return 0
}

# File operations with error handling
safe_mkdir() {
    local dir=$1
    if ! mkdir -p "$dir" 2>/dev/null; then
        log "ERROR" "Failed to create directory: $dir"
        return 1
    fi
    log "DEBUG" "Created directory: $dir"
    return 0
}

safe_touch() {
    local file=$1
    if ! touch "$file" 2>/dev/null; then
        log "ERROR" "Failed to create file: $file"
        return 1
    fi
    log "DEBUG" "Created file: $file"
    return 0
}

# Notification system
notify_user() {
    local message=$1
    local level=${2:-"INFO"}
    
    # Log the message
    log "$level" "$message"
    
    # Send notification if enabled
    if [[ "$ENABLE_NOTIFICATIONS" == "true" ]]; then
        if command -v notify &> /dev/null; then
            echo "$message" | notify -silent
        fi
        
        # Discord webhook notification (if configured)
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            send_discord_notification "$message"
        fi
    fi
}

send_discord_notification() {
    local message=$1
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        curl -H "Content-Type: application/json" \
             -X POST \
             -d "{\"content\":\"$message\"}" \
             "$DISCORD_WEBHOOK" &> /dev/null
    fi
}

# Performance monitoring
start_timer() {
    TIMER_START=$SECONDS
}

end_timer() {
    local task_name=${1:-"Task"}
    local duration=$((SECONDS - TIMER_START))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    log "INFO" "$task_name completed in ${minutes}m ${seconds}s"
    notify_user "$task_name completed in ${minutes}m ${seconds}s"
}

# Cleanup functions
cleanup_temp_files() {
    local scan_dir=$1
    local temp_files=("temp.txt" "tmp.txt" "cleantemp.txt" "cnames.txt" "xss_raw_result.txt")
    
    for file in "${temp_files[@]}"; do
        if [[ -f "$scan_dir/$file" ]]; then
            rm "$scan_dir/$file" 2>/dev/null
            log "DEBUG" "Cleaned up temp file: $file"
        fi
    done
}

# Rate limiting helper
rate_limit() {
    local max_rate=${1:-$REQUEST_PER_SEC}
    sleep $(echo "scale=2; 1/$max_rate" | bc -l)
}

# File size checker
check_file_size() {
    local file=$1
    local max_size_mb=${2:-100}  # Default 100MB
    
    if [[ -f "$file" ]]; then
        local size_mb=$(du -m "$file" | cut -f1)
        if [[ $size_mb -gt $max_size_mb ]]; then
            log "WARN" "File $file is large (${size_mb}MB), consider splitting"
            return 1
        fi
    fi
    return 0
}

# Parallel processing helper
run_parallel() {
    local max_jobs=${1:-$MAX_THREADS}
    local command_file=$2
    
    if [[ -f "$command_file" ]]; then
        cat "$command_file" | xargs -I {} -P "$max_jobs" bash -c '{}'
    fi
}

# Error handling
handle_error() {
    local exit_code=$1
    local line_number=$2
    local command=$3
    
    log "ERROR" "Command failed with exit code $exit_code at line $line_number: $command"
    cleanup_on_exit
    exit $exit_code
}

# Trap handler for cleanup
cleanup_on_exit() {
    log "INFO" "Cleaning up on exit..."
    
    # Kill background processes
    if [[ -n "$SERVER_PID" ]]; then
        kill -9 "$SERVER_PID" &> /dev/null || true
        log "INFO" "Killed listen server (PID: $SERVER_PID)"
    fi
    
    # Clean up temp files
    if [[ -n "$SCAN_DIR" ]]; then
        cleanup_temp_files "$SCAN_DIR"
    fi
    
    log "INFO" "Cleanup completed"
}

# Set up error handling
set -eE
trap 'handle_error $? $LINENO "$BASH_COMMAND"' ERR
trap cleanup_on_exit EXIT INT TERM
