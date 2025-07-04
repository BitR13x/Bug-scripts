#!/bin/bash

# Script for changing download source

# Usage function
usage() {
    echo "Usage: $0 -f file -o output -ip 10.10.10.10 -p 9999"
}

log() {
    local LEVEL="$1"
    local MSG="$2"
    echo "[$LEVEL] $MSG"
}

validate_args() {
    local VALID=1

    # Validate FILE
    if [[ -z "$FILE" ]]; then
        log "ERROR" "Missing required argument: --file"
        VALID=0
    elif [[ ! -f "$FILE" ]]; then
        log "ERROR" "File does not exist: $FILE"
        VALID=0
    fi

    # Validate OUTPUT
    if [[ -z "$OUTPUT" ]]; then
        log "ERROR" "Missing required argument: --output"
        VALID=0
    fi

    # Validate IP
    if [[ -z "$IP" ]]; then
        log "ERROR" "Missing required argument: --ip"
        VALID=0
    elif ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        log "ERROR" "Invalid IP address: $IP"
        VALID=0
    fi

    # Validate PORT
    if [[ -z "$PORT" ]]; then
        log "ERROR" "Missing required argument: --port"
        VALID=0
    elif ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
        log "ERROR" "Invalid port number: $PORT"
        VALID=0
    fi

    # Final check
    if [[ $VALID -eq 0 ]]; then
        usage
        exit 1
    fi
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--file)
                FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT="$2"
                shift 2
                ;;
            -ip|--ip)
                IP="$2"
                shift 2
                ;;
            -p|--port)
                PORT="$2"
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

main() {
    parse_arguments "$@"
    validate_args

    cat $FILE | sed -E "s|https://(github\.com\|raw\.githubusercontent\.com)/.*/(.*)$|http://$IP:$PORT/\2|" > $OUTPUT
}

# CTRL+C
trap 'echo -e "\nInterrupted by user"; cleanup; exit 130' INT

main "$@"

