#!/bin/bash

# Subdomain enumeration module

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# Download required wordlists and resolvers
download_resources() {
    local scan_dir=$1
    
    log "INFO" "Downloading required resources..."
    
    # Download resolvers
    if ! wget -q https://raw.githubusercontent.com/kh4sh3i/Fresh-Resolvers/master/resolvers.txt -O "$scan_dir/resolvers.txt"; then
        log "WARN" "Failed to download resolvers, using system default"
        echo "8.8.8.8" > "$scan_dir/resolvers.txt"
    fi
    
    # Download DNS wordlist
    if ! wget -q https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -O "$scan_dir/dns_wordlist.txt"; then
        log "WARN" "Failed to download DNS wordlist"
    fi
    
    log "INFO" "Resource download completed"
}

# Passive subdomain enumeration
passive_subdomain_enum() {
    local domain=$1
    local scan_dir=$2
    local output_file="$scan_dir/$domain.txt"
    
    log "INFO" "Starting passive subdomain enumeration for $domain"
    start_timer
    
    # Initialize output file
    > "$output_file"
    
    # Crobat enumeration
    log "INFO" "Running crobat enumeration..."
    if command -v crobat &> /dev/null; then
        crobat -s "$domain" >> "$output_file" 2>/dev/null || log "WARN" "Crobat failed"
        show_progress 1 4 "Passive enum"
    fi
    
    # Subfinder enumeration
    log "INFO" "Running subfinder enumeration..."
    if command -v subfinder &> /dev/null; then
        subfinder -silent -d "$domain" -all >> "$output_file" 2>/dev/null || log "WARN" "Subfinder failed"
        show_progress 2 4 "Passive enum"
    fi
    
    # Assetfinder enumeration
    log "INFO" "Running assetfinder enumeration..."
    if command -v assetfinder &> /dev/null; then
        assetfinder -subs-only "$domain" >> "$output_file" 2>/dev/null || log "WARN" "Assetfinder failed"
        show_progress 3 4 "Passive enum"
    fi
    
    # Amass enumeration
    log "INFO" "Running amass enumeration..."
    if command -v amass &> /dev/null; then
        timeout 300 amass enum -passive -d "$domain" >> "$output_file" 2>/dev/null || log "WARN" "Amass failed or timed out"
        show_progress 4 4 "Passive enum"
    fi
    
    # Clean and deduplicate results
    if [[ -f "$output_file" ]]; then
        sort -u "$output_file" > "$output_file.tmp" && mv "$output_file.tmp" "$output_file"
        local count=$(wc -l < "$output_file")
        log "INFO" "Found $count unique subdomains"
    fi
    
    end_timer "Passive subdomain enumeration"
}

# Certificate transparency search
search_crtsh() {
    local domain=$1
    local scan_dir=$2
    
    log "INFO" "Searching certificate transparency logs..."
    
    if [[ -f "$MASSDNS_PATH/scripts/ct.py" ]] && [[ -f "$MASSDNS_PATH/bin/massdns" ]]; then
        python3 "$MASSDNS_PATH/scripts/ct.py" "$domain" 2>/dev/null > "$scan_dir/tmp.txt"
        
        if [[ -s "$scan_dir/tmp.txt" ]]; then
            cat "$scan_dir/tmp.txt" | "$MASSDNS_PATH/bin/massdns" \
                -r "$scan_dir/resolvers.txt" \
                -t A -q -o S \
                -w "$scan_dir/crtsh.txt" 2>/dev/null || log "WARN" "MassDNS failed"
        fi
    else
        log "WARN" "MassDNS not found, skipping certificate transparency search"
    fi
}

# DNS permutation
permutate_subdomains() {
    local domain=$1
    local scan_dir=$2
    local input_file="$scan_dir/$domain.txt"
    local output_file="$scan_dir/dnsgen.txt"
    
    log "INFO" "Starting DNS permutation with dnsgen..."
    start_timer
    
    if command -v dnsgen &> /dev/null && [[ -f "$input_file" ]]; then
        cat "$input_file" | dnsgen - | sort -u > "$output_file"
        
        # Merge with original list
        cat "$input_file" "$output_file" | sort -u > "$input_file.tmp"
        mv "$input_file.tmp" "$input_file"
        
        local count=$(wc -l < "$input_file")
        log "INFO" "Generated $count total subdomains after permutation"
    else
        log "WARN" "dnsgen not available, skipping permutation"
    fi
    
    end_timer "DNS permutation"
}

# DNS resolution and validation
dns_resolution() {
    local domain=$1
    local scan_dir=$2
    local input_file="$scan_dir/$domain.txt"
    local output_file="$scan_dir/shuffledns.txt"
    
    log "INFO" "Starting DNS resolution with shuffledns..."
    start_timer
    
    if command -v shuffledns &> /dev/null && [[ -f "$input_file" ]]; then
        cat "$input_file" | sort -u | shuffledns \
            -d "$domain" \
            -silent \
            -r "$scan_dir/resolvers.txt" \
            -o "$output_file" 2>/dev/null || log "WARN" "ShuffleDNS failed"
        
        if [[ -f "$output_file" ]]; then
            local count=$(wc -l < "$output_file")
            log "INFO" "Resolved $count live subdomains"
        fi
    else
        log "WARN" "shuffledns not available, copying input to output"
        cp "$input_file" "$output_file" 2>/dev/null || true
    fi
    
    end_timer "DNS resolution"
}

# Wayback machine data collection
collect_wayback_data() {
    local domain=$1
    local scan_dir=$2
    local wayback_dir="$scan_dir/wayback"
    
    log "INFO" "Collecting wayback machine data..."
    start_timer
    
    safe_mkdir "$wayback_dir"
    safe_mkdir "$wayback_dir/extensions"
    
    # Get wayback URLs
    if [[ -f "$scan_dir/$domain.txt" ]] && command -v waybackurls &> /dev/null; then
        cat "$scan_dir/$domain.txt" | head -100 | while read subdomain; do
            waybackurls "$subdomain" 2>/dev/null || true
        done | sort -u > "$wayback_dir/wayback_output.txt"
        
        # Extract parameters
        grep '?.*=' "$wayback_dir/wayback_output.txt" 2>/dev/null | \
            cut -d '=' -f 1 | sort -u > "$wayback_dir/wayback_params.txt" || true
        
        # Extract file extensions
        extract_file_extensions "$wayback_dir/wayback_output.txt" "$wayback_dir/extensions"
        
        local url_count=$(wc -l < "$wayback_dir/wayback_output.txt" 2>/dev/null || echo "0")
        log "INFO" "Collected $url_count wayback URLs"
    fi
    
    end_timer "Wayback data collection"
}

# Extract different file extensions from wayback data
extract_file_extensions() {
    local input_file=$1
    local output_dir=$2
    
    local extensions=("js" "html" "json" "php" "aspx" "ts" "txt" "md" "xml" "yaml" "yml")
    
    for ext in "${extensions[@]}"; do
        grep "\.$ext\(\?.*\)\?$" "$input_file" 2>/dev/null | \
            sort -u > "$output_dir/$ext.txt" || true
    done
}

# Main subdomain enumeration function
run_subdomain_enumeration() {
    local domain=$1
    local scan_dir=$2
    local enable_permutation=${3:-false}
    
    log "INFO" "Starting comprehensive subdomain enumeration for $domain"
    
    # Validate domain
    if ! validate_domain "$domain"; then
        return 1
    fi
    
    # Download resources
    download_resources "$scan_dir"
    
    # Run passive enumeration
    passive_subdomain_enum "$domain" "$scan_dir"
    
    # Search certificate transparency
    search_crtsh "$domain" "$scan_dir"
    
    # Run permutation if enabled
    if [[ "$enable_permutation" == "true" ]]; then
        permutate_subdomains "$domain" "$scan_dir"
    fi
    
    # Resolve subdomains
    dns_resolution "$domain" "$scan_dir"
    
    # Collect wayback data
    collect_wayback_data "$domain" "$scan_dir"
    
    log "INFO" "Subdomain enumeration completed for $domain"
    return 0
}
