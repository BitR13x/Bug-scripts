#!/bin/bash

# Web enumeration module

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# HTTP probe for live web services
http_probe() {
    local domain=$1
    local scan_dir=$2
    local input_file="$scan_dir/shuffledns.txt"
    local output_file="$scan_dir/subdomain_live.txt"
    
    log "INFO" "Starting HTTP probing..."
    start_timer
    
    if [[ -f "$input_file" ]] && command -v httpx &> /dev/null; then
        cat "$input_file" | httpx \
            -silent \
            -no-color \
            -random-agent \
            -ports "$HTTPX_PORTS" \
            -threads "$HTTPX_THREADS" \
            -timeout 10 \
            -retries 2 \
            -rate-limit "$REQUEST_PER_SEC" \
            -o "$output_file" 2>/dev/null || log "WARN" "HTTPx failed"
        
        if [[ -f "$output_file" ]]; then
            local count=$(wc -l < "$output_file")
            log "INFO" "Found $count live web services"
        fi
    else
        log "WARN" "HTTPx not available or input file missing"
        return 1
    fi
    
    end_timer "HTTP probing"
}

# Take screenshots of web services
take_screenshots() {
    local domain=$1
    local scan_dir=$2
    local input_file="$scan_dir/subdomain_live.txt"
    local screenshot_dir="$scan_dir/$SCREENSHOTS_DIR"
    
    log "INFO" "Taking screenshots of web services..."
    start_timer
    
    if [[ -f "$input_file" ]] && command -v gowitness &> /dev/null; then
        safe_mkdir "$screenshot_dir"
        
        gowitness file \
            -f "$input_file" \
            -P "$screenshot_dir/" \
            --delay 3 \
            --timeout 15 \
            --threads 5 \
            -D "$scan_dir/gowitness.sqlite3" 2>/dev/null || log "WARN" "Gowitness failed"
        
        log "INFO" "Screenshots saved to $screenshot_dir"
    else
        log "WARN" "Gowitness not available or no live hosts found"
    fi
    
    end_timer "Screenshot capture"
}

# Collect URLs using GAU
collect_urls() {
    local domain=$1
    local scan_dir=$2
    local input_file="$scan_dir/subdomain_live.txt"
    local output_file="$scan_dir/gau_output.txt"
    
    log "INFO" "Collecting URLs from various sources..."
    start_timer
    
    if [[ -f "$input_file" ]] && command -v gau &> /dev/null; then
        # Limit to first 50 domains to avoid overwhelming the system
        head -50 "$input_file" | gau \
            --blacklist jpg,jpeg,gif,css,js,tif,tiff,png,ttf,woff,woff2,ico,svg,eot \
            --threads 5 \
            --timeout 10 2>/dev/null | \
            qsreplace -a | \
            sort -u > "$output_file" || log "WARN" "GAU collection failed"
        
        if [[ -f "$output_file" ]]; then
            local count=$(wc -l < "$output_file")
            log "INFO" "Collected $count unique URLs"
        fi
    else
        log "WARN" "GAU not available or no live hosts found"
    fi
    
    end_timer "URL collection"
}

# Find interesting endpoints
find_interesting_endpoints() {
    local domain=$1
    local scan_dir=$2
    local input_file="$scan_dir/gau_output.txt"
    local output_file="$scan_dir/interesting.txt"
    
    log "INFO" "Finding interesting endpoints..."
    start_timer
    
    if [[ -f "$input_file" ]] && command -v gf &> /dev/null; then
        cat "$input_file" | \
            gf interestingEXT | \
            grep -viE '(\.(js|css|svg|png|jpg|woff))' | \
            qsreplace -a | \
            head -1000 | \
            httpx -mc 200 -silent -threads 20 | \
            awk '{ print $1}' > "$output_file" 2>/dev/null || log "WARN" "Interesting endpoint search failed"
        
        if [[ -f "$output_file" ]]; then
            local count=$(wc -l < "$output_file")
            log "INFO" "Found $count interesting endpoints"
        fi
    else
        log "WARN" "GF patterns not available or no URLs to process"
    fi
    
    end_timer "Interesting endpoint discovery"
}

# Directory bruteforcing with rate limiting
directory_bruteforce() {
    local domain=$1
    local scan_dir=$2
    local input_file="$scan_dir/subdomain_live.txt"
    local reports_dir="$scan_dir/$REPORTS_DIR"
    
    log "INFO" "Starting directory bruteforce..."
    start_timer
    
    if [[ ! -f "$input_file" ]]; then
        log "WARN" "No live hosts found for directory bruteforce"
        return 1
    fi
    
    safe_mkdir "$reports_dir"
    
    local total_hosts=$(wc -l < "$input_file")
    local current=0
    
    # Limit to first 20 hosts to avoid overwhelming
    head -20 "$input_file" | while read -r host; do
        current=$((current + 1))
        show_progress $current $total_hosts "Directory bruteforce"
        
        local clean_host=$(echo "$host" | sed 's|https\?://||g' | sed 's|:.*||g')
        local output_file="$reports_dir/${clean_host}.txt"
        
        if command -v ffuf &> /dev/null && [[ -f "$DIRSEARCH_WORDLIST" ]]; then
            timeout 300 ffuf \
                -w "$DIRSEARCH_WORDLIST" \
                -u "$host/FUZZ" \
                -ac \
                -mc 200,204,301,302,307,401,403 \
                -s \
                -rate "$REQUEST_PER_SEC" \
                -t 10 \
                -o "$output_file" \
                -of csv 2>/dev/null || log "WARN" "FFUF failed for $host"
        elif command -v feroxbuster &> /dev/null; then
            timeout 300 feroxbuster \
                --url "$host" \
                --wordlist "$DIRSEARCH_WORDLIST" \
                --threads 10 \
                --rate-limit "$REQUEST_PER_SEC" \
                --status-codes 200,204,301,302,307,401,403 \
                --output "$output_file" \
                --quiet 2>/dev/null || log "WARN" "Feroxbuster failed for $host"
        fi
        
        # Rate limiting between hosts
        sleep 2
    done
    
    end_timer "Directory bruteforce"
}

# Parameter discovery
parameter_discovery() {
    local domain=$1
    local scan_dir=$2
    local input_file="$scan_dir/subdomain_live.txt"
    local output_file="$scan_dir/parameters.txt"
    
    log "INFO" "Starting parameter discovery..."
    start_timer
    
    if [[ -f "$input_file" ]] && [[ -f "$PARAMSPIDER" ]]; then
        # Limit to first 10 hosts
        head -10 "$input_file" | while read -r host; do
            python3 "$PARAMSPIDER" -d "$host" --level high --quiet 2>/dev/null || true
        done
        
        # Collect results
        find . -name "*.txt" -path "*/output/*" -exec cat {} \; 2>/dev/null | \
            sort -u > "$output_file" || true
        
        if [[ -f "$output_file" ]]; then
            local count=$(wc -l < "$output_file")
            log "INFO" "Found $count parameter endpoints"
        fi
    else
        log "WARN" "ParamSpider not available"
    fi
    
    end_timer "Parameter discovery"
}

# Technology detection
technology_detection() {
    local domain=$1
    local scan_dir=$2
    local input_file="$scan_dir/subdomain_live.txt"
    local output_file="$scan_dir/technologies.txt"
    
    log "INFO" "Detecting web technologies..."
    start_timer
    
    if [[ -f "$input_file" ]] && command -v httpx &> /dev/null; then
        cat "$input_file" | head -50 | httpx \
            -silent \
            -tech-detect \
            -status-code \
            -content-length \
            -threads 20 \
            -timeout 10 > "$output_file" 2>/dev/null || log "WARN" "Technology detection failed"
        
        if [[ -f "$output_file" ]]; then
            local count=$(wc -l < "$output_file")
            log "INFO" "Analyzed $count hosts for technologies"
        fi
    fi
    
    end_timer "Technology detection"
}

# Main web enumeration function
run_web_enumeration() {
    local domain=$1
    local scan_dir=$2
    local enable_bruteforce=${3:-false}
    
    log "INFO" "Starting web enumeration for $domain"
    
    # HTTP probing
    http_probe "$domain" "$scan_dir"
    
    # Take screenshots
    take_screenshots "$domain" "$scan_dir"
    
    # Collect URLs
    collect_urls "$domain" "$scan_dir"
    
    # Find interesting endpoints
    find_interesting_endpoints "$domain" "$scan_dir"
    
    # Technology detection
    technology_detection "$domain" "$scan_dir"
    
    # Parameter discovery
    parameter_discovery "$domain" "$scan_dir"
    
    # Directory bruteforce (if enabled)
    if [[ "$enable_bruteforce" == "true" ]]; then
        directory_bruteforce "$domain" "$scan_dir"
    fi
    
    log "INFO" "Web enumeration completed for $domain"
    return 0
}
