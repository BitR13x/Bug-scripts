#!/bin/bash

# Service enumeration module for CTF environments

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# FTP enumeration
enum_ftp() {
    local target=$1
    local port=${2:-21}

    log "INFO" "Enumerating FTP service on $target:$port"

    local ftp_output
    local output_file="$SCAN_DIR/services/ftp_anonymous.txt"

    # Check for anonymous login
    ftp_output=$(
        timeout 10 ftp -n "$target" 2>/dev/null <<EOF
user anonymous anonymous
ls
quit
EOF
    )

    if grep -q "230" <<<"$ftp_output"; then
        log "FINDING" "FTP anonymous login allowed on $target"

        # List files and save to file
        timeout 30 ftp -n "$target" >"$output_file" 2>/dev/null <<EOF
user anonymous anonymous
ls -la
quit
EOF

        if [[ -s "$output_file" ]]; then
            log "FINDING" "FTP directory listing saved to ftp_anonymous.txt"
            extract_info "$(cat "$output_file")" "FTP anonymous"
        fi
    else
        log "INFO" "FTP anonymous login not allowed on $target"
    fi

    # Banner grabbing
    local banner=$(timeout 5 nc "$target" "$port" <<<"" 2>/dev/null | head -1)
    if [[ -n "$banner" ]]; then
        log "FINDING" "FTP banner: $banner"
        extract_info "$banner" "FTP banner"
    fi
}

# SSH enumeration
enum_ssh() {
    local target=$1
    local port=${2:-22}

    log "INFO" "Enumerating SSH service on $target:$port"

    # Banner grabbing
    local banner=$(timeout 5 nc "$target" "$port" <<<"" 2>/dev/null | head -1)
    if [[ -n "$banner" ]]; then
        log "FINDING" "SSH banner: $banner"
        extract_info "$banner" "SSH banner"
        echo "$banner" > "$SCAN_DIR/services/ssh_info.txt"

        # Check for specific SSH versions with known vulnerabilities
        if echo "$banner" | grep -qi "openssh.*[1-6]\.[0-9]"; then
            log "FINDING" "Potentially vulnerable SSH version detected"
        fi
    fi

    # Check for SSH key algorithms (for potential weaknesses)
    timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$target" -p "$port" 2>&1 |
        grep -E "(kex_exchange_identification|Unable to negotiate)" >> "$SCAN_DIR/services/ssh_info.txt" 2>/dev/null
}

# SMB enumeration
enum_smb() {
    local target=$1
    local port=${2:-445}

    log "INFO" "Enumerating SMB service on $target:$port"

    # SMB version detection
    if command -v smbclient &>/dev/null; then
        # List shares
        smbclient -L "//$target" -N 2>/dev/null >"$SCAN_DIR/services/smb_shares.txt"

        if [[ -s "$SCAN_DIR/services/smb_shares.txt" ]]; then
            log "FINDING" "SMB shares enumerated"

            # Check for accessible shares
            while read -r line; do
                if [[ $line =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+Disk ]]; then
                    local share="${BASH_REMATCH[1]}"
                    log "FINDING" "SMB share found: $share"

                    # Try to access share
                    if smbclient "//$target/$share" -N -c "ls" 2>/dev/null | grep -q "blocks available"; then
                        log "FINDING" "SMB share '$share' is accessible without credentials"
                        smbclient "//$target/$share" -N -c "ls" >"$SCAN_DIR/services/smb_${share}.txt" 2>/dev/null
                    fi
                fi
            done <"$SCAN_DIR/services/smb_shares.txt"
        fi
    fi

    # enum4linux if available
    if command -v enum4linux &>/dev/null; then
        log "INFO" "Running enum4linux..."
        timeout 300 enum4linux -a "$target" >"$SCAN_DIR/services/enum4linux.txt" 2>/dev/null &
    fi

    # SMB null session check
    if command -v rpcclient &>/dev/null; then
        echo "srvinfo" | rpcclient -N "$target" >"$SCAN_DIR/services/smb_null_session.txt" 2>/dev/null
        if [[ -s "$SCAN_DIR/services/smb_null_session.txt" ]]; then
            log "FINDING" "SMB null session may be possible"
        fi
    fi
}

# HTTP/HTTPS enumeration
enum_http() {
    local target=$1
    local port=$2
    local protocol=${3:-http}

    log "INFO" "Enumerating $protocol service on $target:$port"

    # Ensure web directory exists
    if [[ ! -d "$SCAN_DIR/web" ]]; then
        mkdir -p "$SCAN_DIR/web"
        log "INFO" "Created web directory: $SCAN_DIR/web"
    fi

    local base_url="$protocol://$target:$port"

    # Whatweb scan
    if command -v whatweb &>/dev/null; then
        whatweb -a 3 "$base_url" | sed 's/\x1b\[[0-9;]*m//g' >"$SCAN_DIR/web/whatweb_${port}.txt" 2>/dev/null
        if [[ -s "$SCAN_DIR/web/whatweb_${port}.txt" ]]; then
            log "FINDING" "Web technology scan completed for port $port"
            extract_info "$(cat "$SCAN_DIR/web/whatweb_${port}.txt")" "whatweb"
        fi

        # Writing redirect host
        if [[ -s "$SCAN_DIR/web/whatweb_${port}.txt" ]]; then
            redirect_location=$(cat $SCAN_DIR/web/whatweb_${port}.txt | grep -oP 'RedirectLocation\[\K[^\]]+' | sed 's|https\?://||' | sed 's|/$||')

            if [[ -n "$redirect_location" ]]; then
                log "INFO" "Redirect Location: $redirect_location"
                base_url="$protocol://$redirect_location:$port"

            fi

            if grep -q "$target $redirect_location" "/etc/hosts"; then
                echo ""
            else
                echo "$target $redirect_location" | sudo tee -a /etc/hosts >/dev/null
            fi


            whatweb -a 3 "$base_url" | sed 's/\x1b\[[0-9;]*m//g' >"$SCAN_DIR/web/whatweb_${port}_vhost.txt" 2>/dev/null
            if [[ -s "$SCAN_DIR/web/whatweb_${port}_vhost.txt" ]]; then
                log "FINDING" "Web technology scan completed for $redirect_location port $port"
                extract_info "$(cat "$SCAN_DIR/web/whatweb_${port}_vhost.txt")" "whatweb"
            fi
        fi
    fi


    # Nikto scan
    if command -v nikto &>/dev/null; then
        log "INFO" "Running Nikto scan on $base_url..."
        timeout 600 nikto -h "$base_url" 2>&1 > "$SCAN_DIR/web/nikto_${port}.txt" &
    fi

    # Directory enumeration with ffuf
    if command -v ffuf &>/dev/null; then
        log "INFO" "Starting directory enumeration on $base_url..."

        # Use custom CTF wordlist
        if [[ -n "$redirect_location" ]]; then
            generate_ctf_wordlist "$redirect_location"
        else
            generate_ctf_wordlist "$target"
        fi

        ffuf -u "$base_url/FUZZ" \
            -w "$wordlist" \
            -t "$FFUF_THREADS" \
            -e "php,html,txt,js,xml,json,bak,old,backup" \
            -fs "200,204,301,302,307,401,403" \
            -o "$SCAN_DIR/web/gobuster_${port}.txt" \
            -recursion -s > /dev/null 2>&1 &

        # Also run with common wordlist
        if [[ -f "$COMMON_WORDLIST" ]]; then
            ffuf -u "$base_url/FUZZ" \
                -w "$COMMON_WORDLIST" \
                -t "$FFUF_THREADS" \
                -e "php,html,txt" \
                -fs "200,204,301,302,307,401,403" \
                -o "$SCAN_DIR/web/gobuster_common_${port}.txt" \
                -s > /dev/null 2>&1 &
        fi
    fi

    # Check for common CTF files
    check_common_files "$base_url" "$port"

    # Check robots.txt
    if curl -s --connect-timeout 10 "$base_url/robots.txt" | grep -q "Disallow\|Allow"; then
        log "FINDING" "robots.txt found on $base_url"
        curl -s "$base_url/robots.txt" >"$SCAN_DIR/web/robots_${port}.txt"
        extract_info "$(cat "$SCAN_DIR/web/robots_${port}.txt")" "robots.txt"
    fi

    # Check for common admin panels
    check_admin_panels "$base_url" "$port"
}

# Check for common CTF files
check_common_files() {
    local base_url=$1
    local port=$2

    local common_files=(
        "flag.txt" "flag" "user.txt" "root.txt" "proof.txt"
        ".htaccess" ".htpasswd" "config.php" "database.sql"
        "backup.sql" "admin.php" "login.php" "upload.php"
        "phpinfo.php" "info.php" "test.php" "index.bak"
        "sitemap.xml" "crossdomain.xml" "web.config"
    )

    for file in "${common_files[@]}"; do
        local response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$base_url/$file")
        if [[ "$response" == "200" ]]; then
            log "FINDING" "Interesting file found: $base_url/$file"

            # Download and analyze the file
            curl -s --connect-timeout 10 "$base_url/$file" >"$SCAN_DIR/web/${file}_${port}.txt"
            extract_info "$(cat "$SCAN_DIR/web/${file}_${port}.txt")" "$file"
        fi
    done
}

# Check for admin panels
check_admin_panels() {
    local base_url=$1
    local port=$2

    local admin_paths=(
        "admin" "administrator" "admin.php" "login.php"
        "admin/login.php" "wp-admin" "phpmyadmin"
        "admin/index.php" "login" "panel" "dashboard"
    )

    for path in "${admin_paths[@]}"; do
        local response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$base_url/$path")
        if [[ "$response" =~ ^(200|401|403)$ ]]; then
            log "FINDING" "Admin panel found: $base_url/$path (HTTP $response)"
        fi
    done
}

# MySQL/Database enumeration
enum_mysql() {
    local target=$1
    local port=${2:-3306}

    log "INFO" "Enumerating MySQL service on $target:$port"

    # Try common credentials
    local credentials=("root:" "root:root" "root:password" "admin:admin" "mysql:mysql")

    for cred in "${credentials[@]}"; do
        local user=$(echo "$cred" | cut -d':' -f1)
        local pass=$(echo "$cred" | cut -d':' -f2)

        if timeout 10 mysql -h "$target" -P "$port" -u "$user" -p"$pass" -e "SELECT VERSION();" 2>/dev/null | grep -q "VERSION"; then
            log "FINDING" "MySQL login successful with $user:$pass"

            # Enumerate databases
            mysql -h "$target" -P "$port" -u "$user" -p"$pass" -e "SHOW DATABASES;" >"$SCAN_DIR/services/mysql_databases.txt" 2>/dev/null
            break
        fi
    done
}

# SNMP enumeration
enum_snmp() {
    local target=$1
    local port=${2:-161}

    log "INFO" "Enumerating SNMP service on $target:$port"

    if command -v snmpwalk &>/dev/null; then
        # Try common community strings
        local communities=("public" "private" "community" "manager")

        for community in "${communities[@]}"; do
            if timeout 30 snmpwalk -v2c -c "$community" "$target" 2>/dev/null | head -10 | grep -q "iso"; then
                log "FINDING" "SNMP community string '$community' works"

                # Get system information
                snmpwalk -v2c -c "$community" "$target" 1.3.6.1.2.1.1 >"$SCAN_DIR/services/snmp_system.txt" 2>/dev/null

                # Get network interfaces
                snmpwalk -v2c -c "$community" "$target" 1.3.6.1.2.1.2.2.1.2 >"$SCAN_DIR/services/snmp_interfaces.txt" 2>/dev/null

                break
            fi
        done
    fi
}

# DNS enumeration
enum_dns() {
    local target=$1
    local port=${2:-53}

    log "INFO" "Enumerating DNS service on $target:$port"

    # Try zone transfer
    if command -v dig &>/dev/null; then
        # Try to get domain name first
        local domain=$(dig @"$target" -x "$target" +short 2>/dev/null | sed 's/\.$//')

        if [[ -n "$domain" ]]; then
            log "INFO" "Attempting zone transfer for $domain"
            dig @"$target" "$domain" AXFR >"$SCAN_DIR/services/dns_zone_transfer.txt" 2>/dev/null

            if grep -q "XFR size" "$SCAN_DIR/services/dns_zone_transfer.txt"; then
                log "FINDING" "DNS zone transfer successful for $domain"
                extract_info "$(cat "$SCAN_DIR/services/dns_zone_transfer.txt")" "DNS zone transfer"
            fi
        fi

        # DNS enumeration with common subdomains
        local subdomains=("www" "mail" "ftp" "admin" "test" "dev" "staging")
        for sub in "${subdomains[@]}"; do
            if dig @"$target" "$sub.$domain" +short 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
                log "FINDING" "Subdomain found: $sub.$domain"
            fi
        done
    fi
}

# Main service enumeration function
run_service_enumeration() {
    local target=$1
    local ports_file="$SCAN_DIR/nmap/quick_scan.txt"

    log "INFO" "Starting service enumeration phase"
    
    # Ensure services directory exists
    if [[ ! -d "$SCAN_DIR/services" ]]; then
        mkdir -p "$SCAN_DIR/services"
        log "INFO" "Created services directory: $SCAN_DIR/services"
    fi

    if [[ ! -f "$ports_file" ]]; then
        log "ERROR" "No port scan results found. Run port scan first."
        return 1
    fi

    # Parse open ports and enumerate services
    while read -r line; do
        # Match lines that look like "22/tcp open  ssh syn-ack ttl 63"
        if [[ $line =~ ^([0-9]+)/tcp[[:space:]]+open[[:space:]]+([a-zA-Z0-9-]+) ]]; then
            local port="${BASH_REMATCH[1]}"
            local service="${BASH_REMATCH[2]}"

            log "INFO" "Enumerating $service on port $port"

            case $service in
            "ftp")
                enum_ftp "$target" "$port"
                ;;
            "ssh")
                enum_ssh "$target" "$port"
                ;;
            "http")
                enum_http "$target" "$port" "http"
                ;;
            "https" | "ssl/http")
                enum_http "$target" "$port" "https"
                ;;
            "microsoft-ds" | "netbios-ssn" | "smb")
                enum_smb "$target" "$port"
                ;;
            "mysql")
                enum_mysql "$target" "$port"
                ;;
            "snmp")
                enum_snmp "$target" "$port"
                ;;
            "domain" | "dns")
                enum_dns "$target" "$port"
                ;;
            *)
                log "INFO" "No specific enumeration for $service"
                ;;
            esac
        fi
    done <"$ports_file"

    log "SUCCESS" "Service enumeration completed"
}
