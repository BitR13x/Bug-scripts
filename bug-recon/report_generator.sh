#!/bin/bash

# Report generation module

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# Generate HTML report
generate_html_report() {
    local domain=$1
    local scan_dir=$2
    local report_file="$scan_dir/html_report.html"
    
    log "INFO" "Generating HTML report for $domain"
    start_timer
    
    # HTML header and CSS
    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
EOF
    
    echo "    <title>AutoRecon Report for $domain</title>" >> "$report_file"
    
    cat >> "$report_file" << 'EOF'
    <style>
        :root {
            --bg-color: #1e2227;
            --text-color: #ffffff;
            --accent-color: #00a0fc;
            --success-color: #0dee00;
            --warning-color: #d0b200;
            --error-color: #DD4A68;
            --card-bg: #282c34;
            --border-color: #333;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 40px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            color: var(--accent-color);
        }
        
        .header .subtitle {
            color: #888;
            font-size: 1.1em;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            text-align: center;
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: var(--accent-color);
        }
        
        .stat-label {
            color: #888;
            margin-top: 5px;
        }
        
        .section {
            background: var(--card-bg);
            margin-bottom: 30px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            overflow: hidden;
        }
        
        .section-header {
            background: var(--accent-color);
            color: white;
            padding: 15px 20px;
            font-weight: bold;
            font-size: 1.2em;
        }
        
        .section-content {
            padding: 20px;
        }
        
        .vulnerability {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            border-left: 4px solid;
        }
        
        .vuln-critical { border-left-color: var(--error-color); background: rgba(221, 74, 104, 0.1); }
        .vuln-high { border-left-color: #ff6b35; background: rgba(255, 107, 53, 0.1); }
        .vuln-medium { border-left-color: var(--warning-color); background: rgba(208, 178, 0, 0.1); }
        .vuln-low { border-left-color: var(--success-color); background: rgba(13, 238, 0, 0.1); }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .data-table th,
        .data-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        .data-table th {
            background: var(--accent-color);
            color: white;
            font-weight: bold;
        }
        
        .data-table tr:hover {
            background: rgba(0, 160, 252, 0.1);
        }
        
        .data-table a {
            color: var(--accent-color);
            text-decoration: none;
        }
        
        .data-table a:hover {
            text-decoration: underline;
        }
        
        .toggle-btn {
            background: var(--accent-color);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            margin: 10px 0;
        }
        
        .toggle-btn:hover {
            opacity: 0.8;
        }
        
        .collapsible {
            display: none;
        }
        
        .collapsible.active {
            display: block;
        }
        
        pre {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .footer {
            text-align: center;
            padding: 40px 0;
            border-top: 2px solid var(--border-color);
            margin-top: 40px;
            color: #888;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
        }
    </style>
    <script>
        function toggleSection(id) {
            const element = document.getElementById(id);
            element.classList.toggle('active');
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Copied to clipboard!');
            });
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
EOF
    
    echo "            <h1>AutoRecon Report</h1>" >> "$report_file"
    echo "            <div class=\"subtitle\">Target: <strong>$domain</strong></div>" >> "$report_file"
    echo "            <div class=\"subtitle\">Generated: $(date)</div>" >> "$report_file"
    
    cat >> "$report_file" << 'EOF'
        </div>
EOF
    
    # Generate statistics
    generate_statistics "$domain" "$scan_dir" "$report_file"
    
    # Generate sections
    generate_subdomain_section "$domain" "$scan_dir" "$report_file"
    generate_vulnerability_section "$domain" "$scan_dir" "$report_file"
    generate_web_services_section "$domain" "$scan_dir" "$report_file"
    generate_interesting_files_section "$domain" "$scan_dir" "$report_file"
    generate_technical_info_section "$domain" "$scan_dir" "$report_file"
    
    # Footer
    cat >> "$report_file" << 'EOF'
        <div class="footer">
            <p>Generated by AutoRecon - Automated Reconnaissance Tool</p>
            <p>Report generated with enhanced security scanning capabilities</p>
        </div>
    </div>
</body>
</html>
EOF
    
    end_timer "HTML report generation"
    log "INFO" "HTML report saved to $report_file"
}

# Generate statistics section
generate_statistics() {
    local domain=$1
    local scan_dir=$2
    local report_file=$3
    
    local subdomains_count=0
    local live_hosts_count=0
    local vulnerabilities_count=0
    local interesting_files_count=0
    
    # Count subdomains
    if [[ -f "$scan_dir/$domain.txt" ]]; then
        subdomains_count=$(wc -l < "$scan_dir/$domain.txt")
    fi
    
    # Count live hosts
    if [[ -f "$scan_dir/subdomain_live.txt" ]]; then
        live_hosts_count=$(wc -l < "$scan_dir/subdomain_live.txt")
    fi
    
    # Count vulnerabilities
    if [[ -f "$scan_dir/nuclei.txt" ]]; then
        vulnerabilities_count=$(wc -l < "$scan_dir/nuclei.txt")
    fi
    
    # Count interesting files
    if [[ -f "$scan_dir/interesting.txt" ]]; then
        interesting_files_count=$(wc -l < "$scan_dir/interesting.txt")
    fi
    
    cat >> "$report_file" << EOF
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$subdomains_count</div>
                <div class="stat-label">Total Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$live_hosts_count</div>
                <div class="stat-label">Live Web Services</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$vulnerabilities_count</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$interesting_files_count</div>
                <div class="stat-label">Interesting Files</div>
            </div>
        </div>
EOF
}

# Generate subdomain section
generate_subdomain_section() {
    local domain=$1
    local scan_dir=$2
    local report_file=$3
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">Subdomain Enumeration Results</div>
            <div class="section-content">
                <button class="toggle-btn" onclick="toggleSection('subdomains-table')">Toggle Subdomain List</button>
                <div id="subdomains-table" class="collapsible">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Subdomain</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
EOF
    
    if [[ -f "$scan_dir/subdomain_live.txt" ]]; then
        while IFS= read -r subdomain; do
            local clean_subdomain=$(echo "$subdomain" | sed 's|https\?://||g')
            cat >> "$report_file" << EOF
                            <tr>
                                <td><a href="$subdomain" target="_blank">$clean_subdomain</a></td>
                                <td><span style="color: var(--success-color);">Live</span></td>
                                <td>
                                    <button onclick="copyToClipboard('$subdomain')" class="toggle-btn">Copy URL</button>
                                </td>
                            </tr>
EOF
        done < "$scan_dir/subdomain_live.txt"
    fi
    
    cat >> "$report_file" << 'EOF'
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
EOF
}

# Generate vulnerability section
generate_vulnerability_section() {
    local domain=$1
    local scan_dir=$2
    local report_file=$3
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">Vulnerability Assessment</div>
            <div class="section-content">
EOF
    
    # Nuclei vulnerabilities
    if [[ -f "$scan_dir/nuclei.txt" && -s "$scan_dir/nuclei.txt" ]]; then
        cat >> "$report_file" << 'EOF'
                <h3>Nuclei Scanner Results</h3>
                <button class="toggle-btn" onclick="toggleSection('nuclei-results')">Toggle Nuclei Results</button>
                <div id="nuclei-results" class="collapsible">
EOF
        
        while IFS= read -r line; do
            local severity="low"
            if [[ "$line" =~ critical ]]; then
                severity="critical"
            elif [[ "$line" =~ high ]]; then
                severity="high"
            elif [[ "$line" =~ medium ]]; then
                severity="medium"
            fi
            
            cat >> "$report_file" << EOF
                    <div class="vulnerability vuln-$severity">
                        <pre>$line</pre>
                    </div>
EOF
        done < "$scan_dir/nuclei.txt"
        
        cat >> "$report_file" << 'EOF'
                </div>
EOF
    fi
    
    # XSS vulnerabilities
    if [[ -f "$scan_dir/xss_results.txt" && -s "$scan_dir/xss_results.txt" ]]; then
        cat >> "$report_file" << 'EOF'
                <h3>XSS Vulnerabilities</h3>
                <button class="toggle-btn" onclick="toggleSection('xss-results')">Toggle XSS Results</button>
                <div id="xss-results" class="collapsible">
EOF
        
        while IFS= read -r url; do
            cat >> "$report_file" << EOF
                    <div class="vulnerability vuln-high">
                        <strong>Potential XSS:</strong> <a href="$url" target="_blank">$url</a>
                    </div>
EOF
        done < "$scan_dir/xss_results.txt"
        
        cat >> "$report_file" << 'EOF'
                </div>
EOF
    fi
    
    cat >> "$report_file" << 'EOF'
            </div>
        </div>
EOF
}

# Generate web services section
generate_web_services_section() {
    local domain=$1
    local scan_dir=$2
    local report_file=$3
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">Web Services Analysis</div>
            <div class="section-content">
EOF
    
    # Technology detection
    if [[ -f "$scan_dir/technologies.txt" ]]; then
        cat >> "$report_file" << 'EOF'
                <h3>Technology Stack</h3>
                <button class="toggle-btn" onclick="toggleSection('tech-stack')">Toggle Technology Details</button>
                <div id="tech-stack" class="collapsible">
                    <pre>
EOF
        cat "$scan_dir/technologies.txt" >> "$report_file"
        cat >> "$report_file" << 'EOF'
                    </pre>
                </div>
EOF
    fi
    
    # Screenshots link
    if [[ -d "$scan_dir/$SCREENSHOTS_DIR" ]]; then
        cat >> "$report_file" << EOF
                <h3>Screenshots</h3>
                <p>Screenshots are available in the <a href="./$SCREENSHOTS_DIR/" target="_blank">screenshots directory</a></p>
                <p>Start the screenshot server: <code>cd $scan_dir && gowitness server -a $SERVER_IP:$SCREENSHOT_PORT</code></p>
EOF
    fi
    
    cat >> "$report_file" << 'EOF'
            </div>
        </div>
EOF
}

# Generate interesting files section
generate_interesting_files_section() {
    local domain=$1
    local scan_dir=$2
    local report_file=$3
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">Interesting Files & Endpoints</div>
            <div class="section-content">
EOF
    
    if [[ -f "$scan_dir/interesting.txt" && -s "$scan_dir/interesting.txt" ]]; then
        cat >> "$report_file" << 'EOF'
                <button class="toggle-btn" onclick="toggleSection('interesting-files')">Toggle Interesting Files</button>
                <div id="interesting-files" class="collapsible">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
EOF
        
        while IFS= read -r url; do
            cat >> "$report_file" << EOF
                            <tr>
                                <td><a href="$url" target="_blank">$url</a></td>
                                <td><button onclick="copyToClipboard('$url')" class="toggle-btn">Copy</button></td>
                            </tr>
EOF
        done < "$scan_dir/interesting.txt"
        
        cat >> "$report_file" << 'EOF'
                        </tbody>
                    </table>
                </div>
EOF
    else
        cat >> "$report_file" << 'EOF'
                <p>No interesting files found during the scan.</p>
EOF
    fi
    
    cat >> "$report_file" << 'EOF'
            </div>
        </div>
EOF
}

# Generate technical information section
generate_technical_info_section() {
    local domain=$1
    local scan_dir=$2
    local report_file=$3
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">Technical Information</div>
            <div class="section-content">
EOF
    
    # DNS information
    cat >> "$report_file" << EOF
                <h3>DNS Information</h3>
                <button class="toggle-btn" onclick="toggleSection('dns-info')">Toggle DNS Details</button>
                <div id="dns-info" class="collapsible">
                    <h4>Dig Results</h4>
                    <pre>$(dig "$domain" 2>/dev/null || echo "DNS lookup failed")</pre>
                    
                    <h4>Host Results</h4>
                    <pre>$(host "$domain" 2>/dev/null || echo "Host lookup failed")</pre>
                </div>
EOF
    
    # Port scan results
    if [[ -f "$scan_dir/port_scan.txt" ]]; then
        cat >> "$report_file" << 'EOF'
                <h3>Port Scan Results</h3>
                <button class="toggle-btn" onclick="toggleSection('port-scan')">Toggle Port Scan</button>
                <div id="port-scan" class="collapsible">
                    <pre>
EOF
        cat "$scan_dir/port_scan.txt" >> "$report_file"
        cat >> "$report_file" << 'EOF'
                    </pre>
                </div>
EOF
    fi
    
    cat >> "$report_file" << 'EOF'
            </div>
        </div>
EOF
}

# Generate JSON report
generate_json_report() {
    local domain=$1
    local scan_dir=$2
    local json_file="$scan_dir/report.json"
    
    log "INFO" "Generating JSON report for $domain"
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat > "$json_file" << EOF
{
    "scan_info": {
        "target": "$domain",
        "timestamp": "$timestamp",
        "tool": "AutoRecon",
        "version": "2.0"
    },
    "statistics": {
        "total_subdomains": $(wc -l < "$scan_dir/$domain.txt" 2>/dev/null || echo "0"),
        "live_hosts": $(wc -l < "$scan_dir/subdomain_live.txt" 2>/dev/null || echo "0"),
        "vulnerabilities": $(wc -l < "$scan_dir/nuclei.txt" 2>/dev/null || echo "0"),
        "interesting_files": $(wc -l < "$scan_dir/interesting.txt" 2>/dev/null || echo "0")
    },
    "subdomains": [
EOF
    
    # Add subdomains
    if [[ -f "$scan_dir/$domain.txt" ]]; then
        local first=true
        while IFS= read -r subdomain; do
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$json_file"
            fi
            echo -n "        \"$subdomain\"" >> "$json_file"
        done < "$scan_dir/$domain.txt"
        echo "" >> "$json_file"
    fi
    
    cat >> "$json_file" << 'EOF'
    ],
    "live_hosts": [
EOF
    
    # Add live hosts
    if [[ -f "$scan_dir/subdomain_live.txt" ]]; then
        local first=true
        while IFS= read -r host; do
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$json_file"
            fi
            echo -n "        \"$host\"" >> "$json_file"
        done < "$scan_dir/subdomain_live.txt"
        echo "" >> "$json_file"
    fi
    
    cat >> "$json_file" << 'EOF'
    ],
    "files": {
EOF
    
    # List all generated files
    local files=(
        "nuclei.txt:Nuclei scan results"
        "xss_results.txt:XSS vulnerabilities"
        "cors_results.txt:CORS misconfigurations"
        "interesting.txt:Interesting endpoints"
        "technologies.txt:Technology detection"
        "port_scan.txt:Port scan results"
    )
    
    local first=true
    for file_info in "${files[@]}"; do
        local filename=$(echo "$file_info" | cut -d':' -f1)
        local description=$(echo "$file_info" | cut -d':' -f2)
        
        if [[ -f "$scan_dir/$filename" ]]; then
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$json_file"
            fi
            echo "        \"$filename\": \"$description\"" >> "$json_file"
        fi
    done
    
    cat >> "$json_file" << 'EOF'
    }
}
EOF
    
    log "INFO" "JSON report saved to $json_file"
}

# Main report generation function
generate_reports() {
    local domain=$1
    local scan_dir=$2
    
    log "INFO" "Starting report generation for $domain"
    start_timer
    
    # Generate HTML report
    generate_html_report "$domain" "$scan_dir"
    
    # Generate JSON report
    generate_json_report "$domain" "$scan_dir"
    
    # Generate summary
    generate_summary "$domain" "$scan_dir"
    
    end_timer "Report generation"
    
    notify_user "Reports generated for $domain - Check $scan_dir/html_report.html"
}

# Generate scan summary
generate_summary() {
    local domain=$1
    local scan_dir=$2
    local summary_file="$scan_dir/scan_summary.txt"
    
    cat > "$summary_file" << EOF
AutoRecon Scan Summary
=====================

Target: $domain
Scan Date: $(date)
Scan Duration: ${SECONDS}s

Results Summary:
- Total Subdomains: $(wc -l < "$scan_dir/$domain.txt" 2>/dev/null || echo "0")
- Live Web Services: $(wc -l < "$scan_dir/subdomain_live.txt" 2>/dev/null || echo "0")
- Vulnerabilities Found: $(wc -l < "$scan_dir/nuclei.txt" 2>/dev/null || echo "0")
- Interesting Files: $(wc -l < "$scan_dir/interesting.txt" 2>/dev/null || echo "0")

Generated Files:
- HTML Report: html_report.html
- JSON Report: report.json
- Screenshots: $SCREENSHOTS_DIR/
- Raw Data: Various .txt files

Next Steps:
1. Review the HTML report for detailed findings
2. Investigate any vulnerabilities found
3. Check screenshots for visual confirmation
4. Perform manual testing on interesting endpoints

EOF
    
    log "INFO" "Scan summary saved to $summary_file"
}
