#!/bin/bash

# CTF Report generation module

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# Generate CTF-style HTML report
generate_ctf_report() {
    local target=$1
    local platform=$2
    local report_file="$SCAN_DIR/ctf_report.html"
    
    log "INFO" "Generating CTF report for $target"
    
    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CTF Reconnaissance Report</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-purple: #a5a5ff;
            --border-color: #30363d;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', 'Roboto', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 2.5em;
            color: var(--accent-blue);
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            color: var(--text-secondary);
            font-size: 1.1em;
        }
        
        .platform-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .htb { background: linear-gradient(45deg, #9fef00, #00ff88); color: #000; }
        .thm { background: linear-gradient(45deg, #ff6b6b, #4ecdc4); color: #fff; }
        .unknown { background: var(--bg-tertiary); color: var(--text-primary); }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            text-align: center;
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: var(--accent-green);
        }
        
        .stat-label {
            color: var(--text-secondary);
            margin-top: 5px;
        }
        
        .section {
            background: var(--bg-secondary);
            margin-bottom: 25px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            overflow: hidden;
        }
        
        .section-header {
            background: var(--bg-tertiary);
            padding: 15px 20px;
            font-weight: bold;
            font-size: 1.2em;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-content {
            padding: 20px;
        }
        
        .finding {
            background: var(--bg-tertiary);
            padding: 15px;
            margin: 10px 0;
            border-radius: 6px;
            border-left: 4px solid;
        }
        
        .finding-critical { border-left-color: var(--accent-red); }
        .finding-high { border-left-color: #ff8c00; }
        .finding-medium { border-left-color: var(--accent-yellow); }
        .finding-low { border-left-color: var(--accent-blue); }
        .finding-info { border-left-color: var(--accent-purple); }
        
        .finding-title {
            font-weight: bold;
            margin-bottom: 8px;
            color: var(--text-primary);
        }
        
        .finding-content {
            color: var(--text-secondary);
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .port-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .port-table th,
        .port-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        .port-table th {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-weight: bold;
        }
        
        .port-table tr:hover {
            background: var(--bg-tertiary);
        }
        
        .port-open { color: var(--accent-green); }
        .port-filtered { color: var(--accent-yellow); }
        .port-closed { color: var(--accent-red); }
        
        .code-block {
            background: var(--bg-primary);
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            margin: 10px 0;
        }
        
        .toggle-btn {
            background: var(--accent-blue);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
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
        
        .exploit-command {
            background: var(--bg-primary);
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            margin: 5px 0;
            border-left: 3px solid var(--accent-green);
        }
        
        .flag-found {
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            color: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
            margin: 20px 0;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        .footer {
            text-align: center;
            padding: 30px 0;
            border-top: 2px solid var(--border-color);
            margin-top: 40px;
            color: var(--text-secondary);
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 10px;
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
            <h1>🎯 CTF Reconnaissance Report</h1>
EOF
    
    echo "            <div class=\"subtitle\">Target: <strong>$target</strong></div>" >> "$report_file"
    echo "            <div class=\"subtitle\">Scan Date: $(date)</div>" >> "$report_file"
    
    # Add platform badge
    case $platform in
        "HackTheBox")
            echo "            <div class=\"platform-badge htb\">🟢 HackTheBox</div>" >> "$report_file"
            ;;
        "TryHackMe")
            echo "            <div class=\"platform-badge thm\">🔴 TryHackMe</div>" >> "$report_file"
            ;;
        *)
            echo "            <div class=\"platform-badge unknown\">❓ Unknown Platform</div>" >> "$report_file"
            ;;
    esac
    
    cat >> "$report_file" << 'EOF'
        </div>
EOF
    
    # Generate statistics
    generate_ctf_statistics "$target" "$report_file"
    
    # Generate sections
    generate_port_section "$target" "$report_file"
    generate_services_section "$target" "$report_file"
    generate_whatweb_section "$target" "$report_file"
    generate_nuclei_section "$target" "$report_file"
    generate_findings_section "$target" "$report_file"
    generate_exploits_section "$target" "$report_file"
    generate_file_structure_section "$target" "$report_file"
    generate_notes_section "$target" "$report_file"
    
    # Footer
    cat >> "$report_file" << 'EOF'
        <div class="footer">
            <p>🚀 Generated by CTF-Recon - Specialized for HackTheBox & TryHackMe</p>
            <p>Happy Hacking! 🎉</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log "SUCCESS" "CTF report generated: $report_file"
}

# Generate statistics section
generate_ctf_statistics() {
    local target=$1
    local report_file=$2
    
    # Count statistics
    local open_ports=0
    local services=0
    local findings=0
    local exploits=0
    
    if [[ -f "$SCAN_DIR/nmap/quick_scan.txt" ]]; then
        open_ports=$(grep "^[0-9]" "$SCAN_DIR/nmap/quick_scan.txt" | grep "open" | wc -l)
    fi
    
    if [[ -f "$SCAN_DIR/nmap/service_scan.txt" ]]; then
        services=$(grep -c "open" "$SCAN_DIR/nmap/service_scan.txt" 2>/dev/null || echo "0")
    fi
    
    if [[ -f "$FINDINGS_FILE" ]]; then
        findings=$(wc -l < "$FINDINGS_FILE" 2>/dev/null || echo "0")
    fi
    
    if [[ -d "$SCAN_DIR/exploits" ]]; then
        exploits=$(find "$SCAN_DIR/exploits" -name "*.txt" -o -name "*.rc" | wc -l)
    fi
    
    cat >> "$report_file" << EOF
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$open_ports</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$services</div>
                <div class="stat-label">Services Identified</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$findings</div>
                <div class="stat-label">Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$exploits</div>
                <div class="stat-label">Potential Exploits</div>
            </div>
        </div>
EOF
}

# Generate port scanning section
generate_port_section() {
    local target=$1
    local report_file=$2
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">
                🔍 Port Scan Results
                <button class="toggle-btn" onclick="toggleSection('port-details')">Toggle Details</button>
            </div>
            <div class="section-content">
                <table class="port-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version</th>
                        </tr>
                    </thead>
                    <tbody>
EOF
    
    # Add port scan results
    if [[ -f "$SCAN_DIR/nmap/quick_scan.txt" ]]; then
        while read -r line; do
            if [[ $line =~ ^([0-9]+)/tcp[[:space:]]+open[[:space:]]+([a-zA-Z0-9_-]+)[[:space:]]+(.*) ]]; then
                local port="${BASH_REMATCH[1]}"
                local service="${BASH_REMATCH[2]}"
                local version_full="${BASH_REMATCH[3]}"

                cat >> "$report_file" << EOF
                        <tr>
                            <td><strong>$port</strong></td>
                            <td><span class="port-open">Open</span></td>
                            <td>$service</td>
                            <td>${version_full:-"Unknown"}</td>
                        </tr>
EOF
            fi
        done < "$SCAN_DIR/nmap/quick_scan.txt"
    fi
    
    cat >> "$report_file" << 'EOF'
                    </tbody>
                </table>
                
                <div id="port-details" class="collapsible">
                    <h3>Detailed Scan Output</h3>
                    <div class="code-block">
EOF
    
    if [[ -f "$SCAN_DIR/nmap/service_scan.txt" ]]; then
        sed 's/</\&lt;/g; s/>/\&gt;/g' "$SCAN_DIR/nmap/service_scan.txt" >> "$report_file"
    fi
    
    cat >> "$report_file" << 'EOF'
                    </div>
                </div>
            </div>
        </div>
EOF
}

# Generate services section
generate_services_section() {
    local target=$1
    local report_file=$2
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">
                🛠️ Service Enumeration
            </div>
            <div class="section-content">
EOF
    
    # Add service enumeration results
    for service_file in "$SCAN_DIR/services"/*.txt; do
        if [[ -f "$service_file" ]]; then
            local service_name=$(basename "$service_file" .txt)
            
            cat >> "$report_file" << EOF
                <div class="finding finding-info">
                    <div class="finding-title">$service_name</div>
                    <button class="toggle-btn" onclick="toggleSection('$service_name-details')">Show Details</button>
                    <div id="$service_name-details" class="collapsible">
                        <div class="code-block">
EOF
            
            # Add first 50 lines of service output
            head -50 "$service_file" | sed 's/</\&lt;/g; s/>/\&gt;/g' >> "$report_file"
            
            cat >> "$report_file" << 'EOF'
                        </div>
                    </div>
                </div>
EOF
        fi
    done
    
    cat >> "$report_file" << 'EOF'
            </div>
        </div>
EOF
}

# Generate findings section
generate_findings_section() {
    local target=$1
    local report_file=$2
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">
                ⭐ Key Findings
            </div>
            <div class="section-content">
EOF
    
    # Check for flags first
    if [[ -f "$FINDINGS_FILE" ]] && grep -q "FLAG FOUND" "$FINDINGS_FILE"; then
        cat >> "$report_file" << 'EOF'
                <div class="flag-found">
                    🚩 FLAG FOUND! Check the findings below for details.
                </div>
EOF
    fi
    
    # Add findings
    if [[ -f "$FINDINGS_FILE" ]]; then
        while IFS= read -r finding; do
            local severity="info"
            local icon="ℹ️"
            
            if [[ $finding =~ FLAG|flag ]]; then
                severity="critical"
                icon="🚩"
            elif [[ $finding =~ VULNERABLE|exploit|RCE ]]; then
                severity="high"
                icon="🔥"
            elif [[ $finding =~ credentials|password|login ]]; then
                severity="medium"
                icon="🔑"
            elif [[ $finding =~ directory|file|path ]]; then
                severity="low"
                icon="📁"
            fi
            
            cat >> "$report_file" << EOF
                <div class="finding finding-$severity">
                    <div class="finding-title">$icon Finding</div>
                    <div class="finding-content">$finding</div>
                </div>
EOF
        done < "$FINDINGS_FILE"
    else
        cat >> "$report_file" << 'EOF'
                <div class="finding finding-info">
                    <div class="finding-title">ℹ️ No specific findings recorded</div>
                    <div class="finding-content">Check individual service enumeration results for details.</div>
                </div>
EOF
    fi
    
    cat >> "$report_file" << 'EOF'
            </div>
        </div>
EOF
}

# Generate exploits section
generate_exploits_section() {
    local target=$1
    local report_file=$2
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">
                💥 Exploitation Opportunities
            </div>
            <div class="section-content">
EOF
    
    # Add Metasploit commands
    if [[ -d "$SCAN_DIR/exploits" ]]; then
        for msf_file in "$SCAN_DIR/exploits"/*.rc; do
            if [[ -f "$msf_file" ]]; then
                local service_name=$(basename "$msf_file" .rc)
                
                cat >> "$report_file" << EOF
                <div class="finding finding-high">
                    <div class="finding-title">🎯 Metasploit Commands - $service_name</div>
                    <button class="toggle-btn" onclick="toggleSection('msf-$service_name')">Show Commands</button>
                    <div id="msf-$service_name" class="collapsible">
                        <div class="exploit-command">
                            msfconsole -r $msf_file
                        </div>
                        <div class="code-block">
EOF
                
                cat "$msf_file" | sed 's/</\&lt;/g; s/>/\&gt;/g' >> "$report_file"
                
                cat >> "$report_file" << 'EOF'
                        </div>
                    </div>
                </div>
EOF
            fi
        done
        
        # Add searchsploit results
        for exploit_file in "$SCAN_DIR/exploits"/searchsploit_*.txt; do
            if [[ -f "$exploit_file" && -s "$exploit_file" ]]; then
                local service_name=$(basename "$exploit_file" | sed 's/searchsploit_//; s/.txt//')
                
                cat >> "$report_file" << EOF
                <div class="finding finding-medium">
                    <div class="finding-title">🔍 Available Exploits - $service_name</div>
                    <button class="toggle-btn" onclick="toggleSection('exploits-$service_name')">Show Exploits</button>
                    <div id="exploits-$service_name" class="collapsible">
                        <div class="code-block">
EOF
                
                head -20 "$exploit_file" | sed 's/</\&lt;/g; s/>/\&gt;/g' | sed 's/\x1b\[[0-9;]*m//g' >> "$report_file"
                
                cat >> "$report_file" << 'EOF'
                        </div>
                    </div>
                </div>
EOF
            fi
        done
    fi
    
    cat >> "$report_file" << 'EOF'
            </div>
        </div>
EOF
}

# Generate file structure section
generate_file_structure_section() {
    local target=$1
    local report_file=$2
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">
                <h2 onclick="toggleSection('file-structure-section')">📁 Scan Files & Structure</h2>
            </div>
            <div id="file-structure-section" class="section-content">
                <div class="finding finding-info">
                    <div class="finding-title">📊 Directory Structure</div>
                    <div class="finding-content">
                        <div class="file-tree">
EOF
    
    # Generate file tree structure with embedded content
    if [[ -d "$SCAN_DIR" ]]; then
        echo "                            <div class=\"tree-item folder\" onclick=\"toggleFolder('scan-root')\">📁 $(basename "$SCAN_DIR")/</div>" >> "$report_file"
        echo "                            <div id=\"scan-root\" class=\"tree-content active\">" >> "$report_file"
        
        # List main directories and files
        for item in "$SCAN_DIR"/*; do
            if [[ -d "$item" ]]; then
                local dir_name=$(basename "$item")
                local file_count=$(find "$item" -type f 2>/dev/null | wc -l)
                echo "                                <div class=\"tree-item folder\" onclick=\"toggleFolder('$dir_name-folder')\">📁 $dir_name/ ($file_count files)</div>" >> "$report_file"
                echo "                                <div id=\"$dir_name-folder\" class=\"tree-content\">" >> "$report_file"
                
                # List files in directory
                for file in "$item"/*; do
                    if [[ -f "$file" ]]; then
                        local file_name=$(basename "$file")
                        local file_size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "0B")
                        local file_id="${dir_name}_${file_name//[^a-zA-Z0-9]/_}"
                        echo "                                    <div class=\"tree-item file\" onclick=\"viewFile('$file_id')\">📄 $file_name ($file_size)</div>" >> "$report_file"
                    fi
                done
                
                echo "                                </div>" >> "$report_file"
            elif [[ -f "$item" ]]; then
                local file_name=$(basename "$item")
                # Skip the HTML report file to avoid confusion
                if [[ "$file_name" == "ctf_report.html" ]]; then
                    continue
                fi
                local file_size=$(du -h "$item" 2>/dev/null | cut -f1 || echo "0B")
                local file_id="root_${file_name//[^a-zA-Z0-9]/_}"
                echo "                                <div class=\"tree-item file\" onclick=\"viewFile('$file_id')\">📄 $file_name ($file_size)</div>" >> "$report_file"
            fi
        done
        
        echo "                            </div>" >> "$report_file"
    fi
    
    cat >> "$report_file" << 'EOF'
                        </div>
                    </div>
                </div>
                
                <div class="finding finding-info">
                    <div class="finding-title">📖 File Viewer</div>
                    <div class="finding-content">
                        <div id="file-viewer">
                            <p>Click on any file above to view its contents here.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Embedded file contents -->
        <script type="application/json" id="file-contents">
        {
EOF
    
    # Embed file contents as JSON (excluding the HTML report itself to avoid recursion)
    local first_file=true
    for item in "$SCAN_DIR"/*; do
        if [[ -d "$item" ]]; then
            local dir_name=$(basename "$item")
            for file in "$item"/*; do
                if [[ -f "$file" ]]; then
                    local file_name=$(basename "$file")
                    local file_id="${dir_name}_${file_name//[^a-zA-Z0-9]/_}"
                    local file_path="$item/$file_name"
                    
                    # Add comma separator
                    if [[ "$first_file" == false ]]; then
                        echo "," >> "$report_file"
                    fi
                    first_file=false
                    
                    # Embed file content (limit to reasonable size)
                    echo -n "            \"$file_id\": {" >> "$report_file"
                    echo -n "\"name\": \"$file_name\", " >> "$report_file"
                    echo -n "\"path\": \"$file_path\", " >> "$report_file"
                    echo -n "\"dir\": \"$dir_name\", " >> "$report_file"
                    
                    # Check file size and type
                    local file_size_bytes=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
                    if [[ $file_size_bytes -lt 10000 ]]; then  # Less than 10KB
                        # Check if it's a text file and not the HTML report itself
                        if [[ "$file_name" != "ctf_report.html" ]] && file "$file" | grep -q "text\|ASCII\|UTF-8\|empty"; then
                            echo -n "\"content\": \"" >> "$report_file"
                            # Properly escape content for JSON
                            python3 -c "
import json
import sys
try:
    with open('$file', 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    print(json.dumps(content)[1:-1], end='')
except:
    print('[Error reading file]', end='')
" >> "$report_file"
                            echo -n "\", " >> "$report_file"
                            echo -n "\"type\": \"text\"" >> "$report_file"
                        else
                            echo -n "\"content\": \"[File excluded from viewer or binary file]\", " >> "$report_file"
                            echo -n "\"type\": \"excluded\"" >> "$report_file"
                        fi
                    else
                        echo -n "\"content\": \"[File too large - use command line to view]\", " >> "$report_file"
                        echo -n "\"type\": \"large\"" >> "$report_file"
                    fi
                    echo -n "}" >> "$report_file"
                fi
            done
        elif [[ -f "$item" ]]; then
            local file_name=$(basename "$item")
            local file_id="root_${file_name//[^a-zA-Z0-9]/_}"
            
            # Skip the HTML report file to avoid recursion
            if [[ "$file_name" == "ctf_report.html" ]]; then
                continue
            fi
            
            # Add comma separator
            if [[ "$first_file" == false ]]; then
                echo "," >> "$report_file"
            fi
            first_file=false
            
            echo -n "            \"$file_id\": {" >> "$report_file"
            echo -n "\"name\": \"$file_name\", " >> "$report_file"
            echo -n "\"path\": \"$item\", " >> "$report_file"
            echo -n "\"dir\": \"root\", " >> "$report_file"
            
            # Check file size and type
            local file_size_bytes=$(stat -f%z "$item" 2>/dev/null || stat -c%s "$item" 2>/dev/null || echo "0")
            if [[ $file_size_bytes -lt 10000 ]]; then  # Less than 10KB
                if file "$item" | grep -q "text\|ASCII\|UTF-8\|empty"; then
                    echo -n "\"content\": \"" >> "$report_file"
                    # Properly escape content for JSON
                    python3 -c "
import json
import sys
try:
    with open('$item', 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    print(json.dumps(content)[1:-1], end='')
except:
    print('[Error reading file]', end='')
" >> "$report_file"
                    echo -n "\", " >> "$report_file"
                    echo -n "\"type\": \"text\"" >> "$report_file"
                else
                    echo -n "\"content\": \"[Binary file - cannot display]\", " >> "$report_file"
                    echo -n "\"type\": \"binary\"" >> "$report_file"
                fi
            else
                echo -n "\"content\": \"[File too large - use command line to view]\", " >> "$report_file"
                echo -n "\"type\": \"large\"" >> "$report_file"
            fi
            echo -n "}" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << 'EOF'
        }
        </script>

        <style>
            .file-tree {
                font-family: 'Courier New', monospace;
                background: var(--bg-tertiary);
                padding: 15px;
                border-radius: 8px;
                max-height: 400px;
                overflow-y: auto;
            }
            
            .tree-item {
                padding: 5px 0;
                cursor: pointer;
                user-select: none;
                transition: background-color 0.2s;
            }
            
            .tree-item:hover {
                background-color: var(--bg-secondary);
                border-radius: 4px;
                padding-left: 5px;
            }
            
            .tree-item.folder {
                font-weight: bold;
                color: var(--accent-blue);
            }
            
            .tree-item.file {
                color: var(--text-secondary);
                margin-left: 20px;
            }
            
            .tree-item.file:hover {
                color: var(--accent-green);
            }
            
            .tree-content {
                margin-left: 20px;
                display: none;
                border-left: 2px solid var(--border-color);
                padding-left: 10px;
            }
            
            .tree-content.active {
                display: block;
            }
            
            #file-viewer {
                background: var(--bg-tertiary);
                border-radius: 8px;
                padding: 15px;
                min-height: 200px;
                max-height: 600px;
                overflow-y: auto;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.4;
            }
            
            .file-header {
                background: var(--bg-secondary);
                padding: 10px;
                border-radius: 4px;
                margin-bottom: 10px;
                border-left: 4px solid var(--accent-green);
            }
            
            .file-content {
                background: var(--bg-primary);
                padding: 15px;
                border-radius: 4px;
                border: 1px solid var(--border-color);
                white-space: pre-wrap;
                word-wrap: break-word;
                font-family: 'Courier New', monospace;
                font-size: 11px;
                line-height: 1.3;
                max-height: 400px;
                overflow-y: auto;
            }
            
            .file-actions {
                margin-top: 10px;
                text-align: right;
            }
            
            .copy-btn {
                background: var(--accent-blue);
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
                margin-left: 5px;
            }
            
            .copy-btn:hover {
                background: var(--accent-green);
            }
            
            .file-stats {
                font-size: 11px;
                color: var(--text-secondary);
                margin-top: 5px;
            }
        </style>

        <script>
            let fileContents = {};
            
            // Load file contents from embedded JSON
            document.addEventListener('DOMContentLoaded', function() {
                try {
                    const contentScript = document.getElementById('file-contents');
                    if (contentScript) {
                        fileContents = JSON.parse(contentScript.textContent);
                    }
                } catch (e) {
                    console.error('Failed to load file contents:', e);
                }
            });
            
            function toggleFolder(folderId) {
                const folder = document.getElementById(folderId);
                if (folder) {
                    folder.classList.toggle('active');
                }
            }
            
            function viewFile(fileId) {
                const viewer = document.getElementById('file-viewer');
                const fileData = fileContents[fileId];
                
                if (!fileData) {
                    viewer.innerHTML = '<p>File data not found.</p>';
                    return;
                }
                
                const fileName = fileData.name;
                const filePath = fileData.path;
                const fileDir = fileData.dir;
                const content = fileData.content;
                const fileType = fileData.type;
                
                let contentDisplay = '';
                let actions = '';
                
                if (fileType === 'text') {
                    // Create a safe HTML version of the content
                    const safeContent = content
                        .replace(/&/g, '&amp;')
                        .replace(/</g, '&lt;')
                        .replace(/>/g, '&gt;')
                        .replace(/"/g, '&quot;')
                        .replace(/'/g, '&#39;');
                    
                    contentDisplay = `<div class="file-content">${safeContent}</div>`;
                    actions = `
                        <button class="copy-btn" onclick="copyFileContent('${fileId}')">Copy Content</button>
                        <button class="copy-btn" onclick="copyToClipboard('cat \\"${filePath}\\"')">Copy View Command</button>
                    `;
                } else if (fileType === 'binary') {
                    contentDisplay = `
                        <div class="file-content">
                            <p><strong>Binary file detected.</strong></p>
                            <p>This file contains binary data and cannot be displayed as text.</p>
                            <p>Use appropriate tools to analyze this file:</p>
                            <div class="code-block">
# View file type
file "${filePath}"

# Hex dump (first 100 bytes)
xxd "${filePath}" | head -10

# Strings in binary
strings "${filePath}"
                            </div>
                        </div>
                    `;
                    actions = `<button class="copy-btn" onclick="copyToClipboard('file \\"${filePath}\\"')">Copy File Command</button>`;
                } else if (fileType === 'excluded') {
                    contentDisplay = `
                        <div class="file-content">
                            <p><strong>File excluded from viewer.</strong></p>
                            <p>This file is excluded from the embedded viewer (likely the HTML report itself or a binary file).</p>
                            <div class="code-block">
# View file
cat "${filePath}"

# View with syntax highlighting
bat "${filePath}"
                            </div>
                        </div>
                    `;
                    actions = `<button class="copy-btn" onclick="copyToClipboard('cat \\"${filePath}\\"')">Copy View Command</button>`;
                } else {
                    contentDisplay = `
                        <div class="file-content">
                            <p><strong>File too large to display.</strong></p>
                            <p>This file is too large to embed in the report.</p>
                            <div class="code-block">
# View file
cat "${filePath}"

# View first/last lines
head -20 "${filePath}"
tail -20 "${filePath}"

# Search in file
grep -i "keyword" "${filePath}"
                            </div>
                        </div>
                    `;
                    actions = `<button class="copy-btn" onclick="copyToClipboard('cat \\"${filePath}\\"')">Copy View Command</button>`;
                }
                
                const lineCount = fileType === 'text' ? content.split('\n').length : 'N/A';
                
                viewer.innerHTML = `
                    <div class="file-header">
                        <strong>📄 ${fileName}</strong><br>
                        <small>Directory: ${fileDir}/</small><br>
                        <small>Full Path: ${filePath}</small>
                        <div class="file-stats">Type: ${fileType} | Lines: ${lineCount}</div>
                    </div>
                    ${contentDisplay}
                    <div class="file-actions">
                        ${actions}
                    </div>
                `;
            }
            
            function copyFileContent(fileId) {
                const fileData = fileContents[fileId];
                if (fileData && fileData.content) {
                    copyToClipboard(fileData.content);
                }
            }
        </script>
EOF
}

# Generate notes section
generate_notes_section() {
    local target=$1
    local report_file=$2
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">
                📝 Notes & Next Steps
            </div>
            <div class="section-content">
                <div class="finding finding-info">
                    <div class="finding-title">📋 Recommended Next Steps</div>
                    <div class="finding-content">
                        1. Review all open ports and services<br>
                        2. Test default credentials on identified services<br>
                        3. Perform manual testing on web applications<br>
                        4. Check for known vulnerabilities in identified software versions<br>
                        5. Attempt privilege escalation techniques<br>
                        6. Look for sensitive files and configuration issues
                    </div>
                </div>
                
                <div class="finding finding-info">
                    <div class="finding-title">✏️ Personal Notes</div>
                    <div class="finding-content">
                        <div class="notes-container">
                            <div class="notes-toolbar">
                                <button class="notes-btn" onclick="addNote()">➕ Add Note</button>
                                <button class="notes-btn" onclick="exportNotes()">💾 Export Notes</button>
                                <button class="notes-btn" onclick="clearAllNotes()">🗑️ Clear All</button>
                                <span class="notes-counter">Notes: <span id="notes-count">0</span></span>
                            </div>
                            
                            <div id="notes-list" class="notes-list">
                                <!-- Notes will be dynamically added here -->
                            </div>
                            
                            <div class="add-note-form" id="add-note-form" style="display: none;">
                                <div class="form-group">
                                    <label for="note-title">Title:</label>
                                    <input type="text" id="note-title" placeholder="Enter note title..." />
                                </div>
                                <div class="form-group">
                                    <label for="note-content">Content:</label>
                                    <textarea id="note-content" rows="4" placeholder="Enter your notes here..."></textarea>
                                </div>
                                <div class="form-group">
                                    <label for="note-category">Category:</label>
                                    <select id="note-category">
                                        <option value="general">General</option>
                                        <option value="vulnerability">Vulnerability</option>
                                        <option value="exploit">Exploit</option>
                                        <option value="credential">Credentials</option>
                                        <option value="flag">Flag</option>
                                        <option value="todo">To-Do</option>
                                    </select>
                                </div>
                                <div class="form-actions">
                                    <button class="notes-btn save-btn" onclick="saveNote()">💾 Save Note</button>
                                    <button class="notes-btn cancel-btn" onclick="cancelNote()">❌ Cancel</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
EOF
    
    # Add existing notes from file if available
    if [[ -f "$NOTES_FILE" && -s "$NOTES_FILE" ]]; then
        cat >> "$report_file" << 'EOF'
                <div class="finding finding-info">
                    <div class="finding-title">📄 Existing Notes File</div>
                    <div class="finding-content">
                        <div class="code-block">
EOF
        sed 's/</\&lt;/g; s/>/\&gt;/g' "$NOTES_FILE" >> "$report_file"
        cat >> "$report_file" << 'EOF'
                        </div>
                    </div>
                </div>
EOF
    fi
    
    cat >> "$report_file" << 'EOF'
            </div>
        </div>

        <style>
            .notes-container {
                background: var(--bg-tertiary);
                border-radius: 8px;
                padding: 15px;
                margin-top: 10px;
            }
            
            .notes-toolbar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
                flex-wrap: wrap;
                gap: 10px;
            }
            
            .notes-btn {
                background: var(--accent-blue);
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
                transition: background-color 0.2s;
            }
            
            .notes-btn:hover {
                background: var(--accent-green);
            }
            
            .save-btn {
                background: var(--accent-green);
            }
            
            .cancel-btn {
                background: var(--accent-red);
            }
            
            .notes-counter {
                color: var(--text-secondary);
                font-size: 12px;
            }
            
            .notes-list {
                max-height: 400px;
                overflow-y: auto;
                margin-bottom: 15px;
            }
            
            .note-item {
                background: var(--bg-secondary);
                border: 1px solid var(--border-color);
                border-radius: 6px;
                padding: 12px;
                margin-bottom: 10px;
                position: relative;
            }
            
            .note-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 8px;
            }
            
            .note-title {
                font-weight: bold;
                color: var(--text-primary);
                font-size: 14px;
            }
            
            .note-category {
                background: var(--accent-blue);
                color: white;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 10px;
                text-transform: uppercase;
            }
            
            .note-category.vulnerability { background: var(--accent-red); }
            .note-category.exploit { background: var(--accent-yellow); color: black; }
            .note-category.credential { background: var(--accent-green); }
            .note-category.flag { background: var(--accent-purple); }
            .note-category.todo { background: #ff8c00; }
            
            .note-content {
                color: var(--text-secondary);
                font-size: 13px;
                line-height: 1.4;
                white-space: pre-wrap;
                word-wrap: break-word;
                margin-bottom: 8px;
            }
            
            .note-meta {
                display: flex;
                justify-content: space-between;
                align-items: center;
                font-size: 11px;
                color: var(--text-secondary);
                border-top: 1px solid var(--border-color);
                padding-top: 8px;
            }
            
            .note-actions {
                display: flex;
                gap: 5px;
            }
            
            .note-action-btn {
                background: none;
                border: none;
                color: var(--text-secondary);
                cursor: pointer;
                padding: 2px 5px;
                border-radius: 3px;
                font-size: 11px;
            }
            
            .note-action-btn:hover {
                background: var(--bg-tertiary);
                color: var(--text-primary);
            }
            
            .add-note-form {
                background: var(--bg-secondary);
                border: 1px solid var(--border-color);
                border-radius: 6px;
                padding: 15px;
                margin-top: 10px;
            }
            
            .form-group {
                margin-bottom: 12px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 5px;
                font-weight: bold;
                color: var(--text-primary);
                font-size: 12px;
            }
            
            .form-group input,
            .form-group textarea,
            .form-group select {
                width: 100%;
                background: var(--bg-tertiary);
                border: 1px solid var(--border-color);
                border-radius: 4px;
                padding: 8px;
                color: var(--text-primary);
                font-size: 13px;
                font-family: inherit;
            }
            
            .form-group textarea {
                resize: vertical;
                min-height: 80px;
            }
            
            .form-actions {
                display: flex;
                gap: 10px;
                justify-content: flex-end;
                margin-top: 15px;
            }
            
            .empty-notes {
                text-align: center;
                color: var(--text-secondary);
                font-style: italic;
                padding: 20px;
            }
        </style>

        <script>
            let notes = [];
            let noteIdCounter = 1;
            
            // Load notes from localStorage on page load
            document.addEventListener('DOMContentLoaded', function() {
                loadNotesFromStorage();
                updateNotesDisplay();
            });
            
            function loadNotesFromStorage() {
                const savedNotes = localStorage.getItem('ctf-notes-' + window.location.pathname);
                if (savedNotes) {
                    try {
                        notes = JSON.parse(savedNotes);
                        noteIdCounter = Math.max(...notes.map(n => n.id), 0) + 1;
                    } catch (e) {
                        console.error('Failed to load notes from storage:', e);
                        notes = [];
                    }
                }
            }
            
            function saveNotesToStorage() {
                try {
                    localStorage.setItem('ctf-notes-' + window.location.pathname, JSON.stringify(notes));
                } catch (e) {
                    console.error('Failed to save notes to storage:', e);
                }
            }
            
            function addNote() {
                const form = document.getElementById('add-note-form');
                form.style.display = form.style.display === 'none' ? 'block' : 'none';
                
                if (form.style.display === 'block') {
                    document.getElementById('note-title').focus();
                }
            }
            
            function cancelNote() {
                document.getElementById('add-note-form').style.display = 'none';
                clearForm();
            }
            
            function saveNote() {
                const title = document.getElementById('note-title').value.trim();
                const content = document.getElementById('note-content').value.trim();
                const category = document.getElementById('note-category').value;
                
                if (!title || !content) {
                    alert('Please fill in both title and content.');
                    return;
                }
                
                const note = {
                    id: noteIdCounter++,
                    title: title,
                    content: content,
                    category: category,
                    timestamp: new Date().toLocaleString()
                };
                
                notes.unshift(note); // Add to beginning of array
                saveNotesToStorage();
                updateNotesDisplay();
                cancelNote();
            }
            
            function deleteNote(noteId) {
                if (confirm('Are you sure you want to delete this note?')) {
                    notes = notes.filter(note => note.id !== noteId);
                    saveNotesToStorage();
                    updateNotesDisplay();
                }
            }
            
            function editNote(noteId) {
                const note = notes.find(n => n.id === noteId);
                if (!note) return;
                
                document.getElementById('note-title').value = note.title;
                document.getElementById('note-content').value = note.content;
                document.getElementById('note-category').value = note.category;
                
                // Remove the old note and show form
                deleteNote(noteId);
                addNote();
            }
            
            function clearForm() {
                document.getElementById('note-title').value = '';
                document.getElementById('note-content').value = '';
                document.getElementById('note-category').value = 'general';
            }
            
            function updateNotesDisplay() {
                const notesList = document.getElementById('notes-list');
                const notesCount = document.getElementById('notes-count');
                
                notesCount.textContent = notes.length;
                
                if (notes.length === 0) {
                    notesList.innerHTML = '<div class="empty-notes">No notes yet. Click "Add Note" to get started!</div>';
                    return;
                }
                
                notesList.innerHTML = notes.map(note => `
                    <div class="note-item">
                        <div class="note-header">
                            <div class="note-title">${escapeHtml(note.title)}</div>
                            <div class="note-category ${note.category}">${note.category}</div>
                        </div>
                        <div class="note-content">${escapeHtml(note.content)}</div>
                        <div class="note-meta">
                            <span>${note.timestamp}</span>
                            <div class="note-actions">
                                <button class="note-action-btn" onclick="editNote(${note.id})" title="Edit">✏️</button>
                                <button class="note-action-btn" onclick="copyToClipboard('${escapeHtml(note.content).replace(/'/g, "\\'")}')">📋</button>
                                <button class="note-action-btn" onclick="deleteNote(${note.id})" title="Delete">🗑️</button>
                            </div>
                        </div>
                    </div>
                `).join('');
            }
            
            function exportNotes() {
                if (notes.length === 0) {
                    alert('No notes to export.');
                    return;
                }
                
                let exportText = '# CTF Notes Export\\n';
                exportText += '# Generated: ' + new Date().toLocaleString() + '\\n\\n';
                
                notes.forEach(note => {
                    exportText += `## ${note.title} [${note.category.toUpperCase()}]\\n`;
                    exportText += `**Date:** ${note.timestamp}\\n\\n`;
                    exportText += `${note.content}\\n\\n`;
                    exportText += '---\\n\\n';
                });
                
                // Create and download file
                const blob = new Blob([exportText], { type: 'text/markdown' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'ctf-notes-' + new Date().toISOString().split('T')[0] + '.md';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }
            
            function clearAllNotes() {
                if (notes.length === 0) {
                    alert('No notes to clear.');
                    return;
                }
                
                if (confirm('Are you sure you want to delete ALL notes? This cannot be undone.')) {
                    notes = [];
                    saveNotesToStorage();
                    updateNotesDisplay();
                }
            }
            
            function escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }
        </script>
EOF
}

# Generate markdown notes
generate_markdown_notes() {
    local target=$1
    local platform=$2
    local notes_file="$SCAN_DIR/ctf_notes.md"
    
    log "INFO" "Generating markdown notes"
    
    cat > "$notes_file" << EOF
# CTF Reconnaissance Notes

**Target:** $target  
**Platform:** $platform  
**Date:** $(date)  

## Summary

- **Open Ports:** $(grep -c "open" "$SCAN_DIR/nmap/quick_scan.txt" 2>/dev/null || echo "0")
- **Services:** $(find "$SCAN_DIR/services" -name "*.txt" | wc -l)
- **Findings:** $(wc -l < "$FINDINGS_FILE" 2>/dev/null || echo "0")

## Open Ports

\`\`\`
EOF
    
    if [[ -f "$SCAN_DIR/nmap/quick_scan.txt" ]]; then
        grep "^[0-9]" "$SCAN_DIR/nmap/quick_scan.txt" | grep "open" >> "$notes_file"
    fi
    
    cat >> "$notes_file" << 'EOF'
```

## Key Findings

EOF
    
    if [[ -f "$FINDINGS_FILE" ]]; then
        while IFS= read -r finding; do
            echo "- $finding" >> "$notes_file"
        done < "$FINDINGS_FILE"
    fi
    
    cat >> "$notes_file" << 'EOF'

## Exploitation Commands

### Metasploit
```bash
msfconsole
EOF
    
    # Add MSF commands
    for msf_file in "$SCAN_DIR/exploits"/*.rc; do
        if [[ -f "$msf_file" ]]; then
            echo "# $(basename "$msf_file")" >> "$notes_file"
            cat "$msf_file" >> "$notes_file"
            echo "" >> "$notes_file"
        fi
    done
    
    cat >> "$notes_file" << 'EOF'
```

## Nuclei Vulnerability Scan

EOF
    
    # Add nuclei results if available
    local nuclei_file="$SCAN_DIR/vulnerabilities/nuclei_results.txt"
    if [[ -f "$nuclei_file" && -s "$nuclei_file" ]]; then
        local total_vulns=$(wc -l < "$nuclei_file")
        echo "**Total Vulnerabilities Found:** $total_vulns" >> "$notes_file"
        echo "" >> "$notes_file"
        
        # Add critical and high severity
        if grep -q "\[critical\]\|\[high\]" "$nuclei_file" 2>/dev/null; then
            echo "### Critical & High Severity" >> "$notes_file"
            echo '```' >> "$notes_file"
            grep "\[critical\]\|\[high\]" "$nuclei_file" | head -5 >> "$notes_file"
            echo '```' >> "$notes_file"
            echo "" >> "$notes_file"
        fi
        
        # Add CTF-relevant findings
        if grep -qi "login\|admin\|config\|backup\|flag\|secret\|panel\|dashboard" "$nuclei_file" 2>/dev/null; then
            echo "### CTF-Relevant Findings" >> "$notes_file"
            echo '```' >> "$notes_file"
            grep -i "login\|admin\|config\|backup\|flag\|secret\|panel\|dashboard" "$nuclei_file" | head -3 >> "$notes_file"
            echo '```' >> "$notes_file"
            echo "" >> "$notes_file"
        fi
    else
        echo "No vulnerabilities found or scan not performed." >> "$notes_file"
        echo "" >> "$notes_file"
    fi
    
    cat >> "$notes_file" << 'EOF'
## Web Technology Analysis

EOF
    
    # Add whatweb results if available
    local whatweb_files=("$SCAN_DIR"/web/whatweb_*.txt)
    local found_whatweb=false
    
    for whatweb_file in "${whatweb_files[@]}"; do
        if [[ -f "$whatweb_file" && -s "$whatweb_file" ]]; then
            found_whatweb=true
            local port=$(basename "$whatweb_file" | sed 's/whatweb_//; s/.txt//')
            echo "### Port $port" >> "$notes_file"
            echo '```' >> "$notes_file"
            head -10 "$whatweb_file" >> "$notes_file"
            echo '```' >> "$notes_file"
            echo "" >> "$notes_file"
        fi
    done
    
    if [[ "$found_whatweb" == false ]]; then
        echo "No web services detected or WhatWeb scan not performed." >> "$notes_file"
        echo "" >> "$notes_file"
    fi

    cat >> "$notes_file" << 'EOF'
## Manual Testing Checklist

- [ ] Test default credentials
- [ ] Check for directory traversal
- [ ] Test for SQL injection
- [ ] Look for file upload vulnerabilities
- [ ] Check for privilege escalation paths
- [ ] Search for sensitive files
- [ ] Test for command injection
- [ ] Check for weak file permissions

## Notes

EOF
    
    log "SUCCESS" "Markdown notes generated: $notes_file"
}

# Generate nuclei vulnerability section
generate_nuclei_section() {
    local target=$1
    local report_file=$2
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">
                <h2 onclick="toggleSection('nuclei-section')">🔍 Nuclei Vulnerability Scan</h2>
            </div>
            <div id="nuclei-section" class="section-content">
EOF
    
    local nuclei_file="$SCAN_DIR/vulnerabilities/nuclei_results.txt"
    local nuclei_json="$SCAN_DIR/vulnerabilities/nuclei_results.json"
    
    if [[ -f "$nuclei_file" && -s "$nuclei_file" ]]; then
        local total_vulns=$(wc -l < "$nuclei_file")
        local critical_count=$(grep -c "\[critical\]" "$nuclei_file" 2>/dev/null || echo "0")
        local high_count=$(grep -c "\[high\]" "$nuclei_file" 2>/dev/null || echo "0")
        local medium_count=$(grep -c "\[medium\]" "$nuclei_file" 2>/dev/null || echo "0")
        local low_count=$(grep -c "\[low\]" "$nuclei_file" 2>/dev/null || echo "0")
        
        cat >> "$report_file" << EOF
                <div class="finding finding-info">
                    <div class="finding-title">📊 Vulnerability Summary</div>
                    <div class="finding-content">
                        <strong>Total Vulnerabilities Found:</strong> $total_vulns<br>
                        <span style="color: var(--accent-red);">Critical: $critical_count</span> | 
                        <span style="color: var(--accent-yellow);">High: $high_count</span> | 
                        <span style="color: var(--accent-blue);">Medium: $medium_count</span> | 
                        <span style="color: var(--text-secondary);">Low: $low_count</span>
                    </div>
                </div>
EOF
        
        # Show critical and high severity vulnerabilities
        if [[ $critical_count -gt 0 || $high_count -gt 0 ]]; then
            cat >> "$report_file" << 'EOF'
                <div class="finding finding-high">
                    <div class="finding-title">🚨 Critical & High Severity Vulnerabilities</div>
                    <div class="finding-content">
                        <div class="code-block">
EOF
            grep "\[critical\]\|\[high\]" "$nuclei_file" | head -10 | sed 's/</\&lt;/g; s/>/\&gt;/g' >> "$report_file"
            cat >> "$report_file" << 'EOF'
                        </div>
                    </div>
                </div>
EOF
        fi
        
        # Show interesting findings (CTF-relevant)
        if grep -qi "login\|admin\|config\|backup\|flag\|secret\|panel\|dashboard" "$nuclei_file" 2>/dev/null; then
            cat >> "$report_file" << 'EOF'
                <div class="finding finding-medium">
                    <div class="finding-title">🎯 CTF-Relevant Findings</div>
                    <div class="finding-content">
                        <div class="code-block">
EOF
            grep -i "login\|admin\|config\|backup\|flag\|secret\|panel\|dashboard" "$nuclei_file" | head -5 | sed 's/</\&lt;/g; s/>/\&gt;/g' >> "$report_file"
            cat >> "$report_file" << 'EOF'
                        </div>
                    </div>
                </div>
EOF
        fi
        
        # Full results (collapsible)
        cat >> "$report_file" << 'EOF'
                <div class="finding finding-info">
                    <div class="finding-title" onclick="toggleSection('nuclei-full-results')">📋 Full Nuclei Results (Click to expand)</div>
                    <div id="nuclei-full-results" class="collapsible">
                        <div class="code-block">
EOF
        head -50 "$nuclei_file" | sed 's/</\&lt;/g; s/>/\&gt;/g' >> "$report_file"
        cat >> "$report_file" << 'EOF'
                        </div>
                    </div>
                </div>
EOF
    else
        cat >> "$report_file" << 'EOF'
                <div class="finding finding-info">
                    <div class="finding-title">ℹ️ No Nuclei scan results</div>
                    <div class="finding-content">
                        Nuclei vulnerability scan was not run or found no vulnerabilities.<br>
                        To enable: use the <code>-e</code> or <code>--exploits</code> flag
                    </div>
                </div>
EOF
    fi
    
    cat >> "$report_file" << 'EOF'
            </div>
        </div>
EOF
}

# Generate whatweb section
generate_whatweb_section() {
    local target=$1
    local report_file=$2
    
    cat >> "$report_file" << 'EOF'
        <div class="section">
            <div class="section-header">
                <h2 onclick="toggleSection('whatweb-section')">🌐 Web Technology Analysis</h2>
            </div>
            <div id="whatweb-section" class="section-content">
EOF
    
    # Find all whatweb files
    local whatweb_files=("$SCAN_DIR"/web/whatweb_*.txt)
    local found_whatweb=false
    
    for whatweb_file in "${whatweb_files[@]}"; do
        if [[ -f "$whatweb_file" && -s "$whatweb_file" ]]; then
            found_whatweb=true
            local port=$(basename "$whatweb_file" | sed 's/whatweb_//; s/.txt//')
            
            cat >> "$report_file" << EOF
                <div class="finding finding-info">
                    <div class="finding-title">🔍 Port $port Web Analysis</div>
                    <div class="finding-content">
                        <div class="code-block">
EOF
            # Clean up whatweb output and make it more readable
            sed 's/</\&lt;/g; s/>/\&gt;/g' "$whatweb_file" | head -20 >> "$report_file"
            cat >> "$report_file" << 'EOF'
                        </div>
                    </div>
                </div>
EOF
        fi
    done

    # Directories
    local directories_files=($SCAN_DIR/web/gobuster_*.txt)
    if [[ -f "$directories_files" && -s "$directories_files" ]]; then

        cat >> "$report_file" << EOF
            <div class="finding finding-info">
                <div class="finding-title">🔍 Directories Web Analysis</div>
                <div class="finding-content">
                    <div class="code-block">
EOF

        for file in $(ls $directories_files); do
            cat $file | jq ".results[] | .url" >> $report_file
        done

        cat >> "$report_file" << 'EOF'
                    </div>
                </div>
            </div>
EOF
    fi


    if [[ "$found_whatweb" == false ]]; then
        cat >> "$report_file" << 'EOF'
                <div class="finding finding-info">
                    <div class="finding-title">ℹ️ No WhatWeb results</div>
                    <div class="finding-content">
                        No web services were detected or WhatWeb scan was not performed.<br>
                        WhatWeb analyzes web technologies, frameworks, and server information.
                    </div>
                </div>
EOF
    fi
    
    cat >> "$report_file" << 'EOF'
            </div>
        </div>
EOF
}

# Main report generation function
generate_ctf_reports() {
    local target=$1
    local platform=$2
    
    log "INFO" "Generating CTF reports for $target"
    
    # Generate HTML report
    generate_ctf_report "$target" "$platform"
    
    # Generate markdown notes
    generate_markdown_notes "$target" "$platform"
    
    # Generate simple text summary
    generate_text_summary "$target"
    
    log "SUCCESS" "All reports generated successfully"
}

# Generate simple text summary
generate_text_summary() {
    local target=$1
    local summary_file="$SCAN_DIR/summary.txt"
    
    cat > "$summary_file" << EOF
CTF Reconnaissance Summary
========================

Target: $target
Date: $(date)
Platform: $(detect_platform "$target")

Open Ports:
$(grep "^[0-9]" "$SCAN_DIR/nmap/quick_scan.txt" 2>/dev/null | grep "open" || echo "No open ports found")

Vulnerability Scan Results:
$(if [[ -f "$SCAN_DIR/vulnerabilities/nuclei_results.txt" && -s "$SCAN_DIR/vulnerabilities/nuclei_results.txt" ]]; then
    echo "Nuclei found $(wc -l < "$SCAN_DIR/vulnerabilities/nuclei_results.txt") potential vulnerabilities"
    if grep -q "\[critical\]\|\[high\]" "$SCAN_DIR/vulnerabilities/nuclei_results.txt" 2>/dev/null; then
        echo "⚠️  Critical/High severity vulnerabilities detected!"
    fi
else
    echo "No vulnerability scan performed or no vulnerabilities found"
fi)

Web Technology Analysis:
$(if ls "$SCAN_DIR"/web/whatweb_*.txt 1> /dev/null 2>&1; then
    echo "WhatWeb analysis completed for detected web services"
    for whatweb_file in "$SCAN_DIR"/web/whatweb_*.txt; do
        if [[ -f "$whatweb_file" && -s "$whatweb_file" ]]; then
            local port=$(basename "$whatweb_file" | sed 's/whatweb_//; s/.txt//')
            echo "- Port $port: $(head -1 "$whatweb_file" | cut -d' ' -f1)"
        fi
    done
else
    echo "No web services detected"
fi)

Key Findings:
$(cat "$FINDINGS_FILE" 2>/dev/null || echo "No findings recorded")

Files Generated:
- ctf_report.html (Main HTML report)
- ctf_notes.md (Markdown notes)
- summary.txt (This file)
$(if [[ -f "$SCAN_DIR/vulnerabilities/nuclei_results.txt" ]]; then echo "- vulnerabilities/nuclei_results.txt (Nuclei scan results)"; fi)
$(if ls "$SCAN_DIR"/web/whatweb_*.txt 1> /dev/null 2>&1; then echo "- web/whatweb_*.txt (Web technology analysis)"; fi)

Next Steps:
1. Review the HTML report for detailed analysis
2. Check vulnerability scan results for immediate threats
3. Use the Metasploit commands in the exploits directory
4. Perform manual testing based on findings
5. Document any successful exploitation attempts

EOF
    
    log "SUCCESS" "Text summary generated: $summary_file"
}
