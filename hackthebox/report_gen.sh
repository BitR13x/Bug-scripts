#!/bin/bash

# CTF Report generation module - Template-based version

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# Generate CTF-style HTML report using templates
generate_ctf_report() {
    local target=$1
    local platform=$2
    local report_file="$SCAN_DIR/ctf_report.html"
    
    if [[ -f "static/refresh_file_viewer.sh" ]]; then
        cp static/refresh_file_viewer.sh $SCAN_DIR/ 2>/dev/null
    else
        log "WARN" "Refresh script for file structure missing"
    fi

    log "INFO" "Generating CTF report for $target using templates"
    
    # Get script directory
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local template_dir="$script_dir/static/htmltemplate"
    
    # Check if templates exist
    if [[ ! -d "$template_dir" ]]; then
        log "ERROR" "Template directory not found: $template_dir"
        return 1
    fi
    
    # Load main template
    local main_template=""
    if [[ -f "$template_dir/main.html" ]]; then
        main_template=$(cat "$template_dir/main.html")
    else
        log "ERROR" "Main template not found"
        return 1
    fi
    
    # Generate content sections
    local header_content=$(generate_header_content "$target" "$platform")
    local stats_content=$(generate_stats_content)
    local sections_content=$(generate_all_sections_content)
    local footer_content=$(generate_footer_content)
    
    # Replace placeholders in main template
    main_template="${main_template//<!-- HEADER_PLACEHOLDER -->/$header_content}"
    main_template="${main_template//<!-- STATS_PLACEHOLDER -->/$stats_content}"
    main_template="${main_template//<!-- SECTIONS_PLACEHOLDER -->/$sections_content}"
    main_template="${main_template//<!-- FOOTER_PLACEHOLDER -->/$footer_content}"
    
    # Add additional CSS and JavaScript
    local additional_css=""
    if [[ -f "$template_dir/styles.css" ]]; then
        additional_css=$(cat "$template_dir/styles.css")
        main_template="${main_template//<\/style>/$additional_css</style>}"
    fi
    
    # Add JavaScript before closing body tag
    local file_viewer_js=""
    local notes_js=""
    if [[ -f "$template_dir/file_viewer_js.html" ]]; then
        file_viewer_js=$(cat "$template_dir/file_viewer_js.html")
    fi
    if [[ -f "$template_dir/notes_js.html" ]]; then
        notes_js=$(cat "$template_dir/notes_js.html")
    fi
    
    # Write the main template first
    echo "$main_template" > "$report_file"
    
    # Add JavaScript before closing body tag using a more reliable method
    # Create temporary files for the JavaScript content
    local temp_file_js=$(mktemp)
    local temp_notes_js=$(mktemp)
    
    echo "$file_viewer_js" > "$temp_file_js"
    echo "$notes_js" > "$temp_notes_js"
    
    # Use sed to insert JavaScript before </body> tag
    # First insert file viewer JS
    sed -i '/<\/body>/i\
<!-- File Viewer JavaScript -->' "$report_file"
    
    sed -i '/<\/body>/r '"$temp_file_js" "$report_file"
    
    # Then insert notes JS
    sed -i '/<\/body>/i\
<!-- Notes JavaScript -->' "$report_file"
    
    sed -i '/<\/body>/r '"$temp_notes_js" "$report_file"

    # Generate file_structure.json for dynamic loading
    local temp_json_file=$(mktemp)
    generate_file_contents_json > "$temp_json_file"

    log "INFO" "Generating file structure JSON"
    cp $temp_json_file "$SCAN_DIR/file_structure.json" 2>/dev/null

    sed -i "/{{FILE_CONTENTS_JSON}}/r $temp_json_file" "$report_file"
    sed -i '/{{FILE_CONTENTS_JSON}}/d' "$report_file"

    # Generate file tree HTML for refresh functionality
    generate_file_tree_html > "$SCAN_DIR/file_tree.html"

    # Clean up temporary files
    rm -f "$temp_file_js" "$temp_notes_js" "$temp_json_file"
    
    log "SUCCESS" "CTF report generated: $report_file"
}

# Helper functions to generate content sections
generate_header_content() {
    local target=$1
    local platform=$2
    local template_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/static/htmltemplate"
    
    if [[ -f "$template_dir/header.html" ]]; then
        local content=$(cat "$template_dir/header.html")
        content="${content//\{\{TARGET\}\}/$target}"
        content="${content//\{\{SCAN_DATE\}\}/$(date)}"
        
        # Platform-specific replacements
        case $platform in
            "HackTheBox")
                content="${content//\{\{PLATFORM_CLASS\}\}/htb}"
                content="${content//\{\{PLATFORM_BADGE\}\}/🟢 HackTheBox}"
                ;;
            "TryHackMe")
                content="${content//\{\{PLATFORM_CLASS\}\}/thm}"
                content="${content//\{\{PLATFORM_BADGE\}\}/🔴 TryHackMe}"
                ;;
            *)
                content="${content//\{\{PLATFORM_CLASS\}\}/unknown}"
                content="${content//\{\{PLATFORM_BADGE\}\}/❓ Unknown Platform}"
                ;;
        esac
        
        echo "$content"
    fi
}

generate_stats_content() {
    local template_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/static/htmltemplate"
    
    if [[ -f "$template_dir/stats.html" ]]; then
        local content=$(cat "$template_dir/stats.html")
        local open_ports=$(grep -c "open" "$SCAN_DIR/nmap/quick_scan.txt" 2>/dev/null || echo "0")
        local services=$(find "$SCAN_DIR/services" -name "*.txt" 2>/dev/null | wc -l)
        local findings=$(wc -l < "$FINDINGS_FILE" 2>/dev/null || echo "0")
        local exploits=$(find "$SCAN_DIR/exploits" -name "*.rc" 2>/dev/null | wc -l)
        
        content="${content//\{\{OPEN_PORTS\}\}/$open_ports}"
        content="${content//\{\{SERVICES\}\}/$services}"
        content="${content//\{\{FINDINGS\}\}/$findings}"
        content="${content//\{\{EXPLOITS\}\}/$exploits}"
        
        echo "$content"
    fi
}

generate_all_sections_content() {
    local sections=""
    
    # Port section
    sections+=$(generate_port_section_content)
    
    # Services section  
    sections+=$(generate_services_section_content)
    
    # WhatWeb section
    sections+=$(generate_whatweb_section_content)
    
    # Nuclei section
    sections+=$(generate_nuclei_section_content)
    
    # File structure section
    sections+=$(generate_file_structure_section_content)
    
    # Notes section
    sections+=$(generate_notes_section_content)
    
    echo "$sections"
}

generate_port_section_content() {
    local template_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/static/htmltemplate"
    
    if [[ -f "$template_dir/port_section.html" ]]; then
        local content=$(cat "$template_dir/port_section.html")
        local port_rows=""
        local detailed_output=""
        
        # Generate port table rows
        if [[ -f "$SCAN_DIR/nmap/quick_scan.txt" ]]; then
            while read -r line; do
                if [[ $line =~ ^([0-9]+)/tcp[[:space:]]+open[[:space:]]+([a-zA-Z0-9_-]+)[[:space:]]+(.*) ]]; then
                    local port="${BASH_REMATCH[1]}"
                    local service="${BASH_REMATCH[2]}"
                    local version="${BASH_REMATCH[3]}"

                    port_rows+="                        <tr>
                            <td><strong>$port</strong></td>
                            <td><span class=\"port-open\">Open</span></td>
                            <td>$service</td>
                            <td>${version:-"Unknown"}</td>
                        </tr>"
                fi
            done < "$SCAN_DIR/nmap/quick_scan.txt"
            
            # Get detailed output
            if [[ -f "$SCAN_DIR/nmap/service_scan.txt" ]]; then
                detailed_output=$(cat "$SCAN_DIR/nmap/service_scan.txt")
            fi
        fi
        
        content="${content//\{\{PORT_TABLE_ROWS\}\}/$port_rows}"
        content="${content//\{\{DETAILED_SCAN_OUTPUT\}\}/$detailed_output}"
        
        echo "$content"
    fi
}

generate_services_section_content() {
    local template_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/static/htmltemplate"
    
    if [[ -f "$template_dir/services_section.html" ]]; then
        local content=$(cat "$template_dir/services_section.html")
        local service_findings=""
        
        # Generate service findings
        for service_file in "$SCAN_DIR/services"/*.txt; do
            if [[ -f "$service_file" ]]; then
                local service_name=$(basename "$service_file" .txt)
                local service_content=$(head -50 "$service_file" | sed 's/</\&lt;/g; s/>/\&gt;/g')
                
                service_findings+="                <div class=\"finding finding-info\">
                    <div class=\"finding-title\">$service_name</div>
                    <button class=\"toggle-btn\" onclick=\"toggleSection('$service_name-details')\">Show Details</button>
                    <div id=\"$service_name-details\" class=\"collapsible\">
                        <div class=\"code-block\">
$service_content
                        </div>
                    </div>
                </div>"
            fi
        done
        
        content="${content//\{\{SERVICE_FINDINGS\}\}/$service_findings}"
        
        echo "$content"
    fi
}

generate_whatweb_section_content() {
    local template_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/static/htmltemplate"
    
    if [[ -f "$template_dir/whatweb_section.html" ]]; then
        local content=$(cat "$template_dir/whatweb_section.html")
        local whatweb_content=""
        
        # Find all whatweb files
        local found_whatweb=false
        for whatweb_file in "$SCAN_DIR"/web/whatweb_*.txt; do
            if [[ -f "$whatweb_file" && -s "$whatweb_file" ]]; then
                found_whatweb=true
                local port=$(basename "$whatweb_file" | sed 's/whatweb_//; s/.txt//')
                local file_content=$(head -20 "$whatweb_file" | sed 's/</\&lt;/g; s/>/\&gt;/g')
                
                whatweb_content+="                <div class=\"finding finding-info\">
                    <div class=\"finding-title\">🔍 Port $port Web Analysis</div>
                    <div class=\"finding-content\">
                        <div class=\"code-block\">
$file_content
                        </div>
                    </div>
                </div>"
            fi
        done
        
        if [[ "$found_whatweb" == false ]]; then
            whatweb_content="                <div class=\"finding finding-info\">
                    <div class=\"finding-title\">ℹ️ No WhatWeb results</div>
                    <div class=\"finding-content\">
                        No web services were detected or WhatWeb scan was not performed.<br>
                        WhatWeb analyzes web technologies, frameworks, and server information.
                    </div>
                </div>"
        fi
        
        content="${content//\{\{WHATWEB_CONTENT\}\}/$whatweb_content}"
        
        echo "$content"
    fi
}

generate_nuclei_section_content() {
    local template_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/static/htmltemplate"
    
    if [[ -f "$template_dir/nuclei_section.html" ]]; then
        local content=$(cat "$template_dir/nuclei_section.html")
        local nuclei_content=""
        local nuclei_file="$SCAN_DIR/vulnerabilities/nuclei_results.txt"
        
        if [[ -f "$nuclei_file" && -s "$nuclei_file" ]]; then
            local total_vulns=$(wc -l < "$nuclei_file")
            local critical_count=$(grep -c "\[critical\]" "$nuclei_file" 2>/dev/null || echo "0")
            local high_count=$(grep -c "\[high\]" "$nuclei_file" 2>/dev/null || echo "0")
            local medium_count=$(grep -c "\[medium\]" "$nuclei_file" 2>/dev/null || echo "0")
            local low_count=$(grep -c "\[low\]" "$nuclei_file" 2>/dev/null || echo "0")
            
            nuclei_content="                <div class=\"finding finding-info\">
                    <div class=\"finding-title\">📊 Vulnerability Summary</div>
                    <div class=\"finding-content\">
                        <strong>Total Vulnerabilities Found:</strong> $total_vulns<br>
                        <span style=\"color: var(--accent-red);\">Critical: $critical_count</span> | 
                        <span style=\"color: var(--accent-yellow);\">High: $high_count</span> | 
                        <span style=\"color: var(--accent-blue);\">Medium: $medium_count</span> | 
                        <span style=\"color: var(--text-secondary);\">Low: $low_count</span>
                    </div>
                </div>"
            
            # Add critical/high findings if they exist
            if [[ $critical_count -gt 0 || $high_count -gt 0 ]]; then
                local critical_findings=$(grep "\[critical\]\|\[high\]" "$nuclei_file" | head -10 | sed 's/</\&lt;/g; s/>/\&gt;/g')
                nuclei_content+="                <div class=\"finding finding-high\">
                    <div class=\"finding-title\">🚨 Critical & High Severity Vulnerabilities</div>
                    <div class=\"finding-content\">
                        <div class=\"code-block\">
$critical_findings
                        </div>
                    </div>
                </div>"
            fi
            
            # Add full results
            local full_results=$(head -50 "$nuclei_file" | sed 's/</\&lt;/g; s/>/\&gt;/g')
            nuclei_content+="                <div class=\"finding finding-info\">
                    <div class=\"finding-title\" onclick=\"toggleSection('nuclei-full-results')\">📋 Full Nuclei Results (Click to expand)</div>
                    <div id=\"nuclei-full-results\" class=\"collapsible\">
                        <div class=\"code-block\">
$full_results
                        </div>
                    </div>
                </div>"
        else
            nuclei_content="                <div class=\"finding finding-info\">
                    <div class=\"finding-title\">ℹ️ No Nuclei scan results</div>
                    <div class=\"finding-content\">
                        Nuclei vulnerability scan was not run or found no vulnerabilities.<br>
                        To enable: use the <code>-e</code> or <code>--exploits</code> flag
                    </div>
                </div>"
        fi
        
        content="${content//\{\{NUCLEI_CONTENT\}\}/$nuclei_content}"
        
        echo "$content"
    fi
}

generate_file_structure_section_content() {
    local template_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/static/htmltemplate"
    
    if [[ -f "$template_dir/file_structure_section.html" ]]; then
        local content=$(cat "$template_dir/file_structure_section.html")
        
        # Provide empty file tree content - JavaScript will populate it dynamically
        local file_tree_content="<div class=\"loading-message\">Loading file structure from embedded data...</div>"
        
        # No existing notes for now
        local existing_notes=""
        if [[ -f "$NOTES_FILE" && -s "$NOTES_FILE" ]]; then
            local notes_content=$(sed 's/</\&lt;/g; s/>/\&gt;/g' "$NOTES_FILE")
            existing_notes="                <div class=\"finding finding-info\">
                    <div class=\"finding-title\">📄 Existing Notes File</div>
                    <div class=\"finding-content\">
                        <div class=\"code-block\">
$notes_content
                        </div>
                    </div>
                </div>"
        fi
        
        content="${content//\{\{FILE_TREE_CONTENT\}\}/$file_tree_content}"
        content="${content//\{\{SCAN_DIR\}\}/$SCAN_DIR}"
        content="${content//\{\{EXISTING_NOTES\}\}/$existing_notes}"
        
        echo "$content"
    fi
}

generate_notes_section_content() {
    local template_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/static/htmltemplate"
    
    if [[ -f "$template_dir/notes_section.html" ]]; then
        local content=$(cat "$template_dir/notes_section.html")
        local existing_notes=""
        
        # Add existing notes from file if available
        if [[ -f "$NOTES_FILE" && -s "$NOTES_FILE" ]]; then
            local notes_content=$(sed 's/</\&lt;/g; s/>/\&gt;/g' "$NOTES_FILE")
            existing_notes="                <div class=\"finding finding-info\">
                    <div class=\"finding-title\">📄 Existing Notes File</div>
                    <div class=\"finding-content\">
                        <div class=\"code-block\">
$notes_content
                        </div>
                    </div>
                </div>"
        fi
        
        content="${content//\{\{EXISTING_NOTES\}\}/$existing_notes}"
        
        echo "$content"
    fi
}

generate_footer_content() {
    local template_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/static/htmltemplate"
    
    if [[ -f "$template_dir/footer.html" ]]; then
        local content=$(cat "$template_dir/footer.html")
        content="${content//\{\{GENERATION_DATE\}\}/$(date)}"
        echo "$content"
    fi
}

generate_file_tree_html() {
    if [[ -d "$SCAN_DIR" ]]; then
        echo "<div class=\"tree-item folder\" onclick=\"toggleFolder('scan-root')\">📁 $(basename "$SCAN_DIR")/</div>"
        echo "<div id=\"scan-root\" class=\"tree-content active\">"
        
        for item in "$SCAN_DIR"/*; do
            if [[ -d "$item" ]]; then
                local dir_name=$(basename "$item")
                local file_count=$(find "$item" -type f 2>/dev/null | wc -l)
                echo "    <div class=\"tree-item folder\" onclick=\"toggleFolder('$dir_name-folder')\">📁 $dir_name/ ($file_count files)</div>"
                echo "    <div id=\"$dir_name-folder\" class=\"tree-content\">"
                
                for file in "$item"/*; do
                    if [[ -f "$file" ]]; then
                        local file_name=$(basename "$file")
                        local file_size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "0B")
                        local file_id="${dir_name}_${file_name//[^a-zA-Z0-9]/_}"
                        echo "        <div class=\"tree-item file\" onclick=\"viewFile('$file_id')\">📄 $file_name ($file_size)</div>"
                    fi
                done
                
                echo "    </div>"
            elif [[ -f "$item" ]]; then
                local file_name=$(basename "$item")
                if [[ "$file_name" == "ctf_report.html" ]]; then
                    continue
                fi
                local file_size=$(du -h "$item" 2>/dev/null | cut -f1 || echo "0B")
                local file_id="root_${file_name//[^a-zA-Z0-9]/_}"
                echo "    <div class=\"tree-item file\" onclick=\"viewFile('$file_id')\">📄 $file_name ($file_size)</div>"
            fi
        done
        
        echo "</div>"
    fi
}

generate_file_contents_json() {
    echo "{"
    local first_file=true
    
    for item in "$SCAN_DIR"/*; do
        if [[ -d "$item" ]]; then
            local dir_name=$(basename "$item")
            for file in "$item"/*; do
                if [[ -f "$file" ]]; then
                    local file_name=$(basename "$file")
                    local file_id="${dir_name}_${file_name//[^a-zA-Z0-9]/_}"
                    
                    if [[ "$first_file" == false ]]; then
                        echo ","
                    fi
                    first_file=false
                    
                    echo -n "    \"$file_id\": {"
                    echo -n "\"name\": \"$file_name\", "
                    echo -n "\"path\": \"$file\", "
                    echo -n "\"dir\": \"$dir_name\", "
                    
                    local file_size_bytes=$(stat -c%s "$file" 2>/dev/null || echo "0")
                    if [[ $file_size_bytes -lt 10000 ]] && [[ "$file_name" != "ctf_report.html" ]] && file "$file" | grep -q "text\|ASCII\|UTF-8\|empty"; then
                        echo -n "\"content\": "
                        # Use jq to properly escape JSON content
                        if command -v jq >/dev/null 2>&1; then
                            cat "$file" | jq -Rs . | tr -d '\n'
                        else
                            # Fallback: use python for JSON escaping
                            python3 -c "
import json
import sys
try:
    with open('$file', 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    print(json.dumps(content), end='')
except Exception as e:
    print('\"[Error reading file: ' + str(e) + ']\"', end='')
" 2>/dev/null
                        fi
                        echo -n ", \"type\": \"text\""
                    else
                        echo -n "\"content\": \"[File excluded from viewer or binary file]\", \"type\": \"excluded\""
                    fi
                    echo -n "}"
                fi
            done
        elif [[ -f "$item" ]]; then
            local file_name=$(basename "$item")
            if [[ "$file_name" == "ctf_report.html" ]]; then
                continue
            fi
            
            if [[ "$first_file" == false ]]; then
                echo ","
            fi
            first_file=false
            
            local file_id="root_${file_name//[^a-zA-Z0-9]/_}"
            echo -n "    \"$file_id\": {"
            echo -n "\"name\": \"$file_name\", "
            echo -n "\"path\": \"$item\", "
            echo -n "\"dir\": \"root\", "
            
            local file_size_bytes=$(stat -c%s "$item" 2>/dev/null || echo "0")
            if [[ $file_size_bytes -lt 10000 ]] && file "$item" | grep -q "text\|ASCII\|UTF-8\|empty"; then
                echo -n "\"content\": "
                # Use jq to properly escape JSON content
                if command -v jq >/dev/null 2>&1; then
                    cat "$item" | jq -Rs . | tr -d '\n'
                else
                    # Fallback: use python for JSON escaping
                    python3 -c "
import json
import sys
try:
    with open('$item', 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    print(json.dumps(content), end='')
except Exception as e:
    print('\"[Error reading file: ' + str(e) + ']\"', end='')
" 2>/dev/null
                fi
                echo -n ", \"type\": \"text\""
            else
                echo -n "\"content\": \"[File excluded from viewer or binary file]\", \"type\": \"excluded\""
            fi
            echo -n "}"
        fi
    done
    echo ""
    echo "}"
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
- **Services:** $(find "$SCAN_DIR/services" -name "*.txt" 2>/dev/null | wc -l)
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
