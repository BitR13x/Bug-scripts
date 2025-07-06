#!/bin/bash

# File Structure Refresh Script for CTF-Recon
# This script updates the file viewer in the HTML report with new files

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
log() {
    local level=$1
    local message=$2
    case $level in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
    esac
}

SCAN_DIR=$(pwd)
REPORT_FILE="ctf_report.html"

if [[ ! -f "$REPORT_FILE" ]]; then
    log "ERROR" "HTML report not found: $REPORT_FILE"
    exit 1
fi

log "INFO" "Refreshing file structure for: ${SCAN_DIR}"

# Generate updated file structure JSON
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

# Generate updated file structure
log "INFO" "Generating file structure JSON..."
JSON_OUTPUT="$SCAN_DIR/file_structure.json"
generate_file_contents_json > "$JSON_OUTPUT"

if [[ -f "$JSON_OUTPUT" ]]; then
    log "SUCCESS" "File structure JSON created: $JSON_OUTPUT"
else
    log "ERROR" "Failed to create file structure JSON"
    exit 1
fi

# Generate updated HTML tree
log "INFO" "Refreshing included json..."


# Replace everything between the markers
#replacement_content=$(<"$JSON_OUTPUT")
#escaped_replacement=$(printf '%s\n' "$replacement_content" | sed 's/[&/\]/\\&/g')

# JSON_OUTPUT
# Replace content inside the script tag
awk -v jsonfile="$JSON_OUTPUT" '
  BEGIN {
    in_block = 0
    while ((getline line < jsonfile) > 0) {
      # Store JSON lines into array
      json_lines[linecount++] = line
    }
    close(jsonfile)
  }
  /<script[^>]*id="file-contents"[^>]*>/ {
    print
    for (i = 0; i < linecount; i++) {
      # Print each JSON line exactly as-is
      print json_lines[i]
    }
    in_block = 1
    next
  }
  in_block && /<\/script>/ {
    print
    in_block = 0
    next
  }
  !in_block {
    print
  }
' "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"

# Generate statistics
log "INFO" "File statistics: $STATS"

echo ""
log "INFO" "File refresh completed! To update the HTML report:"
echo "Refresh your browser page"

log "INFO" "Files generated:"
echo "  - $JSON_OUTPUT (File structure data)"
echo ""
log "SUCCESS" "File viewer refresh complete!"
