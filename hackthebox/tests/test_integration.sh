#!/bin/bash

# Test script for nuclei, whatweb, and file structure integration

# Set up test environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../utils.sh"

# Create test scan directory
TEST_TARGET="10.10.10.100"
export SCAN_DIR="/tmp/test_ctf_scan_$(date +%Y%m%d_%H%M%S)"
export FINDINGS_FILE="$SCAN_DIR/findings.txt"
export NOTES_FILE="$SCAN_DIR/notes.txt"

echo "Creating test environment in: $SCAN_DIR"
mkdir -p "$SCAN_DIR"/{nmap,services,exploits,web,vulnerabilities}

# Create mock nmap results
cat > "$SCAN_DIR/nmap/quick_scan.txt" << 'EOF'
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp   open  http    Apache httpd 2.4.41
443/tcp  open  https   Apache httpd 2.4.41
8080/tcp open  http    Jetty 9.4.39
EOF

cat > "$SCAN_DIR/nmap/service_scan.txt" << 'EOF'
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
443/tcp  open  https   Apache httpd 2.4.41 ((Ubuntu))
8080/tcp open  http    Jetty 9.4.39.v20210325
EOF

# Create mock service enumeration results
cat > "$SCAN_DIR/services/ftp_anonymous.txt" << 'EOF'
FTP Anonymous Login Test
========================
Target: 10.10.10.100:21
Status: Connection refused
EOF

cat > "$SCAN_DIR/services/smb_shares.txt" << 'EOF'
SMB Share Enumeration
====================
Target: 10.10.10.100
No SMB services detected on standard ports.
EOF

# Create mock nuclei results
cat > "$SCAN_DIR/vulnerabilities/nuclei_results.txt" << 'EOF'
[critical] [CVE-2021-44228] http://10.10.10.100:8080 - Apache Log4j RCE
[high] [CVE-2021-34527] http://10.10.10.100:80 - Windows Print Spooler RCE
[medium] [exposed-panels] http://10.10.10.100:80/admin - Admin Panel Exposed
[medium] [default-login] http://10.10.10.100:8080/manager - Tomcat Manager Default Credentials
[low] [tech-detect] http://10.10.10.100:80 - Apache/2.4.41 detected
[info] [http-missing-security-headers] http://10.10.10.100:80 - Missing security headers
EOF

cat > "$SCAN_DIR/vulnerabilities/nuclei_results.json" << 'EOF'
{"template":"CVE-2021-44228","type":"http","host":"http://10.10.10.100:8080","matched-at":"http://10.10.10.100:8080","info":{"name":"Apache Log4j RCE","severity":"critical"}}
{"template":"exposed-panels","type":"http","host":"http://10.10.10.100:80","matched-at":"http://10.10.10.100:80/admin","info":{"name":"Admin Panel","severity":"medium"}}
EOF

# Create mock whatweb results
cat > "$SCAN_DIR/web/whatweb_80.txt" << 'EOF'
http://10.10.10.100:80 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.100], Title[Welcome to Apache2 Ubuntu Default Page], UncommonHeaders[x-custom-header]
EOF

cat > "$SCAN_DIR/web/whatweb_8080.txt" << 'EOF'
http://10.10.10.100:8080 [200 OK] Country[RESERVED][ZZ], HTTPServer[Jetty(9.4.39.v20210325)], IP[10.10.10.100], Jetty[9.4.39.v20210325], Title[Jetty Default Page], X-Powered-By[Jetty]
EOF

# Create mock exploit files
cat > "$SCAN_DIR/exploits/metasploit_http_80.rc" << 'EOF'
use auxiliary/scanner/http/dir_scanner
set RHOSTS 10.10.10.100
set RPORT 80
run

use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS 10.10.10.100
set RPORT 80
check
EOF

cat > "$SCAN_DIR/exploits/searchsploit_apache.txt" << 'EOF'
Apache HTTP Server 2.4.41 - Remote Code Execution | exploits/linux/remote/47887.py
Apache 2.4.41 - Privilege Escalation | exploits/linux/local/47885.sh
Apache HTTP Server - Directory Traversal | exploits/multiple/remote/33575.txt
EOF

# Create mock findings
cat > "$FINDINGS_FILE" << 'EOF'
Admin panel found on port 80 (/admin)
Potential RCE vulnerability in Log4j (Critical)
Default Jetty installation detected on port 8080
Tomcat Manager with default credentials
Missing security headers on web server
EOF

# Create a sample configuration file
cat > "$SCAN_DIR/config_backup.txt" << 'EOF'
# Sample configuration file
server_name=web01
admin_user=admin
admin_pass=password123
database_host=localhost
debug_mode=true
secret_key=super_secret_key_here
EOF

# Create a sample log file
cat > "$SCAN_DIR/access.log" << 'EOF'
10.10.10.1 - - [04/Jul/2025:20:00:01 +0000] "GET / HTTP/1.1" 200 1234
10.10.10.1 - - [04/Jul/2025:20:00:02 +0000] "GET /admin HTTP/1.1" 200 5678
10.10.10.1 - - [04/Jul/2025:20:00:03 +0000] "POST /login HTTP/1.1" 302 0
10.10.10.1 - - [04/Jul/2025:20:00:04 +0000] "GET /flag.txt HTTP/1.1" 404 1024
EOF

echo "Test data created successfully!"

# Test report generation
echo "Testing report generation..."
source "$SCRIPT_DIR/report_gen.sh"

# Generate test reports
generate_ctf_reports "$TEST_TARGET" "htb"

echo ""
echo "Test completed! Check the following files:"
echo "- HTML Report: $SCAN_DIR/ctf_report.html"
echo "- Markdown Notes: $SCAN_DIR/ctf_notes.md"
echo "- Text Summary: $SCAN_DIR/summary.txt"
echo ""
echo "You can open the HTML report in a browser to verify all sections are displayed correctly."

# Verify sections exist in HTML report
echo ""
echo "Verification Results:"
echo "===================="

if grep -q "Nuclei Vulnerability Scan" "$SCAN_DIR/ctf_report.html"; then
    echo "✅ Nuclei section found in HTML report"
else
    echo "❌ Nuclei section NOT found in HTML report"
fi

if grep -q "Web Technology Analysis" "$SCAN_DIR/ctf_report.html"; then
    echo "✅ WhatWeb section found in HTML report"
else
    echo "❌ WhatWeb section NOT found in HTML report"
fi

if grep -q "Scan Files & Structure" "$SCAN_DIR/ctf_report.html"; then
    echo "✅ File Structure section found in HTML report"
else
    echo "❌ File Structure section NOT found in HTML report"
fi

if grep -q "file-contents" "$SCAN_DIR/ctf_report.html"; then
    echo "✅ Embedded file contents found in HTML report"
else
    echo "❌ Embedded file contents NOT found in HTML report"
fi

# Verify sections exist in markdown notes
if grep -q "Nuclei Vulnerability Scan" "$SCAN_DIR/ctf_notes.md"; then
    echo "✅ Nuclei section found in Markdown notes"
else
    echo "❌ Nuclei section NOT found in Markdown notes"
fi

if grep -q "Web Technology Analysis" "$SCAN_DIR/ctf_notes.md"; then
    echo "✅ WhatWeb section found in Markdown notes"
else
    echo "❌ WhatWeb section NOT found in Markdown notes"
fi

# Check if vulnerability summary is in text summary
if grep -q "Vulnerability Scan Results" "$SCAN_DIR/summary.txt"; then
    echo "✅ Vulnerability summary found in text summary"
else
    echo "❌ Vulnerability summary NOT found in text summary"
fi

echo ""
echo "File Structure Test:"
echo "==================="
echo "Created directories:"
find "$SCAN_DIR" -type d | sort
echo ""
echo "Created files:"
find "$SCAN_DIR" -type f | sort
echo ""
echo "Test environment: $SCAN_DIR"
echo "To clean up: rm -rf $SCAN_DIR"
echo ""
echo "Open the HTML report in your browser to test the interactive file viewer!"
echo "firefox $SCAN_DIR/ctf_report.html &"
