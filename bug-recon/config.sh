#!/bin/bash

# Configuration file for AutoRecon
# Modify these paths according to your system setup

# Tool paths
export DIRSEARCH_WORDLIST="$HOME/tools/SecLists/Discovery/Web-Content/dirsearch.txt"
export FEROXBUSTER="/usr/bin/feroxbuster"
export PARAMSPIDER="$HOME/tools/ParamSpider/paramspider.py"
export MASSDNS_PATH="$HOME/tools/massdns"

# HTTP scanning configuration
export HTTPX_PORTS="80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4443,4444,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8444,8500,8800,8834,8880,8881,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,27201,32000,55440,55672"

# Rate limiting
export REQUEST_PER_SEC=10
export MAX_THREADS=50
export HTTPX_THREADS=100

# Server configuration
export SERVER_IP="localhost"
export SCREENSHOT_PORT=30200

# Output configuration
export OUTPUT_DIR="./scans"
export BACKUP_DIR="backup"
export REPORTS_DIR="reports"
export SCREENSHOTS_DIR="screenshots"

# Notification settings
export ENABLE_NOTIFICATIONS=true
export DISCORD_WEBHOOK=""

# Blacklist domains (comma separated)
export BLACKLIST_DOMAINS=""

# Colors
export RED=$(tput setaf 1)
export GREEN=$(tput setaf 2)
export YELLOW=$(tput setaf 3)
export BLUE=$(tput setaf 4)
export RESET=$(tput sgr0)

# Logging configuration
export LOG_LEVEL="INFO"  # DEBUG, INFO, WARN, ERROR
export LOG_FILE="autorecon.log"
export ENABLE_VERBOSE=false
