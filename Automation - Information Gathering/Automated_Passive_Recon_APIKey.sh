###############################################################################################
#Automated Information Gathering Script2 By: 4lph4-01 for simulation 11/04/2024
# Bash script: Requires URL; Addjustment to target & API
###############################################################################################

#!/bin/bash

# Check if the required tools are installed
command -v lynx >/dev/null 2>&1 || { echo >&2 "lynx is required but not installed. Aborting."; exit 1; }
command -v whois >/dev/null 2>&1 || { echo >&2 "whois is required but not installed. Aborting."; exit 1; }
command -v curl >/dev/null 2>&1 || { echo >&2 "curl is required but not installed. Aborting."; exit 1; }
command -v eyewitness >/dev/null 2>&1 || { echo >&2 "EyeWitness is required but not installed. Aborting."; exit 1; }

# Target website URL
TARGET_URL="https://example.com"

# Output directory for results
OUTPUT_DIR="passive_recon_results"
mkdir -p "$OUTPUT_DIR"

# Passive Reconnaissance
echo "=== Passive Reconnaissance ==="

# Google Dorks
echo "[*] Gathering information using Google Dorks..."
# Example: Find directories with directory listing enabled
search_query="site:example.com intitle:\"index of /\""
lynx --dump "https://www.google.com/search?q=$search_query" > "$OUTPUT_DIR/google_dorks.txt"

# Email Address Enumeration
echo "[*] Enumerating email addresses..."
# Example: Look for email addresses in WHOIS records
whois example.com | grep -i "email" > "$OUTPUT_DIR/whois_emails.txt"

# Passive DNS Analysis
echo "[*] Performing passive DNS analysis..."
# Example: Retrieve passive DNS records using PassiveTotal API
# Replace API_KEY with your PassiveTotal API key
API_KEY="your_api_key_here"
curl "https://api.passivetotal.org/v2/enrichment/subdomains?query=$TARGET_URL" -H "Authorization: Bearer $API_KEY" > "$OUTPUT_DIR/passive_dns.txt"

# Social Media Analysis
echo "[*] Analyzing social media profiles..."
# Example: Search for company information on Twitter
# Replace COMPANY_NAME with the target company name
COMPANY_NAME="example"
lynx --dump "https://twitter.com/search?q=$COMPANY_NAME" > "$OUTPUT_DIR/twitter_search.txt"

# Metadata Analysis
echo "[*] Extracting metadata from files..."
# Example: Extract metadata from publicly available documents
# Replace FILE_URL with the URL of the document
FILE_URL="https://example.com/document.pdf"
exiftool "$FILE_URL" > "$OUTPUT_DIR/metadata.txt"

# Archive.org Analysis
echo "[*] Analyzing historical snapshots using Archive.org..."
# Example: Retrieve historical snapshots of the target website
lynx --dump "https://web.archive.org/cdx/search?url=$TARGET_URL/*&output=text&fl=timestamp" > "$OUTPUT_DIR/archive_snapshots.txt"

# Passive Reconnaissance Frameworks
echo "[*] Running passive reconnaissance framework..."
# Example: Run Recon-ng for additional reconnaissance
recon-ng -r "recon/modules/discovery/info_gathering/domains-contacts" > "$OUTPUT_DIR/recon-ng_results.txt"

# Network Traffic Analysis
echo "[*] Analyzing network traffic..."
# Example: Monitor network traffic using tcpdump
sudo tcpdump -i any -w "$OUTPUT_DIR/network_traffic.pcap" -v & sleep 10; sudo pkill tcpdump

# File Type Analysis
echo "[*] Analyzing file types..."
# Example: Find potentially sensitive files hosted on the target website
lynx --dump "https://automationintesting.online/" | grep -Eo "href=\"[^ ]+\.conf\"" > "$OUTPUT_DIR/sensitive_files.txt"

# EyeWitness for Screenshots
echo "=== EyeWitness Screenshots ==="
echo "[*] Taking screenshots using EyeWitness..."
eyewitness -f "$TARGET_URL" --web --timeout 30 -d "$OUTPUT_DIR/eyewitness"

echo "=== Passive Reconnaissance Script Completed ==="
