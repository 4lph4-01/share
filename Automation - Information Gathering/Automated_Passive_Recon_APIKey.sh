########################################################################################################################################################################################################################
# Nix Automated Information Gathering Script2 By: 41ph4-01 for simulation 11/04/2024
# Bash script: Automated installation of Packages & Binaries Note: Eyewitness requires manual install & configuration,
# Special thanks to RedSiege Infomration Security for Eyewitness. EyeWitness installation: https://github.com/FortyNorthSecurity/EyeWitness; 
# Addjustment to target & API required. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

#!/bin/bash

# Check if the required tools are installed and install missing ones if necessary
check_installation() {
    local missing=0
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo >&2 "$tool is required but not installed. Installing..."
            if [ "$tool" = "lynx" ]; then
                sudo apt-get install -y lynx
            elif [ "$tool" = "whois" ]; then
                sudo apt-get install -y whois
            elif [ "$tool" = "curl" ]; then
                sudo apt-get install -y curl
            elif [ "$tool" = "eyewitness" ]; then
                echo "EyeWitness installation: https://github.com/FortyNorthSecurity/EyeWitness"
                missing=1
            fi
        }
    done
    return $missing
}

# Target website URL
TARGET_URL="https://example.com"

# Output directory for results
OUTPUT_DIR="passive_recon_results"
mkdir -p "$OUTPUT_DIR"

# Passive Reconnaissance
echo "=== Passive Reconnaissance ==="

# Check and install missing tools
if check_installation lynx whois curl eyewitness; then
    echo "Missing software installed. Continuing..."
else
    echo "Failed to install missing software. Exiting."
    exit 1
fi

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
lynx --dump "$TARGET_URL" | grep -Eo "href=\"[^ ]+\.conf\"" > "$OUTPUT_DIR/sensitive_files.txt"

# EyeWitness for Screenshots
echo "=== EyeWitness Screenshots ==="
echo "[*] Taking screenshots using EyeWitness..."
eyewitness -f "$TARGET_URL" --web --timeout 30 -d "$OUTPUT_DIR/eyewitness"

echo "=== Passive Reconnaissance Script Completed ==="
