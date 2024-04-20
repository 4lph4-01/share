###############################################################################################
#Automated Information Gathering Script By: 4lph4-01 for simulation 11/04/2024
#Bash script: Ensure required packaages and binaries are installed; Adjust the URL to run
###############################################################################################


#!/bin/bash

# Check if the required tools are installed
command -v theHarvester >/dev/null 2>&1 || { echo >&2 "theHarvester is required but not installed. Aborting."; exit 1; }
command -v wget >/dev/null 2>&1 || { echo >&2 "wget is required but not installed. Aborting."; exit 1; }
command -v curl >/dev/null 2>&1 || { echo >&2 "curl is required but not installed. Aborting."; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo >&2 "openssl is required but not installed. Aborting."; exit 1; }
command -v eyewitness >/dev/null 2>&1 || { echo >&2 "EyeWitness is required but not installed. Aborting."; exit 1; }

# Check if target URL is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

# Target website URL
TARGET_URL="$1"

# Output directory for results
OUTPUT_DIR="pen_test_results"
mkdir -p "$OUTPUT_DIR"

# Passive Information Gathering
echo "=== Passive Information Gathering ==="

# Gathering subdomains using theHarvester
echo "[*] Gathering subdomains using theHarvester..."
theHarvester -d "$TARGET_URL" -l 5000 -b google > "$OUTPUT_DIR/subdomains.txt"

# Spidering the website using Wget
echo "[*] Spidering the website using Wget..."
wget --spider -r -l inf -o "$OUTPUT_DIR/spider.log" "$TARGET_URL"

# HTTP Header Analysis
echo "=== HTTP Header Analysis ==="
echo "[*] Fetching HTTP headers using curl..."
curl -I "$TARGET_URL" > "$OUTPUT_DIR/http_headers.txt"

# SSL/TLS Certificate Analysis
echo "=== SSL/TLS Certificate Analysis ==="
echo "[*] Fetching SSL certificate information..."
openssl s_client -connect "$TARGET_URL":443 -servername "$TARGET_URL" < /dev/null | openssl x509 -noout -text > "$OUTPUT_DIR/ssl_certificate_info.txt"

# Robots.txt Analysis
echo "=== Robots.txt Analysis ==="
echo "[*] Fetching robots.txt file..."
curl "$TARGET_URL/robots.txt" > "$OUTPUT_DIR/robots.txt"

# Sitemap Analysis
echo "=== Sitemap Analysis ==="
echo "[*] Fetching sitemap..."
curl "$TARGET_URL/sitemap.xml" > "$OUTPUT_DIR/sitemap.xml"

# Third-party Component Analysis (Example: jQuery)
echo "=== Third-party Component Analysis ==="
echo "[*] Checking if jQuery is used..."
curl -s "$TARGET_URL" | grep -i "jquery" > "$OUTPUT_DIR/jquery_usage.txt"

# EyeWitness for Screenshots
echo "=== EyeWitness Screenshots ==="
echo "[*] Taking screenshots using EyeWitness..."
eyewitness -f "$TARGET_URL" --web --timeout 30 -d "$OUTPUT_DIR/eyewitness"

echo "=== Passive Penetration Testing Script Completed ==="
