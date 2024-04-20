###############################################################################################
#Automated Information Gathering Script By: 4lph4-01 for simulation 11/04/2024
#Bash acript: Adjust the URL to run
###############################################################################################


#!/bin/bash

# Target website URL
TARGET_URL="https://example.com"

# Output directory for results
OUTPUT_DIR="pen_test_results"

# Create output directory if it doesn't exist
mkdir -p $OUTPUT_DIR

# Passive Information Gathering
echo "=== Passive Information Gathering ==="

# Gathering subdomains using theHarvester
echo "[*] Gathering subdomains using theHarvester..."
theHarvester -d example.com -l 5000 -b google > $OUTPUT_DIR/subdomains.txt

# Spidering the website using Wget
echo "[*] Spidering the website using Wget..."
wget --spider -r -l inf -o $OUTPUT_DIR/spider.log $TARGET_URL

# HTTP Header Analysis
echo "=== HTTP Header Analysis ==="
echo "[*] Fetching HTTP headers using curl..."
curl -I $TARGET_URL > $OUTPUT_DIR/http_headers.txt

# SSL/TLS Certificate Analysis
echo "=== SSL/TLS Certificate Analysis ==="
echo "[*] Fetching SSL certificate information..."
openssl s_client -connect example.com:443 -servername example.com < /dev/null | openssl x509 -noout -text > $OUTPUT_DIR/ssl_certificate_info.txt

# Robots.txt Analysis
echo "=== Robots.txt Analysis ==="
echo "[*] Fetching robots.txt file..."
curl $TARGET_URL/robots.txt > $OUTPUT_DIR/robots.txt

# Sitemap Analysis
echo "=== Sitemap Analysis ==="
echo "[*] Fetching sitemap..."
curl $TARGET_URL/sitemap.xml > $OUTPUT_DIR/sitemap.xml

# Third-party Component Analysis (Example: jQuery)
echo "=== Third-party Component Analysis ==="
echo "[*] Checking if jQuery is used..."
curl -s $TARGET_URL | grep -i "jquery" > $OUTPUT_DIR/jquery_usage.txt

echo "=== Passive Penetration Testing Script Completed ==="
