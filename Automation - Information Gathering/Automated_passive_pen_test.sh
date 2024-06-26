########################################################################################################################################################################################
# Nix automated Information Gathering Script By: 41ph4-01 for simulation 11/04/2024
# Bash script: Installs packages and binaries; Adjust the URL to run.
# Eyewitness requires manual configuration, Dirctions to GitHub page for installation.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################################


#!/bin/bash

# Function to install required software
install_required() {
    local package=$1
    echo "Installing $package..."
    # Check the package manager and install the package
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y $package
    elif command -v yum &>/dev/null; then
        sudo yum install -y $package
    elif command -v brew &>/dev/null; then
        brew install $package
    else
        echo "Error: Package manager not found. Please install $package manually."
        exit 1
    fi
}

# Check if the required tools are installed and install them if necessary
check_and_install() {
    local tool=$1
    local package=$2
    command -v $tool >/dev/null 2>&1 || { echo >&2 "$tool is required but not installed. Installing $tool..."; install_required $package; }
}

# Check and install required tools
check_and_install theHarvester theHarvester
check_and_install wget wget
check_and_install curl curl
check_and_install openssl openssl
check_and_install eyewitness EyeWitness

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
