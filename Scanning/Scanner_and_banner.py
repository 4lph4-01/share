#########################################################################################################################################################################################
# In a python3 environment: Scanner_and_banner.py Accepts IPADDRESS AND CIDR, and attempts to grab the banner pf the port detected. By 41ph4-01 23/04/2024 & our community. 
# This scanner will perform an ARP scan to discover active hosts on the local network. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################

import socket
import struct
import ipaddress
from typing import List, Tuple

# Function to calculate the IP range from a CIDR notation
def get_ip_range_from_cidr(cidr: str) -> List[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network]
    except ValueError as e:
        print(f"Invalid CIDR: {cidr}. Error: {e}")
        return []

# Function to test if a port is open and grab the banner if possible
def test_port(target: str, port: int):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # Set timeout for connection
            s.connect((target, port))
            print(f"Port {port} on {target} is open")

            # Attempt to grab a banner
            try:
                s.sendall(b"\n")  # Send a newline to trigger a response
                response = s.recv(1024).decode("utf-8", errors="ignore").strip()
                if response:
                    print(f"Banner: {response}")
                else:
                    print(f"No banner received from port {port} on {target}")
            except socket.error:
                print(f"No banner received from port {port} on {target}")
    except socket.error:
        print(f"Port {port} on {target} is closed")

# Main function to perform scanning
def scan_subnet(cidr: str, start_port: int, end_port: int):
    ip_range = get_ip_range_from_cidr(cidr)
    if not ip_range:
        return

    for ip in ip_range:
        print(f"Scanning IP: {ip}")
        for port in range(start_port, end_port + 1):
            test_port(ip, port)

# Define the CIDR range and port range
CIDR = "192.168.1.0/24"
START_PORT = 1
END_PORT = 100

# Perform the scan
scan_subnet(CIDR, START_PORT, END_PORT)

