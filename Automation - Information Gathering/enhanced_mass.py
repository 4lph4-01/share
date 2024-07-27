import asyncio
import aiohttp
import socket
import ssl
import requests
from bs4 import BeautifulSoup
import json
import websockets
import whois

# Subdomain Enumeration
async def fetch(session, url):
    async with session.get(url) as response:
        return await response.text()

async def get_subdomains(domain):
    subdomains = set()
    urls = [
        f"https://crt.sh/?q={domain}&output=json",
        f"https://api.hackertarget.com/hostsearch/?q={domain}"
    ]

    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, url) for url in urls]
        responses = await asyncio.gather(*tasks)

        for response in responses:
            if "crt.sh" in response:
                json_response = json.loads(response)
                for item in json_response:
                    subdomains.add(item['name_value'])
            else:
                lines = response.split('\n')
                for line in lines:
                    if line:
                        subdomains.add(line.split(',')[0])
    
    return list(subdomains)

# IP Address Discovery
def get_ip_ranges(domain):
    ip_ranges = []
    try:
        w = whois.whois(domain)
        if w and 'nets' in w:
            for net in w['nets']:
                ip_ranges.append(net['range'])
    except Exception as e:
        print(f"Error fetching IP ranges: {e}")
    return ip_ranges

# Port Scanning
async def scan_port(ip, port, open_ports):
    try:
        conn = asyncio.open_connection(ip, port)
        await asyncio.wait_for(conn, timeout=1.0)
        open_ports.append(port)
    except:
        pass

async def scan_ports(ip):
    open_ports = []
    tasks = [scan_port(ip, port, open_ports) for port in range(1, 1025)]
    await asyncio.gather(*tasks)
    return open_ports

# Vulnerability Detection
def get_vulnerabilities(service):
    response = requests.get(f"https://cve.circl.lu/api/search/{service}")
    if response.status_code == 200:
        return response.json()
    return []

# SSL/TLS Information
def get_ssl_info(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            return ssock.getpeercert()

# Real-Time Updates
async def live_updates(websocket, path):
    domain = await websocket.recv()
    subdomains = await get_subdomains(domain)
    ip_ranges = get_ip_ranges(domain)
    ssl_info = get_ssl_info(domain)
    vulnerabilities = []

    for subdomain in subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            open_ports = await scan_ports(ip)
            for port in open_ports:
                try:
                    service = socket.getservbyport(port)
                    vulnerabilities.extend(get_vulnerabilities(service))
                except:
                    pass
        except:
            pass
    
    result = {
        "subdomains": subdomains,
        "ip_ranges": ip_ranges,
        "ssl_info": ssl_info,
        "vulnerabilities": vulnerabilities
    }

    await websocket.send(json.dumps(result))

# Main Function
async def main(domain):
    subdomains = await get_subdomains(domain)
    ip_ranges = get_ip_ranges(domain)
    ssl_info = get_ssl_info(domain)
    vulnerabilities = []

    for subdomain in subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            open_ports = await scan_ports(ip)
            for port in open_ports:
                try:
                    service = socket.getservbyport(port)
                    vulnerabilities.extend(get_vulnerabilities(service))
                except:
                    pass
        except:
            pass
    
    result = {
        "subdomains": subdomains,
        "ip_ranges": ip_ranges,
        "ssl_info": ssl_info,
        "vulnerabilities": vulnerabilities
    }

    print(json.dumps(result, indent=4))

# WebSocket Server for Real-Time Updates
async def start_server():
    async with websockets.serve(live_updates, "localhost", 8765):
        await asyncio.Future()  # Run forever

# Run the script
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python script.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    asyncio.run(main(domain))

    # Uncomment the following line to start the WebSocket server
    # asyncio.run(start_server())
