#####################################################################################################################################################################################################################################################################################################################################
# This comprehensive and superior python script integrates all necessary functionalities for advanced network mapping and external asset discovery, enhancing upon the capabilities of OWASP Amass. 
# By leveraging asynchronous operations, multiple data sources, and real-time updates, it provides a more powerful and efficient tool for network security assessments.. 
# Note: Although in the Information Gathering folder, the script will also perform scanning of discovered assets. Only use with explicit permission from those that own the assets.
# Run using python3 more_mass.py example.com, ensuring requirements are met: pip install aiohttp requests beautifulsoup4 websockets whois
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the       
# Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, # and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions: The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################

import asyncio
import aiohttp
import socket
import ssl
import requests
from bs4 import BeautifulSoup
import json
import websockets
import whois

def display_splash_screen():
    splash = """
    
   _____                               _____                                _____  .__  .__                         .___   __           ________  __      __  _____    ___________________               _____ ______________  ___ ___    _____           _______  ____ 
  /     \   ___________   ____        /     \ _____    ______ ______       /  _  \ |  | |__| ____   ____   ____   __| _/ _/  |_  ____   \_____  \/  \    /  \/  _  \  /   _____/\______   \             /  |  /_   \______   \/   |   \  /  |  |          \   _  \/_   |
 /  \ /  \ /  _ \_  __ \_/ __ \      /  \ /  \\__  \  /  ___//  ___/      /  /_\  \|  | |  |/ ___\ /    \_/ __ \ / __ |  \   __\/  _ \   /   |   \   \/\/   /  /_\  \ \_____  \  |     ___/   ______   /   |  ||   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
/    Y    (  <_> )  | \/\  ___/     /    Y    \/ __ \_\___ \ \___ \      /    |    \  |_|  / /_/  >   |  \  ___// /_/ |   |  | (  <_> ) /    |    \        /    |    \/        \ |    |      /_____/  /    ^   /   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
\____|__  /\____/|__|    \___  >____\____|__  (____  /____  >____  > /\  \____|__  /____/__\___  /|___|  /\___  >____ |   |__|  \____/  \_______  /\__/\  /\____|__  /_______  / |____|               \____   ||___||____|    \___|_  /\____   |           \_____  /___|
        \/                   \/_____/       \/     \/     \/     \/  )/          \/       /_____/      \/     \/     \/                         \/      \/         \/        \/                            |__|                     \/      |__|                 \/    
 
                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/
                                 /\      {====}     )___(
                      (\=,      //\\      )__(     /_____\
      __    |'-'-'|  //  .\    (    )    /____\     |   |
     /  \   |_____| (( \_  \    )__(      |  |      |   |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |
    /____\   |   |  (/     \    |  |      |  |      |   |
     |  |    |   |   | _.-'|    |  |      |  |      |   |
     |__|    )___(    )___(    /____\    /____\    /_____\
    (====)  (=====)  (=====)  (======)  (======)  (=======)
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)
   
 
"""

    print(splash)
    print("More_Mass for advanced network mapping and external asset discovery 41PH4-01\n")

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
            if response.startswith('['):  # Check if response is JSON from crt.sh
                json_response = json.loads(response)
                for item in json_response:
                    subdomains.add(item['name_value'])
            else:  # Process plain text response from hackertarget
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
        if w and hasattr(w, 'nets'):
            for net in w['nets']:
                if 'range' in net:
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
        print("Usage: python3 network_mapper.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    asyncio.run(main(domain))

    # Uncomment the following line to start the WebSocket server
    # asyncio.run(start_server())
