#########################################################################################################################################################################################
# In a python environment: python scanner.py IPADDRESS AND CIDR/SUBNET HERE
# This scanner will perform an ARP scan to discover active hosts on the local network. 
#Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################

from scapy.all import ARP, Ether, srp
import argparse

def scan_network(target_ip):
    # Create ARP request packet
    arp_request = ARP(pdst=target_ip)

    # Create Ether broadcast packet
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine the two packets
    arp_broadcast = ether_frame/arp_request

    # Send the packet and capture responses
    answered_list = srp(arp_broadcast, timeout=1, verbose=False)[0]

    # Extract MAC addresses from responses
    active_hosts = []
    for element in answered_list:
        active_host = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        active_hosts.append(active_host)

    return active_hosts

def print_results(active_hosts):
    print("Active hosts on the network:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for host in active_hosts:
        print(f"{host['ip']}\t\t{host['mac']}")

def main():
    parser = argparse.ArgumentParser(description="Simple network scanner using ARP")
    parser.add_argument("target", help="Target IP address or IP range (e.g., 192.168.1.1/24)")
    args = parser.parse_args()

    target_ip = args.target

    active_hosts = scan_network(target_ip)
    print_results(active_hosts)

if __name__ == "__main__":
    main()