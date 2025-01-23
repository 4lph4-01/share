#########################################################################################################################################################################################
# Powershell pingsweep IPADDRESS AND Calculated /CIDR. By 41ph4-01 23/04/2024 & our community. 
# This scanner will perform an ARP scan to discover active hosts on the local network. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################

# Function to calculate the IP range from a CIDR notation
function Get-IPRangeFromCIDR {
    param (
        [string]$CIDR
    )

    $parts = $CIDR.Split('/')
    $ip = $parts[0]
    $prefix = [int]$parts[1]

    # Convert the IP address to a 32-bit integer
    $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

    # Calculate the subnet mask
    $mask = [math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefix)

    # Calculate the start and end IPs
    $networkAddress = $ipInt -band $mask
    $broadcastAddress = $networkAddress + [math]::Pow(2, 32 - $prefix) - 1

    return @(
        [System.Net.IPAddress]($networkAddress),
        [System.Net.IPAddress]($broadcastAddress)
    )
}

# Specify the CIDR range
$CIDR = "192.168.1.0/24"

# Get the start and end IPs from the CIDR range
$range = Get-IPRangeFromCIDR -CIDR $CIDR
$startIP = [System.Net.IPAddress]::Parse($range[0].ToString())
$endIP = [System.Net.IPAddress]::Parse($range[1].ToString())

# Convert start and end IPs to integers for looping
$startInt = [BitConverter]::ToUInt32(([System.Net.IPAddress]::Parse($startIP.ToString()).GetAddressBytes()))
$endInt = [BitConverter]::ToUInt32(([System.Net.IPAddress]::Parse($endIP.ToString()).GetAddressBytes()))

# Loop through each IP in the range and ping it
for ($ipInt = $startInt; $ipInt -le $endInt; $ipInt++) {
    # Convert the integer back to an IP address
    $ipBytes = [BitConverter]::GetBytes($ipInt)
    [Array]::Reverse($ipBytes)
    $currentIP = [System.Net.IPAddress]::New($ipBytes)

    # Ping the IP address
    $result = Test-Connection -ComputerName $currentIP -Count 1 -Quiet
    if ($result) {
        Write-Host "$currentIP is reachable"
    }
}

