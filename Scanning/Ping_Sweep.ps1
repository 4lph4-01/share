#########################################################################################################################################################################################
# Simple_PowerShell_Ping_Sweep
# This scanner will perform an ARP scan to discover active hosts on the local network. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################

# Define the range of IP addresses to ping
$startIP = "Start IP"
$endIP = "End IP"

# Loop through each IP address in the range and ping it
for ($i = [System.Net.IPAddress]::Parse($startIP).GetAddressBytes()[3]; $i -le [System.Net.IPAddress]::Parse($endIP).GetAddressBytes()[3]; $i++) {
    $currentIP = "192.168.1.$i"
    $result = Test-Connection -ComputerName $currentIP -Count 1 -Quiet
    if ($result) {
        Write-Host "$currentIP is reachable"
    }
}
