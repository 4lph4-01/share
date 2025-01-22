#########################################################################################################################################################################################
# Simple Port Scan & Banner Grab. By 41ph4-01 23/04/2024 & our community. 
# This scanner will perform an ARP scan to discover active hosts on the local network. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################

function Test-Port {
    param(
        [string]$target,
        [int]$port
    )

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($target, $port)
        
        $stream = $tcpClient.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $reader = New-Object System.IO.StreamReader($stream)

        # Send a newline character to trigger a response from the server
        $writer.WriteLine()

        # Read the response from the server
        $response = $reader.ReadLine()
        
        $tcpClient.Close()

        Write-Host "Port $port on $target is open"
        if ($response) {
            Write-Host "Banner: $response"
        }
        return $true
    } catch {
        Write-Host "Port $port on $target is closed"
        return $false
    }
}

# Define the target host and port range
$target = "192.168.1.100"
$startPort = 1
$endPort = 100

# Loop through each port in the range and test if it's open
for ($port = $startPort; $port -le $endPort; $port++) {
    Test-Port -target $target -port $port
}
