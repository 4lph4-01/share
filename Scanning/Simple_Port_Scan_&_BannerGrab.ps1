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
