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
