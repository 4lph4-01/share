########################################################################################################################################################################################################################
# Powershell Script to hash the file system to identify malicious artifacts: By 41ph4-01 23/04/2024 & our community. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

# Define your VirusTotal API key
$apiKey = "YOUR_API_KEY_HERE"

# Function to submit a hash to VirusTotal
function Get-VirusTotalHash($hash) {
    $url = "https://www.virustotal.com/api/v3/files/$hash"
    $headers = @{
        "x-apikey" = $apiKey
    }

    $response = Invoke-RestMethod -Uri $url -Headers $headers

    if ($response.data.attributes.last_analysis_stats.malicious > 0) {
        Write-Host "Malicious: $($response.data.attributes.last_analysis_stats.malicious) / $($response.data.attributes.last_analysis_stats.total)"
    } else {
        Write-Host "Not detected as malicious"
    }
}

# Iterate through files and calculate hashes
Get-ChildItem 'C:\' -File -Recurse | ForEach-Object {
    $stream = try {
        [IO.FileStream]::new($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    } catch {
        # Fallback in case another process has opened the file with FileShare.ReadWrite flag.
        [IO.FileStream]::new($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    }

    if ($stream) {
        try {
            $hashInfo = Get-FileHash -InputStream $stream -Algorithm SHA256
            Write-Host "File: $($File.FullName)"
            Write-Host "SHA256 Hash: $($hashInfo.Hash)"
            Get-VirusTotalHash $hashInfo.Hash
        } finally {
            $stream.Close()
        }
    }
}


#SHA1
#SHA256
#SHA384
#SHA512
#MACTripleDES
#MD5
#RIPEMD160
