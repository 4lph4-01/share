#########################################################################################################################################################################################################################
# Initial powershell script for Forensic Artifact Collection. Note usage: Save as Forensic_Collection.ps1, Right-click PowerShell → Run as Administrator, Navigate to script location and run: .
# \Forensic_Collection.ps1, Wait for completion (5-15 minutes depending on system size), Analyse the output folder structure. By 41PH4-01 and our community.      
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

$startTime = Get-Date
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outDir = "C:\Forensic_Collect_$timestamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host "Collecting forensic artifacts to: $outDir" -ForegroundColor Green
Write-Host ""

# Create subfolders
$subFolders = @("network", "processes", "services", "registry", "accounts", "files", "tasks", "logs", "misc")
foreach ($folder in $subFolders) {
    New-Item -ItemType Directory -Path "$outDir\$folder" -Force | Out-Null
}

# ============================================================================
# NETWORK COLLECTION
# ============================================================================
Write-Host "[1/8] Collecting network information..." -ForegroundColor Yellow

net view \\127.0.0.1 > "$outDir\network\net_view.txt" 2>&1
net session > "$outDir\network\net_session.txt" 2>&1
net use > "$outDir\network\net_use.txt" 2>&1
nbtstat -S > "$outDir\network\nbtstat_S.txt" 2>&1

netstat -na > "$outDir\network\netstat_na.txt" 2>&1
netstat -b > "$outDir\network\netstat_b.txt" 2>&1

# Bounded loop for`netstat -na 5` / `netstat -nao 5`
$snapshotCount = 5
$intervalSec  = 5
for ($i = 1; $i -le $snapshotCount; $i++) {
    Write-Host "  netstat snapshot $i of $snapshotCount..." -ForegroundColor DarkGray
    "--- Snapshot $i ($(Get-Date -Format 'HH:mm:ss')) ---" | Out-File -Append "$outDir\network\netstat_na_timed.txt"
    netstat -na | Out-File -Append "$outDir\network\netstat_na_timed.txt"
    "--- Snapshot $i PID map ($(Get-Date -Format 'HH:mm:ss')) ---" | Out-File -Append "$outDir\network\netstat_nao_timed.txt"
    netstat -nao | Out-File -Append "$outDir\network\netstat_nao_timed.txt"
    if ($i -lt $snapshotCount) { Start-Sleep -Seconds $intervalSec }
}

#  Advfirewall
netsh advfirewall show currentprofile > "$outDir\network\netsh_advfirewall_profile.txt" 2>&1
netsh advfirewall firewall show rule name=all > "$outDir\network\netsh_advfirewall_all_rules.txt" 2>&1

# TCP connection mapping with timestamps
for ($i = 0; $i -lt 3; $i++) {
    netstat -anob >> "$outDir\network\netstat_timeline_run$i.txt" 2>&1
    Start-Sleep -Seconds 10
}

# ============================================================================
# PROCESS COLLECTION
# ============================================================================
Write-Host "[2/8] Collecting process information..." -ForegroundColor Yellow

tasklist > "$outDir\processes\tasklist.txt" 2>&1
tasklist /v > "$outDir\processes\tasklist_verbose.txt" 2>&1

# Unusual Processes Get-CimInstance
Get-CimInstance Win32_Process | Select-Object * |
    Export-Csv "$outDir\processes\cim_process_full.csv" -NoTypeInformation 2>&1

Get-CimInstance Win32_Process |
    Select-Object Name, ParentProcessId, ProcessId, CommandLine, ExecutablePath |
    Export-Csv "$outDir\processes\cim_process_parentmap.csv" -NoTypeInformation 2>&1

# Parent-child process tree via CIM
Get-CimInstance Win32_Process |
    Select-Object Name, ProcessId, ParentProcessId, ExecutablePath |
    Export-Csv "$outDir\processes\process_tree.csv" -NoTypeInformation 2>&1

# Dump command lines for offline inspection of suspicious PIDs
Get-CimInstance Win32_Process |
    Select-Object ProcessId, Name, CommandLine |
    Format-List | Out-File "$outDir\processes\all_command_lines.txt" 2>&1

# ============================================================================
# SERVICES COLLECTION
# ============================================================================
Write-Host "[3/8] Collecting service information..." -ForegroundColor Yellow

Get-Service | Where-Object {$_.Status -eq 'Running'} |
    Select-Object Name, DisplayName, Status, StartType |
    Export-Csv "$outDir\services\running_services.csv" -NoTypeInformation 2>&1

Get-Service |
    Select-Object Name, DisplayName, Status, StartType |
    Export-Csv "$outDir\services\all_services.csv" -NoTypeInformation 2>&1

net start > "$outDir\services\net_start.txt" 2>&1


sc query > "$outDir\services\sc_query.txt" 2>&1
tasklist /svc > "$outDir\services\tasklist_svc.txt" 2>&1

# Service executables and paths via CIM
Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, PathName |
    Export-Csv "$outDir\services\service_paths.csv" -NoTypeInformation 2>&1

# ============================================================================
# REGISTRY COLLECTION (Auto-start entries)
# ============================================================================
Write-Host "[4/8] Collecting registry auto-start entries..." -ForegroundColor Yellow

reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" > "$outDir\registry\HKLM_Run.txt" 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" > "$outDir\registry\HKLM_RunOnce.txt" 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" > "$outDir\registry\HKLM_RunOnceEx.txt" 2>&1

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" > "$outDir\registry\HKCU_Run.txt" 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" > "$outDir\registry\HKCU_RunOnce.txt" 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" > "$outDir\registry\HKCU_RunOnceEx.txt" 2>&1

# Startup artifacts with CIM
Get-CimInstance Win32_StartupCommand |
    Select-Object Name, Command, Location, User |
    Export-Csv "$outDir\registry\cim_startup_commands.csv" -NoTypeInformation 2>&1

# Auto-start folder locations
Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, Length |
    Export-Csv "$outDir\registry\startup_folder_items.csv" -NoTypeInformation 2>&1

Get-ChildItem -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, Length |
    Export-Csv "$outDir\registry\startup_folder_allusers.csv" -NoTypeInformation 2>&1

# ============================================================================
# ACCOUNT COLLECTION
# ============================================================================
Write-Host "[5/8] Collecting account information..." -ForegroundColor Yellow

net user > "$outDir\accounts\net_user.txt" 2>&1
net localgroup administrators > "$outDir\accounts\net_localgroup_admin.txt" 2>&1

Get-LocalUser | Select-Object Name, SID, Enabled, LastLogon |
    Export-Csv "$outDir\accounts\local_users.csv" -NoTypeInformation 2>&1

Get-LocalGroup | Select-Object Name, SID |
    Export-Csv "$outDir\accounts\local_groups.csv" -NoTypeInformation 2>&1

# Members of Administrators group
Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Select-Object ObjectClass, Name, PrincipalSource |
    Export-Csv "$outDir\accounts\admin_group_members.csv" -NoTypeInformation 2>&1

# ============================================================================
# FILE SYSTEM COLLECTION (Large/suspicious files)
# ============================================================================
Write-Host "[6/8] Collecting file system information..." -ForegroundColor Yellow

# Large files in C:\ root (>1 MB)
Get-ChildItem -Path "C:\" -File -ErrorAction SilentlyContinue |
    Where-Object {$_.Length -gt 1000000} |
    Select-Object FullName, Length, LastWriteTime, CreationTime |
    Export-Csv "$outDir\files\large_files_root.csv" -NoTypeInformation 2>&1

# Scoped recursive scan — top-level user dirs only, with max depth 3
# Scans each user profile's Desktop, Downloads, Temp, and AppData\Local\Temp
$userDirs = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "$env:LOCALAPPDATA\Temp"
)

foreach ($dir in $userDirs) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Filter "*.exe" -Recurse -Depth 2 -ErrorAction SilentlyContinue |
            Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
            Select-Object FullName, LastWriteTime, Length |
            Export-Csv "$outDir\files\recent_exes_$(Split-Path $dir -Leaf).csv" -NoTypeInformation 2>&1
    }
}

# Scan all profiles' Temp dirs for recently created .exe/.bat/.ps1/.vbs
$suspExt = @("*.exe", "*.bat", "*.ps1", "*.vbs", "*.dll", "*.scr")
foreach ($ext in $suspExt) {
    Get-ChildItem -Path "C:\Users" -Filter $ext -Recurse -Depth 3 -ErrorAction SilentlyContinue |
        Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
        Select-Object FullName, LastWriteTime, CreationTime, Length |
        Export-Csv "$outDir\files\recent_suspicious_$($ext.TrimStart('*')).csv" -NoTypeInformation 2>&1
}

# Check known persistence locations
$persistencePaths = @(
    "C:\Windows\System32\Tasks",
    "C:\Windows\SysWOW64\Tasks",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($path in $persistencePaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue |
            Select-Object FullName, LastWriteTime, CreationTime, Length |
            Export-Csv "$outDir\files\persistence_$(Split-Path $path -Leaf).csv" -NoTypeInformation 2>&1
    }
}

# ============================================================================
# TASK COLLECTION
# ============================================================================
Write-Host "[7/8] Collecting scheduled tasks..." -ForegroundColor Yellow

schtasks /query /fo CSV /v > "$outDir\tasks\scheduled_tasks_v.csv" 2>&1
schtasks /query /fo LIST /v > "$outDir\tasks\scheduled_tasks_list.txt" 2>&1

Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} |
    Select-Object TaskName, State, TaskPath |
    Export-Csv "$outDir\tasks\active_scheduled_tasks.csv" -NoTypeInformation 2>&1

# Pull task action details (command lines executed by tasks)
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} |
    ForEach-Object {
        $task = $_
        $task.Actions | ForEach-Object {
            [PSCustomObject]@{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State    = $task.State
                Execute  = $_.Execute
                Arguments = $_.Arguments
                WorkingDir = $_.WorkingDirectory
            }
        }
    } | Export-Csv "$outDir\tasks\task_actions_detail.csv" -NoTypeInformation 2>&1

# ============================================================================
# LOG COLLECTION
# ============================================================================
Write-Host "[8/8] Collecting event logs..." -ForegroundColor Yellow

# Security log export (last 1000 events)
Get-WinEvent -FilterHashtable @{LogName='Security'; MaxEvents=1000} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, Message |
    Export-Csv "$outDir\logs\security_events_recent.csv" -NoTypeInformation 2>&1

# System log
Get-WinEvent -FilterHashtable @{LogName='System'; MaxEvents=500} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Export-Csv "$outDir\logs\system_events.csv" -NoTypeInformation 2>&1

# Application log
Get-WinEvent -FilterHashtable @{LogName='Application'; MaxEvents=500} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Export-Csv "$outDir\logs\application_events.csv" -NoTypeInformation 2>&1

# Query each log individually instead of wildcard in FilterHashtable
$criticalLogs = @('Security', 'System', 'Application')
foreach ($logName in $criticalLogs) {
    Get-WinEvent -FilterHashtable @{LogName=$logName; Level=1,2; MaxEvents=200} -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, LogName, Id, LevelDisplayName, Message |
        Export-Csv "$outDir\logs\critical_and_error_${logName}.csv" -NoTypeInformation 2>&1
}

# PowerShell operational log (potential malicious script execution)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; MaxEvents=500} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Export-Csv "$outDir\logs\powersShell_operational.csv" -NoTypeInformation 2>&1

# Sysmon operational log if present
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; MaxEvents=1000} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Export-Csv "$outDir\logs\sysmon_operational.csv" -NoTypeInformation 2>&1

# ============================================================================
# GENERATE SUMMARY REPORT
# ============================================================================
Write-Host ""
Write-Host "Generating summary report..." -ForegroundColor Cyan

$elapsed = (Get-Date) - $startTime
$summaryFile = "$outDir\COLLECTION_SUMMARY.txt"

@"
FORENSIC ARTIFACT COLLECTION SUMMARY
=====================================
Collection Time:      $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Collection Duration:  $($elapsed.ToString())
Output Directory:     $outDir
Hostname:             $env:COMPUTERNAME
Username:             $env:USERNAME
OS:                   $((Get-CimInstance Win32_OperatingSystem).Caption)

COLLECTED FILES:
----------------
"@ | Out-File -FilePath $summaryFile -Encoding UTF8

Get-ChildItem -Recurse $outDir -File |
    Sort-Object FullName |
    Select-Object @{N='Path';E={$_.FullName.Replace($outDir, '.')}},
                  @{N='SizeKB';E={[math]::Round($_.Length / 1KB, 1)}},
                  LastWriteTime |
    Format-Table -AutoSize | Out-String |
    Out-File -FilePath $summaryFile -Append -Encoding UTF8

$totalFiles = (Get-ChildItem -Recurse $outDir -File).Count
$totalSize  = [math]::Round(((Get-ChildItem -Recurse $outDir -File | Measure-Object Length -Sum).Sum / 1MB), 2)

@"
----------------------------------------
Total files collected: $totalFiles
Total size:            $totalSize MB

RECOMMENDED ANALYSIS TOOLS:
---------------------------
  - TCPView        : Live TCP connection monitoring
  - Process Explorer: Process tree and DLL analysis
  - Autoruns       : Comprehensive auto-start location scanner
  - Event Viewer   : GUI-based log review

NOTES:
------
  - Review network outputs for unexpected outbound connections.
  - Cross-reference suspicious PIDs in tasklist with netstat -ano output.
  - Check registry Run keys and Startup folders against known-good baseline.
  - Decode any base64 strings found in command lines at:
      https://www.base64decode.com
      or PowerShell: [Convert]::FromBase64String('<string>')
"@ | Out-File -FilePath $summaryFile -Append -Encoding UTF8

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "COLLECTION COMPLETE!" -ForegroundColor Green
Write-Host "Artifacts saved to: $outDir" -ForegroundColor Green
Write-Host "Summary report:    $summaryFile" -ForegroundColor Green
Write-Host "Files collected:   $totalFiles" -ForegroundColor Green
Write-Host "Total size:        $totalSize MB" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green


#########################################################################################################################################################################################################################
# Notes:
# Administrative privileges required - Some commands need elevated rights
# Output location - Creates timestamped folder on C:\ drive
# Privacy considerations - This collects sensitive system data; ensure proper authorisation
# Storage space - Ensure sufficient disk space for log exports
# Base64 decoding - Use https://www.base64decode.com or PowerShell: [Convert]::FromBase64String()
#
# Focus Area's:
# Network: Unexpected outbound connections, listening ports
# Processes: Unknown executables, suspicious parent-child relationships
# Registry: Unauthorised persistence mechanisms
# Accounts: New admin accounts, unexpected group memberships
# Scheduled Tasks: Tasks running unknown scripts/executables
########################################################################################################################################################################################################################
