#.\EnhancedChecks.ps1 -RemoteLogServer "http://your-log-server-url/api/logs"

function Invoke-EnhancedPrivilegeEscalationChecks {
    param (
        [string]$OutputFile = "$env:USERPROFILE\EnhancedPrivilegeEscalationReport.txt",
        [string]$RemoteLogServer = ""
    )

    Write-Output "Starting enhanced privilege escalation enumeration..."
    $Report = @()

    # 1. Check for Unquoted Service Paths
    Write-Output "[*] Checking for unquoted service paths..."
    $Services = Get-WmiObject -Query "SELECT * FROM Win32_Service"
    foreach ($Service in $Services) {
        $Path = $Service.PathName
        if ($Path -and $Path -match '\s' -and $Path -notmatch '"') {
            $Report += "`n[Unquoted Service Path]"
            $Report += "Service Name: $($Service.Name)"
            $Report += "Display Name: $($Service.DisplayName)"
            $Report += "Path: $Path"
        }
    }

    # 2. Check Writable Directories
    Write-Output "[*] Searching for writable directories..."
    $WritableDirs = Get-ChildItem -Path "C:\" -Recurse -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            (Get-Acl $_.FullName).Access |
            Where-Object { $_.IdentityReference -like "$env:USERNAME" -and $_.FileSystemRights -match "Write" }
        }
    if ($WritableDirs) {
        $Report += "`n[Writable Directories]"
        $WritableDirs | ForEach-Object { $Report += $_.FullName }
    } else {
        $Report += "`nNo writable directories found."
    }

    # 3. Check Weak Registry Permissions
    Write-Output "[*] Checking for weak registry permissions..."
    $RegistryKeys = @("HKLM:\SOFTWARE", "HKLM:\SYSTEM", "HKCU:\")
    foreach ($Key in $RegistryKeys) {
        try {
            $Permissions = Get-Acl -Path $Key
            $WeakKeys = $Permissions.Access | Where-Object {
                $_.FileSystemRights -match "Write" -and $_.IdentityReference -match $env:USERNAME
            }
            if ($WeakKeys) {
                $Report += "`n[Weak Registry Permissions]"
                $Report += "Registry Key: $Key"
            }
        } catch {
            $Report += "`nUnable to check permissions for registry key: $Key"
        }
    }

    # 4. Check Scheduled Tasks
    Write-Output "[*] Enumerating scheduled tasks..."
    $Tasks = Get-ScheduledTask | ForEach-Object {
        $TaskPath = $_.Actions.Execute
        if (Test-Path $TaskPath) {
            $Permissions = Get-Acl -Path $TaskPath
            $Writable = $Permissions.Access | Where-Object {
                $_.IdentityReference -match $env:USERNAME -and $_.FileSystemRights -match "Write"
            }
            if ($Writable) {
                $Report += "`n[Writable Scheduled Task]"
                $Report += "Task Name: $($_.TaskName)"
                $Report += "Path: $TaskPath"
            }
        }
    }

    # 5. Search Startup Scripts
    Write-Output "[*] Checking startup scripts..."
    $StartupDirs = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($Dir in $StartupDirs) {
        if (Test-Path $Dir) {
            $WritableScripts = Get-ChildItem -Path $Dir -Recurse -ErrorAction SilentlyContinue |
                Where-Object {
                    (Get-Acl $_.FullName).Access |
                    Where-Object { $_.IdentityReference -like "$env:USERNAME" -and $_.FileSystemRights -match "Write" }
                }
            if ($WritableScripts) {
                $Report += "`n[Writable Startup Scripts]"
                $WritableScripts | ForEach-Object { $Report += $_.FullName }
            }
        }
    }

    # 6. DLL Hijacking Opportunities
    Write-Output "[*] Checking for DLL hijacking opportunities..."
    $DllSearchPaths = @(
        "$env:WINDIR\System32",
        "$env:WINDIR\SysWOW64"
    )
    foreach ($Path in $DllSearchPaths) {
        if (Test-Path $Path) {
            $WritableDlls = Get-ChildItem -Path $Path -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue |
                Where-Object {
                    (Get-Acl $_.FullName).Access |
                    Where-Object { $_.IdentityReference -like "$env:USERNAME" -and $_.FileSystemRights -match "Write" }
                }
            if ($WritableDlls) {
                $Report += "`n[Writable DLLs]"
                $WritableDlls | ForEach-Object { $Report += $_.FullName }
            }
        }
    }

    # Save the Report Locally
    Write-Output "Saving results to $OutputFile..."
    $Report | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Output "[+] Enhanced privilege escalation enumeration complete. Results saved to $OutputFile."

    # Send the Report to a Remote Log Server (if specified)
    if ($RemoteLogServer) {
        try {
            $ReportText = $Report -join "`n"
            Invoke-RestMethod -Uri $RemoteLogServer -Method POST -Body @{ Report = $ReportText }
            Write-Output "[+] Report successfully sent to $RemoteLogServer."
        } catch {
            Write-Output "[-] Failed to send report to $RemoteLogServer: $_"
        }
    }
}

# Execute the function
Invoke-EnhancedPrivilegeEscalationChecks

