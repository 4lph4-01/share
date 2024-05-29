########################################################################################################################################################################################################################
# Basic powershell script based on good practice: 41ph4-01 28/05/2024 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################



# Ensure necessary modules are loaded
Import-Module ActiveDirectory

# Output file for the audit report
$outputFile = "C:\FullADAuditReport.html"

# Function to check for weak passwords
function Check-WeakPasswords {
    $weakPasswordUsers = Search-ADAccount -PasswordNeverExpires:$false -UsersOnly | Where-Object { ($_ | Get-ADUser -Properties PasswordLastSet).PasswordLastSet -lt (Get-Date).AddDays(-90) }
    return $weakPasswordUsers
}

# Function to find inactive accounts
function Check-InactiveAccounts {
    $inactiveUsers = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 90
    $inactiveComputers = Search-ADAccount -AccountInactive -ComputersOnly -TimeSpan 90
    return @($inactiveUsers, $inactiveComputers)
}

# Function to find accounts with elevated privileges
function Check-PrivilegedAccounts {
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    $privilegedAccounts = foreach ($group in $privilegedGroups) {
        Get-ADGroupMember -Identity $group -Recursive
    }
    return $privilegedAccounts
}

# Function to check security configuration settings
function Check-SecuritySettings {
    $settings = @{}
    $settings["Default Domain Password Policy"] = Get-ADDefaultDomainPasswordPolicy | Select-Object -Property MinPasswordLength, MaxPasswordAge, PasswordHistoryCount, ComplexityEnabled, ReversibleEncryptionEnabled, LockoutThreshold
    $settings["Anonymous SID Enumeration"] = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")."RestrictAnonymous"
    return $settings
}

# Function to check for user logon events
function Check-UserLogons {
    $userLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} | Where-Object { $_.Properties[5].Value -ne 'S-1-5-18' } | Select-Object TimeCreated, @{Name="User"; Expression={$_.Properties[5].Value}}
    return $userLogons
}

# Function to check for user lockouts
function Check-UserLockouts {
    $userLockouts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} | Select-Object TimeCreated, @{Name="User"; Expression={$_.Properties[0].Value}}
    return $userLockouts
}

# Function to check for recent changes in AD (users, groups, computers)
function Check-RecentChanges {
    $changes = Get-ADObject -Filter {whenChanged -gt (Get-Date).AddDays(-30)} -Property whenChanged, whenCreated, objectClass, name | Select-Object whenChanged, whenCreated, objectClass, name
    return $changes
}

# Function to generate HTML report
function Generate-HTMLReport {
    param (
        [hashtable]$AuditResults
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Full Active Directory Security Audit Report</title>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table, th, td {
            border: 1px solid black;
        }
        th, td {
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <h1>Full Active Directory Security Audit Report</h1>
"@

    foreach ($key in $AuditResults.Keys) {
        $html += "<h2>$key</h2>"
        $html += "<table><tr>"

        # Assume all results are collections of objects
        $firstItem = $AuditResults[$key] | Select-Object -First 1
        if ($firstItem -ne $null) {
            foreach ($property in $firstItem.PSObject.Properties) {
                $html += "<th>$($property.Name)</th>"
            }
            $html += "</tr>"

            foreach ($item in $AuditResults[$key]) {
                $html += "<tr>"
                foreach ($property in $item.PSObject.Properties) {
                    $html += "<td>$($property.Value)</td>"
                }
                $html += "</tr>"
            }
        } else {
            $html += "<td>No data found</td></tr>"
        }

        $html += "</table>"
    }

    $html += @"
</body>
</html>
"@

    $html | Out-File -FilePath $outputFile -Encoding UTF8
}

# Perform audit
$AuditResults = @{}
$AuditResults["Weak Password Users"] = Check-WeakPasswords
$AuditResults["Inactive Accounts"] = Check-InactiveAccounts
$AuditResults["Privileged Accounts"] = Check-PrivilegedAccounts
$AuditResults["Security Settings"] = Check-SecuritySettings
$AuditResults["User Logons"] = Check-UserLogons
$AuditResults["User Lockouts"] = Check-UserLockouts
$AuditResults["Recent Changes"] = Check-RecentChanges

# Generate HTML report
Generate-HTMLReport -AuditResults $AuditResults

Write-Output "Security audit report generated at $outputFile"
