# Define users, seasons, and years
$users = @("user1", "user2", "user3", "admin")
$seasons = @("Spring", "Summer", "Autumn", "Winter")
$years = 2000..2024
$services = @("Service1", "Service2", "Service3")

# Generate season-based passwords
$passwords = foreach ($season in $seasons) {
    foreach ($year in $years) {
        "$season$year"
    }
}

# Function to install necessary tools
Function Install-Tools {
    Write-Host "[Setup] Installing necessary tools..."
    try {
        # Install Python dependencies (example with pip for Python tools)
        Invoke-Expression "pip install ldap3 cryptography"
        Write-Host "[+] Tools installed successfully."
    } catch {
        Write-Host "[!] Installation failed: $_"
    }
}

# Kerberoasting simulation
Function Kerberoasting {
    Write-Host "\n[Kerberoasting] Simulating service ticket request and cracking..."
    foreach ($service in $services) {
        $year = $seasons | Get-Random
        $season = $years | Get-Random
        Write-Host "Requesting service ticket for $service ($season $year)..."
        $ticketHash = "hash_$season_$year_$([System.Random]::Next(1000,9999))"
        Write-Host "Captured ticket hash: $ticketHash"
        Start-Sleep -Seconds 1
    }
}

# Password spraying simulation (No lockouts)
Function PasswordSpraying {
    Write-Host "\n[Password Spraying] Trying season-based passwords..."
    foreach ($user in $users) {
        foreach ($password in $passwords) {
            Write-Host "Trying $user:$password"
            
            # Simulate authentication attempt (replace this with actual logic in your environment)
            $success = Get-Random -Minimum 0 -Maximum 2

            if ($success -eq 1) {
                Write-Host "[+] Success: $user logged in with $password"
                break
            } else {
                Write-Host "[-] Failed for $user"
            }
        }
        Start-Sleep -Seconds 60  # Add delay between user attempts to prevent lockouts
    }
}

# AS-REP Roasting simulation
Function ASREPRoasting {
    Write-Host "\n[AS-REP Roasting] Identifying accounts without pre-authentication..."
    foreach ($user in $users) {
        Write-Host "Checking $user..."
        $success = Get-Random -Minimum 0 -Maximum 2
        if ($success -eq 1) {
            $ticketHash = "asrep_hash_$([System.Random]::Next(1000,9999))"
            Write-Host "[+] Captured AS-REP hash for $user: $ticketHash"
        } else {
            Write-Host "[-] $user is secure."
        }
        Start-Sleep -Seconds 1
    }
}

# LDAP Enumeration simulation
Function LDAPEnumeration {
    Write-Host "\n[LDAP Enumeration] Gathering sensitive AD information..."
    $objects = @("CN=Users", "CN=Admins", "OU=Finance", "OU=IT")
    foreach ($obj in $objects) {
        Write-Host "Enumerating LDAP object: $obj..."
        $sensitiveData = "Data_$([System.Random]::Next(100,999))"
        Write-Host "Discovered sensitive data: $sensitiveData"
        Start-Sleep -Seconds 1
    }
}

# GPO Analysis simulation
Function GPOAnalysis {
    Write-Host "\n[GPO Analysis] Checking for misconfigurations..."
    $gpoSettings = @("Password Policy", "Account Lockout", "Local Admin Rights")
    foreach ($setting in $gpoSettings) {
        Write-Host "Checking $setting..."
        $success = Get-Random -Minimum 0 -Maximum 2
        if ($success -eq 1) {
            Write-Host "[!] Vulnerable setting found: $setting"
        } else {
            Write-Host "[+] $setting is secure."
        }
        Start-Sleep -Seconds 1
    }
}

# Privilege escalation simulation
Function PrivilegeEscalation {
    Write-Host "\n[Privilege Escalation] Attempting to gain elevated access..."
    $escalationMethods = @("DLL Injection", "Token Impersonation", "Credential Dumping")
    foreach ($method in $escalationMethods) {
        Write-Host "Attempting $method..."
        $success = Get-Random -Minimum 0 -Maximum 2
        if ($success -eq 1) {
            Write-Host "[+] Success with $method!"
            break
        } else {
            Write-Host "[-] $method failed."
        }
        Start-Sleep -Seconds 1
    }
}

# Main Menu
Function Main {
    Install-Tools  # Ensure tools are installed
    Write-Host "Active Directory Attack Simulation Suite"
    Write-Host "1. Kerberoasting"
    Write-Host "2. Password Spraying"
    Write-Host "3. AS-REP Roasting"
    Write-Host "4. LDAP Enumeration"
    Write-Host "5. GPO Analysis"
    Write-Host "6. Privilege Escalation"
    Write-Host "7. Run All"

    $choice = Read-Host "Choose an attack to simulate (1-7): "

    switch ($choice) {
        1 { Kerberoasting }
        2 { PasswordSpraying }
        3 { ASREPRoasting }
        4 { LDAPEnumeration }
        5 { GPOAnalysis }
        6 { PrivilegeEscalation }
        7 { Kerberoasting; PasswordSpraying; ASREPRoasting; LDAPEnumeration; GPOAnalysis; PrivilegeEscalation }
        default { Write-Host "Invalid choice. Exiting." }
    }
}

# Run the program
Main

