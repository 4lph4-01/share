#########################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

# Define default seasons, years, and services
$seasons = @("Spring", "Summer", "Autumn", "Winter")
$years = 2000..2024
$services = @("service1", "service2", "service3")

# Generate season-based passwords
$passwords = foreach ($season in $seasons) {
    foreach ($year in $years) {
        "$season$year"
    }
}

# Function to load users
Function Load-Users {
    Write-Host "[Setup] Loading user list..."
    $filePath = Read-Host "Enter path to user file (.txt or .csv) or press Enter to use defaults"

    if ([string]::IsNullOrWhiteSpace($filePath)) {
        Write-Host "[+] Using default user list."
        return @("user1", "user2", "user3", "admin")
    }

    try {
        if ($filePath -like "*.csv") {
            Write-Host "[+] Loading users from CSV..."
            return Import-Csv -Path $filePath | ForEach-Object { $_.username }
        } elseif ($filePath -like "*.txt") {
            Write-Host "[+] Loading users from text file..."
            return Get-Content -Path $filePath
        } else {
            Write-Host "[!] Unsupported file format. Using default list."
            return @("user1", "user2", "user3", "admin")
        }
    } catch {
        Write-Host "[!] Failed to load user file: $_"
        return @("user1", "user2", "user3", "admin")
    }
}

# Function to install necessary tools
Function Install-Tools {
    Write-Host "[Setup] Installing necessary tools..."
    try {
        # Ensure Python is installed and accessible
        Invoke-Expression "python --version" | Out-Null
        # Install Python dependencies (for simulation or using Python-based tools)
        Invoke-Expression "pip install ldap3 cryptography"
        Write-Host "[+] Tools installed successfully."
    } catch {
        Write-Host "[!] Installation failed: $_"
    }
}

# Kerberoasting simulation
Function Kerberoasting {
    Write-Host "`n[Kerberoasting] Simulating service ticket request and cracking..."
    foreach ($service in $services) {
        $season = $seasons | Get-Random
        $year = $years | Get-Random
        Write-Host "Requesting service ticket for $service ($season $year)..."
        $ticketHash = "hash_$service_$season_$year_$([System.Random]::Next(1000,9999))"
        Write-Host "Captured ticket hash: $ticketHash"
        Start-Sleep -Seconds 1
    }
}

# Password spraying simulation
Function PasswordSpraying {
    Write-Host "`n[Password Spraying] Trying season-based passwords..."
    foreach ($user in $users) {
        foreach ($password in $passwords) {
            Write-Host "Trying $user:$password"
            $success = Get-Random -Minimum 0 -Maximum 2
            if ($success -eq 1) {
                Write-Host "[+] Success: $user logged in with $password"
                break
            } else {
                Write-Host "[-] Failed for $user"
            }
        }
        Start-Sleep -Seconds 60  # Add delay to prevent lockouts
    }
}

# AS-REP Roasting simulation
Function ASREPRoasting {
    Write-Host "`n[AS-REP Roasting] Identifying accounts without pre-authentication..."
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

# Main Menu
Function Main {
    # Load user list
    $users = Load-Users

    # Install necessary tools
    Install-Tools

    Write-Host "`nActive Directory Attack Simulation Suite"
    Write-Host "1. Kerberoasting"
    Write-Host "2. Password Spraying"
    Write-Host "3. AS-REP Roasting"
    Write-Host "4. Run All"

    $choice = Read-Host "Choose an attack to simulate (1-4): "

    switch ($choice) {
        1 { Kerberoasting }
        2 { PasswordSpraying }
        3 { ASREPRoasting }
        4 { Kerberoasting; PasswordSpraying; ASREPRoasting }
        default { Write-Host "Invalid choice. Exiting." }
    }
}

# Run the program
Main
