######################################################################################################################################################################## 
# A comprehensive powershell script to perform enumeration of DNS (Domain Name Services) and testing. Note: Requires a word list to dicover subdomains
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the through bruteforce      
# Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, # and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################


function Enumerate-DNSRecords {
    param (
        [string]$domain,
        [string]$dnsServer
    )
    $recordTypes = @("A", "AAAA", "MX", "NS", "CNAME", "TXT", "SRV", "SOA", "PTR")

    foreach ($recordType in $recordTypes) {
        Write-Output "Enumerating $recordType records for $domain using DNS server $dnsServer"
        try {
            $records = Resolve-DnsName -Name $domain -Server $dnsServer -Type $recordType -ErrorAction Stop
            foreach ($record in $records) {
                Write-Output "$($recordType) record: $($record.Name) - $($record.IPAddress)"
            }
        } catch {
            Write-Output "No $recordType records found for $domain"
        }
    }
}

function Test-DNSZoneTransfer {
    param (
        [string]$domain,
        [string]$dnsServer
    )
    Write-Output "Testing for DNS zone transfer vulnerability for $domain using DNS server $dnsServer"
    try {
        $nsRecords = Resolve-DnsName -Name $domain -Server $dnsServer -Type NS -ErrorAction Stop
        foreach ($ns in $nsRecords) {
            $nsServer = $ns.NameHost
            Write-Output "Attempting zone transfer with $nsServer"
            try {
                $zoneTransfer = nslookup -querytype=AXFR $domain $nsServer
                if ($zoneTransfer) {
                    Write-Output "Zone transfer successful with $nsServer"
                    Write-Output $zoneTransfer
                } else {
                    Write-Output "Zone transfer failed with $nsServer"
                }
            } catch {
                Write-Output "Error during zone transfer attempt with $nsServer: $_"
            }
        }
    } catch {
        Write-Output "Error resolving NS records for $domain: $_"
    }
}

function Perform-DNSQueries {
    param (
        [string]$domain,
        [string]$dnsServer
    )
    Write-Output "Performing basic DNS queries for $domain using DNS server $dnsServer"

    try {
        $aRecords = Resolve-DnsName -Name $domain -Server $dnsServer -Type A -ErrorAction Stop
        foreach ($record in $aRecords) {
            Write-Output "A record for $domain: $($record.IPAddress)"
        }
    } catch {
        Write-Output "Error resolving A records for $domain: $_"
    }

    try {
        $mxRecords = Resolve-DnsName -Name $domain -Server $dnsServer -Type MX -ErrorAction Stop
        foreach ($record in $mxRecords) {
            Write-Output "MX record: $($record.NameExchange) - Preference: $($record.Preference)"
        }
    } catch {
        Write-Output "Error resolving MX records for $domain: $_"
    }

    try {
        $txtRecords = Resolve-DnsName -Name $domain -Server $dnsServer -Type TXT -ErrorAction Stop
        foreach ($record in $txtRecords) {
            Write-Output "TXT record: $($record.Text)"
        }
    } catch {
        Write-Output "Error resolving TXT records for $domain: $_"
    }
}

function Reverse-DNSLookup {
    param (
        [string]$ipAddress,
        [string]$dnsServer
    )
    Write-Output "Performing reverse DNS lookup for $ipAddress"
    try {
        $ptrRecords = Resolve-DnsName -Name $ipAddress -Server $dnsServer -Type PTR -ErrorAction Stop
        foreach ($record in $ptrRecords) {
            Write-Output "PTR record: $($record.NameHost)"
        }
    } catch {
        Write-Output "Error performing reverse DNS lookup for $ipAddress: $_"
    }
}

function Check-DNSSEC {
    param (
        [string]$domain,
        [string]$dnsServer
    )
    Write-Output "Checking DNSSEC configuration for $domain"
    try {
        $dnskeyRecords = Resolve-DnsName -Name $domain -Server $dnsServer -Type DNSKEY -ErrorAction Stop
        foreach ($record in $dnskeyRecords) {
            Write-Output "DNSKEY record: $($record.DnsKey)"
        }
        Write-Output "DNSSEC is enabled for this domain."
    } catch {
        Write-Output "DNSSEC is not enabled for this domain."
    }
}

function Subdomain-Enumeration {
    param (
        [string]$domain,
        [string]$dnsServer,
        [string]$wordlist
    )
    Write-Output "Enumerating subdomains for $domain using DNS server $dnsServer"
    try {
        $subdomains = Get-Content -Path $wordlist
        foreach ($subdomain in $subdomains) {
            $fullDomain = "$subdomain.$domain"
            try {
                $aRecords = Resolve-DnsName -Name $fullDomain -Server $dnsServer -Type A -ErrorAction Stop
                foreach ($record in $aRecords) {
                    Write-Output "A record for $fullDomain: $($record.IPAddress)"
                }
            } catch {
                Write-Output "No A records found for $fullDomain"
            }
        }
    } catch {
        Write-Output "Error reading wordlist: $_"
    }
}

function Run-PenTest {
    param (
        [string]$domain,
        [string]$internalDnsServer,
        [string]$externalDnsServer,
        [string]$wordlist
    )
    Write-Output "Running penetration test against internal DNS server"
    Enumerate-DNSRecords -domain $domain -dnsServer $internalDnsServer
    Test-DNSZoneTransfer -domain $domain -dnsServer $internalDnsServer
    Perform-DNSQueries -domain $domain -dnsServer $internalDnsServer
    Subdomain-Enumeration -domain $domain -dnsServer $internalDnsServer -wordlist $wordlist
    Check-DNSSEC -domain $domain -dnsServer $internalDnsServer

    Write-Output "Running penetration test against external DNS server"
    Enumerate-DNSRecords -domain $domain -dnsServer $externalDnsServer
    Test-DNSZoneTransfer -domain $domain -dnsServer $externalDnsServer
    Perform-DNSQueries -domain $domain -dnsServer $externalDnsServer
    Subdomain-Enumeration -domain $domain -dnsServer $externalDnsServer -wordlist $wordlist
    Check-DNSSEC -domain $domain -dnsServer $externalDnsServer
}

# Define the domain and DNS servers to test
$domain = "example.com"
$internalDnsServer = "192.168.1.1"  # Change to your internal DNS server IP
$externalDnsServer = "8.8.8.8"  # Google DNS server for external testing
$wordlist = "subdomains.txt"  # Path to your wordlist for subdomain enumeration

# Run the penetration test
Run-PenTest -domain $domain -internalDnsServer $internalDnsServer -externalDnsServer $externalDnsServer -wordlist $wordlist
