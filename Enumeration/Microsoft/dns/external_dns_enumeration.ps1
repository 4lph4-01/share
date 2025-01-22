######################################################################################################################################################################## 
# A basic powershell script to perform external enumeration of DNS. By 41ph4-01 23/04/2024 & our community. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the through bruteforce      
# Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, # and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################

# Define the domain to test
$domain = "example.com"
$dnsServer = "8.8.8.8"  # Google DNS server, you can change it to your target DNS server

# Function to enumerate DNS records
function Enumerate-DNSRecords {
    param (
        [string]$domain
    )

    $recordTypes = @("A", "AAAA", "MX", "NS", "CNAME", "TXT", "SRV")

    foreach ($recordType in $recordTypes) {
        Write-Host "Enumerating $recordType records for $domain"
        try {
            $records = Resolve-DnsName -Name $domain -Type $recordType -Server $dnsServer
            if ($records) {
                foreach ($record in $records) {
                    Write-Host "$recordType record: $($record.Name) - $($record.IPAddress)"
                }
            }
        } catch {
            Write-Host "Failed to resolve $recordType records for $domain"
        }
    }
}

# Function to test for DNS zone transfers
function Test-DNSZoneTransfer {
    param (
        [string]$domain
    )

    Write-Host "Testing for DNS zone transfer vulnerability for $domain"

    $nameServers = Resolve-DnsName -Name $domain -Type NS -Server $dnsServer
    foreach ($ns in $nameServers) {
        $nsServer = $ns.Name
        Write-Host "Attempting zone transfer with $nsServer"
        $zoneTransfer = nslookup.exe -q=any -d2 $domain $nsServer
        if ($zoneTransfer -match "zone transfer") {
            Write-Host "Zone transfer successful with $nsServer"
            Write-Host $zoneTransfer
        } else {
            Write-Host "Zone transfer failed with $nsServer"
        }
    }
}

# Function to perform basic DNS queries
function Perform-DNSQueries {
    param (
        [string]$domain
    )

    Write-Host "Performing basic DNS queries for $domain"

    $aRecord = Resolve-DnsName -Name $domain -Type A -Server $dnsServer
    Write-Host "A record for $domain: $($aRecord.IPAddress)"

    $mxRecords = Resolve-DnsName -Name $domain -Type MX -Server $dnsServer
    foreach ($mx in $mxRecords) {
        Write-Host "MX record: $($mx.NameExchange) - Preference: $($mx.Preference)"
    }

    $txtRecords = Resolve-DnsName -Name $domain -Type TXT -Server $dnsServer
    foreach ($txt in $txtRecords) {
        Write-Host "TXT record: $($txt.Strings)"
    }
}

# Main function to run all tests
function Run-PenTest {
    param (
        [string]$domain
    )

    Enumerate-DNSRecords -domain $domain
    Test-DNSZoneTransfer -domain $domain
    Perform-DNSQueries -domain $domain
}

# Run the penetration test
Run-PenTest -domain $domain
