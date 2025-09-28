#########################################################################################################################################################################################################################
# Initial powershell script for Active Directoey user creation Takes the first two letters of the the first name supplied (prefix), Append a random six‑digit number, Ensures the generated samAccountName does not 
# already exist, Create the user in the Users container (or the OU you set). And Email address: <lastname><firstTwoLettersOfFirstName>@domain.com   
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################


# --------------------------- CONFIGURATION -----------------------
$DomainDN        = 'DC=yourdomain,DC=com'          # <<< CHANGE TO YOUR AD DN
$UsersOU         = "CN=Users,$DomainDN"            # Target OU (default Users container)
$InitialPassword = 'P@ssw0rd123!'                 # Must meet your domain policy
$PasswordSecure  = ConvertTo-SecureString $InitialPassword -AsPlainText -Force
$MailDomain      = 'yourdomain.com'                # <<< DOMAIN part for the e‑mail address
# -----------------------------------------------------------------

Import-Module ActiveDirectory   # Load AD cmdlets

# ---------- Helper: generate a zero‑padded 6‑digit suffix ----------
function New-RandomSuffix {
    $num = Get-Random -Minimum 0 -Maximum 1000000   # 0 … 999999
    return $num.ToString('D6')
}

# -------------------------- MAIN LOGIC ---------------------------
param (
    [Parameter(Mandatory=$true)]
    [string]$FullName          # e.g. "John Doe"
)

# Clean the name – keep only letters, split into given / surname
$cleaned = $FullName -replace '[^A-Za-z\s]', ''      # strip punctuation
$parts   = $cleaned.Trim().Split(' ',2)              # first token = given name
if ($parts.Count -lt 2) {
    Write-Error "Please provide both a first and a last name."
    exit 1
}
$givenName = $parts[0]
$surname   = $parts[1]

# Prefix = first two letters of the given name (upper‑cased)
if ($givenName.Length -lt 2) {
    Write-Error "First name must contain at least two letters."
    exit 1
}
$prefix = $givenName.Substring(0,2).ToUpper()   # e.g. "JO"

# Build a unique sAMAccountName: <prefix><6‑digit‑random>
do {
    $suffix = New-RandomSuffix
    $sam    = "$prefix$suffix"
    $exists = Get-ADUser -Filter "samAccountName -eq '$sam'" -ErrorAction SilentlyContinue
} while ($exists)

# Build the e‑mail address: <lastname><firstTwoLettersOfFirstName>@domain.com
$emailLocalPart = ($surname + $givenName.Substring(0,2)).ToLower()
$mailAddress    = "$emailLocalPart@$MailDomain"

# Build the UPN (used for login) – you can keep it identical to the mail
$userPrincipalName = "$sam@$MailDomain"

# --------------------------------------------------------------
# Create the AD user
# --------------------------------------------------------------
New-ADUser `
    -Name               "$FullName" `
    -GivenName          $givenName `
    -Surname            $surname `
    -SamAccountName     $sam `
    -UserPrincipalName  $userPrincipalName `
    -Mail               $mailAddress `
    -Path               $UsersOU `
    -AccountPassword    $PasswordSecure `
    -Enabled            $true `
    -ChangePasswordAtLogon $true   # Force password change on first logon

Write-Host "`n Created AD user:`n"
Write-Host "   Display Name : $FullName"
Write-Host "   sAMAccountName: $sam"
Write-Host "   UPN           : $userPrincipalName"
Write-Host "   E‑mail (mail) : $mailAddress"
Write-Host "   OU            : $UsersOU"

#.\Create-AdUserFromName.ps1 -FullName "John Doe"
# Save the code as Create-AdUserFromName.ps1.
# Edit the configuration section near the top:
# Replace DC=yourdomain,DC=com with your actual domain DN.
# MailDomain → the domain part of the e‑mail addresses you own (e.g., example.com).
# If you want the account in a different OU, change $UsersOU.
# $InitialPassword → a password that satisfies your domain’s complexity requirements.
# Run PowerShell as Administrator (or a user with the necessary AD permissions).
# If you want the account in a different OU, change $UsersOU.
# Open PowerShell as an administrator (or a user with delegated AD create rights).
# Run the script, passing the full name:
# Execute the script, passing the full name as an argument, e.g.:.\Create-AdUserFromName.ps1 -FullName "John Doe"

