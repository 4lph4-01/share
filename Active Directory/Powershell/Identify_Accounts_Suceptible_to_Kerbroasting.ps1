# Import ActiveDirectory module
Import-Module ActiveDirectory

# Define function to perform Kerberoasting audit
function Audit-Kerberoasting {
    # Define LDAP filter to retrieve user accounts with service principal names (SPNs)
    $filter = "(&(objectClass=user)(servicePrincipalName=*))"

    # Perform LDAP query to retrieve vulnerable user accounts
    $vulnerableUsers = Get-ADUser -Filter $filter -Properties sAMAccountName

    # Display vulnerable user accounts
    Write-Host "Vulnerable User Accounts (with SPNs):"
    $vulnerableUsers | ForEach-Object {
        Write-Host $_.sAMAccountName
    }
}

# Call function to perform Kerberoasting audit
Audit-Kerberoasting
