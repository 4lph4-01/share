# Import ActiveDirectory module
Import-Module ActiveDirectory

# Define function to perform ASRepRoasting audit
function Audit-ASRepRoasting {
    # Define LDAP filter to retrieve user accounts with pre-authentication disabled
    $filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"

    # Perform LDAP query to retrieve vulnerable user accounts
    $vulnerableUsers = Get-ADUser -Filter $filter -Properties sAMAccountName

    # Display vulnerable user accounts
    Write-Host "Vulnerable User Accounts:"
    $vulnerableUsers | ForEach-Object {
        Write-Host $_.sAMAccountName
    }
}

# Call function to perform ASRepRoasting audit
Audit-ASRepRoasting
