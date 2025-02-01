# Description: Enumerates Active Directory users and groups

# Import Active Directory module
Import-Module ActiveDirectory

# Get all users
$users = Get-ADUser -Filter * -Property DisplayName, EmailAddress

# Get all groups
$groups = Get-ADGroup -Filter * -Property Name, Description

# Output results
$users | Format-Table DisplayName, EmailAddress
$groups | Format-Table Name, Description

