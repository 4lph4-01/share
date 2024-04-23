########################################################################################################################################################################################################################
# Powershell Script to Identify accounts suceptible ASRepRoasting to By: 41ph4-01 23/04/2024 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################


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
