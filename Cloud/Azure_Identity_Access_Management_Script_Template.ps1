#########################################################################################################################################################################################################################
# Azure Identity Access Management Script (IAM) PS Script (Included examples, IAM 1, IAM 2, IAM 3, and IAM 4  Controls only)
# Expand as required. It's getting late - Apologies for any fat finger mistakes! 21/04/2024
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################



# Import common functions
. ".\CommonFunctions.ps1"

# Function to audit IAM controls
function AuditIAMControls {
    # Control IAM.1: Ensure that multi-factor authentication (MFA) is enabled for all privileged users
    $privilegedUsers = Get-AzADUser -All $true | Where-Object { $_.IsAdministrator -eq $true }

    foreach ($user in $privilegedUsers) {
        $mfaEnabled = $null
        $userMFADetails = Get-AzADUser -UserPrincipalName $user.UserPrincipalName | Get-AzureADUserRegisteredDevice

        if ($userMFADetails -ne $null -and $userMFADetails.Count -gt 0) {
            $mfaEnabled = $true
        } else {
            $mfaEnabled = $false
        }

        if ($mfaEnabled) {
            LogMessage "[$($user.UserPrincipalName)] Multi-factor authentication (MFA) is enabled for privileged user."
        } else {
            LogMessage "[$($user.UserPrincipalName)] Multi-factor authentication (MFA) is not enabled for privileged user."
        }
    }

    # Control IAM.2: Ensure that 'Administrator' accounts are not used for day-to-day activities
    $adminAccounts = Get-AzADUser -All $true | Where-Object { $_.IsAdministrator -eq $true }

    foreach ($adminAccount in $adminAccounts) {
        $activities = Get-AzAuditLog -StartDate (Get-Date).AddDays(-30) -Filter "initiatedBy.userPrincipalName eq '$($adminAccount.UserPrincipalName)'"

        if ($activities -eq $null -or $activities.Count -eq 0) {
            LogMessage "[$($adminAccount.UserPrincipalName)] 'Administrator' account has not been used for day-to-day activities in the last 30 days."
        } else {
            LogMessage "[$($adminAccount.UserPrincipalName)] 'Administrator' account has been used for day-to-day activities in the last 30 days."
        }
    }

    # Control IAM.3: Ensure that role assignments are reviewed regularly
    $roleAssignments = Get-AzRoleAssignment | Where-Object { $_.PrincipalType -eq "User" -or $_.PrincipalType -eq "Group" }

    foreach ($roleAssignment in $roleAssignments) {
        $reviewDate = $roleAssignment.Properties.LastModifiedTime
        $daysSinceReview = (Get-Date) - $reviewDate

        if ($daysSinceReview.Days -gt 90) {
            LogMessage "[$($roleAssignment.Properties.PrincipalName)] Role assignment has not been reviewed in the last 90 days."
        }
    }

    # Control IAM.4: Ensure that users have only necessary permissions assigned
    $allRoleAssignments = Get-AzRoleAssignment | Where-Object { $_.PrincipalType -eq "User" -or $_.PrincipalType -eq "Group" }
    $unnecessaryPermissions = @()

    foreach ($roleAssignment in $allRoleAssignments) {
        $roleDefinition = Get-AzRoleDefinition -Id $roleAssignment.Properties.RoleDefinitionId
        $roleName = $roleDefinition.Name

        if ($roleName -eq "Owner" -or $roleName -eq "Contributor") {
            $unnecessaryPermissions += $roleAssignment.Properties.PrincipalName
        }
    }

    if ($unnecessaryPermissions.Count -gt 0) {
        LogMessage "Users have unnecessary permissions (Owner or Contributor roles): $($unnecessaryPermissions -join ', ')."
    }

    # Add more controls checks as needed...
}

# Execute the IAM controls audit
try {
    InitializeLog
    AuditIAMControls
} catch {
    LogMessage "Error occurred: $_"
}
