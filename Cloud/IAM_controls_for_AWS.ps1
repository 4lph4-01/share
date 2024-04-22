#########################################################################################################################################################################################################################
# AWS Identity Access Management Script (IAM) PS Script (Included examples, IAM 1, IAM 2, IAM 3, and IAM 4  Controls only)
# Expand and add additional controls as required. 21/04/2024
# https://github.com/microsoft/configmgr-hub/blob/master/samples/CommonFunctions.ps1
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

# Function to audit IAM controls
function AuditIAMControls {
    # Control IAM.1: Ensure that multi-factor authentication (MFA) is enabled for all privileged users
    $privilegedUsers = Get-IAMUser | Where-Object { $_.PermissionsBoundary -ne $null }

    foreach ($user in $privilegedUsers) {
        $mfaEnabled = $null
        $userMFADetails = Get-IAMUserMFA -UserName $user.UserName

        if ($userMFADetails -ne $null -and $userMFADetails.MFADevices.Count -gt 0) {
            $mfaEnabled = $true
        } else {
            $mfaEnabled = $false
        }

        if ($mfaEnabled) {
            Write-Output "[$($user.UserName)] Multi-factor authentication (MFA) is enabled for privileged user."
        } else {
            Write-Output "[$($user.UserName)] Multi-factor authentication (MFA) is not enabled for privileged user."
        }
    }

    # Control IAM.2: Ensure that 'Administrator' accounts are not used for day-to-day activities
    $adminAccounts = Get-IAMUser | Where-Object { $_.PermissionsBoundary -ne $null }

    foreach ($adminAccount in $adminAccounts) {
        $activities = Get-IAMAuditLog -UserName $adminAccount.UserName -StartDate (Get-Date).AddDays(-30)

        if ($activities -eq $null -or $activities.Count -eq 0) {
            Write-Output "[$($adminAccount.UserName)] 'Administrator' account has not been used for day-to-day activities in the last 30 days."
        } else {
            Write-Output "[$($adminAccount.UserName)] 'Administrator' account has been used for day-to-day activities in the last 30 days."
        }
    }

    # Control IAM.3: Ensure that role assignments are reviewed regularly
    $roleAssignments = Get-IAMRole | Get-IAMRolePolicy -AllVersions

    foreach ($roleAssignment in $roleAssignments) {
        $reviewDate = $roleAssignment.CreateDate
        $daysSinceReview = (Get-Date) - $reviewDate

        if ($daysSinceReview.Days -gt 90) {
            Write-Output "[$($roleAssignment.RoleName)] Role assignment has not been reviewed in the last 90 days."
        }
    }

    # Control IAM.4: Ensure that users have only necessary permissions assigned
    $allRoleAssignments = Get-IAMRole | Get-IAMRolePolicy -AllVersions
    $unnecessaryPermissions = @()

    foreach ($roleAssignment in $allRoleAssignments) {
        $roleName = $roleAssignment.RoleName

        if ($roleName -eq "AdministratorAccess" -or $roleName -eq "PowerUserAccess") {
            $unnecessaryPermissions += $roleAssignment.UserName
        }
    }

    if ($unnecessaryPermissions.Count -gt 0) {
        Write-Output "Users have unnecessary permissions (AdministratorAccess or PowerUserAccess roles): $($unnecessaryPermissions -join ', ')."
    }

    # Add more controls checks as needed...
}

# Execute the IAM controls Audit
try {
    InitializeLog
    AuditIAMControls
} catch {
    Write-Output "Error occurred: $_"
}
