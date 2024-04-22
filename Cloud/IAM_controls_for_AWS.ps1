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

# Execute the IAM controls audit
try {
    InitializeLog
    AuditIAMControls
} catch {
    Write-Output "Error occurred: $_"
}
