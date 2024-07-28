$script = Get-Content -Path .\reverse_shell.ps1 -Raw
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$encoded = [Convert]::ToBase64String($bytes)
$encoded
