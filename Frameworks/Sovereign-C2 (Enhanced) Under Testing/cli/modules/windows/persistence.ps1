# Registry persistence
$command = 'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MyApp /t REG_SZ /d "C:\path\to\your\agent.exe" /f'
Invoke-Expression $command

# Scheduled Task persistence
$taskName = "MyPersistentTask"
$command = 'schtasks /create /tn $taskName /tr "C:\path\to\your\agent.exe" /sc onlogon /f'
Invoke-Expression $command
