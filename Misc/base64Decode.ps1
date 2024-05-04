$encodedText=
"Place base64 code here"
$DecodedText=
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedText))
$DecodedText
