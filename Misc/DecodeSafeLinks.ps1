Clear-Host
$encodedURL = Read-Host("Please provide the ATP SafeLinks URL that you want to decode to original URL")
Add-Type -AssemblyName System.Web

try
{
$decodedURL = [System.Web.HttpUtility]::UrlDecode($encodedURL)
#$decodedURL = (($decodedURL -Split "url=")[1] -split "&data=;")[0]
if($decodedURL -match ".safelinks.protection.outlook.com\/\?url=.+&data=")
{
$decodedURL = $Matches[$Matches.Count - 1]
$decodedURL = (($decodedURL -Split "\?url=")[1] -Split "&data=")[0]
}
elseif($decodedURL -match ".safelinks.protection.outlook.com\/\?url=.+&amp;data=")
{
$decodedURL = $Matches[$Matches.Count - 1]
$decodedURL = (($decodedURL -Split "\?url=")[1] -Split "&amp;data=")[0]
}
else{throw "InvalidSafeLinksURL"}
}
catch
{
Write-Log -function "Start-AP_DecodeSafeLinksURL" -step "Decoding URL" -Description "Couldn't decode and parse URL: $encodedURL"
Write-Host "Couldn't decode and parse URL: $encodedURL"
Read-Host "Press any key and then to reload main menu [Enter]"

}


Write-Host "The decoded URL is:" -ForegroundColor Green
Write-Host $decodedURL