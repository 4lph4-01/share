########################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################################

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
