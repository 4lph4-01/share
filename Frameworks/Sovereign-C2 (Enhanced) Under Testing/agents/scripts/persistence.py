######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

import os
import platform
import subprocess

def add_to_startup(file_path):
    if platform.system() == "Windows":
        add_to_startup_windows(file_path)
    elif platform.system() == "Linux":
        add_to_startup_linux(file_path)
    elif platform.system() == "Darwin":
        add_to_startup_mac(file_path)

def add_to_startup_windows(file_path):
    import winreg as reg

    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "SovereignAgent"
    
    try:
        reg_key = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_WRITE)
        reg.SetValueEx(reg_key, value_name, 0, reg.REG_SZ, file_path)
        reg.CloseKey(reg_key)
        print("Successfully added to Windows startup.")
    except Exception as e:
        print(f"Failed to add to Windows startup: {e}")

def add_to_startup_linux(file_path):
    try:
        cron_job = f"@reboot {file_path}"
        process = subprocess.Popen(['crontab', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if cron_job not in stdout.decode():
            with open("mycron", "w") as f:
                f.write(stdout.decode())
                f.write(cron_job + "\n")
            subprocess.run(['crontab', 'mycron'])
            os.remove("mycron")
        print("Successfully added to Linux startup.")
    except Exception as e:
        print(f"Failed to add to Linux startup: {e}")

def add_to_startup_mac(file_path):
    plist_content = f"""
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.sovereign.agent</string>
        <key>ProgramArguments</key>
        <array>
            <string>{file_path}</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
    </dict>
    </plist>
    """
    plist_path = os.path.expanduser("~/Library/LaunchAgents/com.sovereign.agent.plist")
    try:
        with open(plist_path, "w") as f:
            f.write(plist_content)
        subprocess.run(["launchctl", "load", plist_path])
        print("Successfully added to macOS startup.")
    except Exception as e:
        print(f"Failed to add to macOS startup: {e}")

if __name__ == "__main__":
    file_path = os.path.realpath(__file__)
    add_to_startup(file_path)
