import os

def escalate_privileges():
    if os.name == 'nt':
        command = "powershell -Command \"Start-Process cmd -Verb runAs\""
        os.system(command)
