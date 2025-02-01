import os

def gather_system_info():
    system_info = {}

    if os.name == 'nt':
        command = "systeminfo"
        result = os.popen(command).read()
        system_info["system_info"] = result
    elif os.name == 'posix':
        # Add Linux/MacOS system information gathering logic
        # Example: Gather system and hardware information on Linux
        command = "uname -a && lsb_release -a && df -h && free -m"
        result = os.popen(command).read()
        system_info["system_info"] = result

    return system_info

if __name__ == "__main__":
    info = gather_system_info()
    for key, value in info.items():
        print(f"{key}: {value}")
