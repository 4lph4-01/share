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

def gather_system_info():
    system_info = {}

    if os.name == 'nt':
        script_path = os.path.join(os.path.dirname(__file__), 'windows', 'reconnaissance.ps1')
        result = os.popen(f"powershell -ExecutionPolicy Bypass -File {script_path}").read()
        system_info["system_info"] = result
    elif os.name == 'posix':
        command = "uname -a && lsb_release -a && df -h && free -m"
        result = os.popen(command).read()
        system_info["system_info"] = result

    return system_info

if __name__ == "__main__":
    info = gather_system_info()
    for key, value in info.items():
        print(f"{key}: {value}")
