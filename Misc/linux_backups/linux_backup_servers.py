######################################################################################################################################################################################################################
# Python script and json configuration files to back-up remote Linux servers. Edit the json to the assets that are the targer for backup, and run using sudo python backup_servers.py. By 41ph4-01 23/04/2024 & our community. 
# The script uses key-based authentication for enhanced security.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

def display_splash_screen():
    splash = r"""
    
    
.____    .__                                                     __                  ___.                  __                            __                .__               _____ ______________  ___ ___    _____           _______  ____ 
|    |   |__| ____  __ _____  ___ _______   ____   _____   _____/  |_  ____          \_ |__ _____    ____ |  | ____ ________           _/  |_  ____   ____ |  |             /  |  /_   \______   \/   |   \  /  |  |          \   _  \/_   |
|    |   |  |/    \|  |  \  \/  / \_  __ \_/ __ \ /     \ /  _ \   __\/ __ \   ______ | __ \\__  \ _/ ___\|  |/ /  |  \____ \   ______ \   __\/  _ \ /  _ \|  |    ______  /   |  ||   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
|    |___|  |   |  \  |  />    <   |  | \/\  ___/|  Y Y  (  <_> )  | \  ___/  /_____/ | \_\ \/ __ \\  \___|    <|  |  /  |_> > /_____/  |  | (  <_> |  <_> )  |__ /_____/ /    ^   /   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
|_______ \__|___|  /____//__/\_ \  |__|    \___  >__|_|  /\____/|__|  \___  >         |___  (____  /\___  >__|_ \____/|   __/           |__|  \____/ \____/|____/         \____   ||___||____|    \___|_  /\____   |           \_____  /___|
        \/       \/            \/              \/      \/                 \/              \/     \/     \/     \/     |__|                                                     |__|                     \/      |__|                 \/ 

                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/      (_ _)
                                 /\      {====}     )___(        | |____....----....____         _
                      (\=,      //\\      )__(     /_____\       | |\                . .~~~~---~~ |
      __    |'-'-'|  //  .\    (    )    /____\     |   |        | | |         __\\ /(/(  .       |
     /  \   |_____| (( \_  \    )__(      |  |      |   |        | | |      <--= '|/_/_( /|       |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |        | | |       }\~) | / _(./      ..|
    /____\   |   |  (/     \    |  |      |  |      |   |        | | |.:::::::\\/      --...::::::|
     |  |    |   |   | _.-'|    |  |      |  |      |   |        | | |:::::::::\//::\\__\:::::::::|
     |__|    )___(    )___(    /____\    /____\    /_____\       | | |::::::::_//_:_//__\\_:::::::| 
    (====)  (=====)  (=====)  (======)  (======)  (=======)      | | |::::::::::::::::::::::::::::|
    }===={  }====={  }====={  }======{  }======{  }======={      | |/:::''''~~~~'''':::::::::::::'~
   (______)(_______)(_______)(________)(________)(_________)     | |
    
   
 
"""

    print(splash)
    print("Linux Remote Backup Tool - 41PH4-01 & Our Community\n")


import paramiko
from scp import SCPClient
import os
import datetime
import json

# Load server configuration from a JSON file
def load_config(config_file):
    with open(config_file, 'r') as file:
        config = json.load(file)
    return config

# Create an SSH client with key-based authentication
def create_ssh_client(server, port, user, key_file):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(server, port, user, key_filename=key_file)
    return client

# Execute a command on the remote server
def execute_command(ssh_client, command):
    stdin, stdout, stderr = ssh_client.exec_command(command)
    return stdout.read().decode(), stderr.read().decode()

# Backup function
def backup_server(ssh_client, scp_client, server, backup_dir, remote_backup_server):
    date_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"{server['name']}_full_backup_{date_str}.tar.gz"
    local_backup_file = os.path.join(backup_dir, backup_filename)
    remote_temp_file = f"/tmp/{backup_filename}"

    # Create a full system backup tarball on the remote server
    backup_command = f"sudo tar -czvf {remote_temp_file} --exclude=/tmp/* --exclude=/proc/* --exclude=/sys/* --exclude=/dev/* --exclude=/run/* --exclude=/mnt/* --exclude=/media/* /"
    print(f"Executing backup command on {server['name']}: {backup_command}")
    stdout, stderr = execute_command(ssh_client, backup_command)
    if stderr:
        print(f"Error creating backup on {server['name']}: {stderr}")
        return

    # Download the backup tarball from the remote server
    print(f"Downloading backup from {server['name']} to {local_backup_file}")
    scp_client.get(remote_temp_file, local_backup_file)
    
    # Transfer the backup tarball to the remote backup server
    remote_backup_path = os.path.join(remote_backup_server['backup_dir'], backup_filename)
    remote_ssh_client = create_ssh_client(remote_backup_server['host'], remote_backup_server['port'], remote_backup_server['username'], remote_backup_server['key_file'])
    remote_scp_client = SCPClient(remote_ssh_client.get_transport())
    
    print(f"Transferring backup from {local_backup_file} to {remote_backup_path} on {remote_backup_server['name']}")
    remote_scp_client.put(local_backup_file, remote_backup_path)
    
    # Clean up the backup tarball on the remote server
    cleanup_command = f"sudo rm {remote_temp_file}"
    print(f"Cleaning up temporary backup file on {server['name']}")
    execute_command(ssh_client, cleanup_command)

    # Close remote backup server connections
    remote_scp_client.close()
    remote_ssh_client.close()

# Main function
def main():
    config_file = 'config.json'
    backup_dir = '/path/to/local/backup/dir'  # Local temporary backup storage

    config = load_config(config_file)
    remote_backup_server = config['remote_backup_server']

    for server in config['servers']:
        print(f"Connecting to {server['name']} ({server['host']})")
        
        ssh_client = create_ssh_client(server['host'], server['port'], server['username'], server['key_file'])
        scp_client = SCPClient(ssh_client.get_transport())

        backup_server(ssh_client, scp_client, server, backup_dir, remote_backup_server)

        scp_client.close()
        ssh_client.close()
        print(f"Backup for {server['name']} completed.\n")

if __name__ == '__main__':
    main()


######################################################################################################################################################
# The backup_dir in the script should be set a local temporary backup storage location.
# The remote_backup_server should contain the configuration the remote storage server where the backups will be stored.
# Ensure the user specified in the configuration has the necessary permissions to read the directories and create tarballs on the remote servers.
######################################################################################################################################################

