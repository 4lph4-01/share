Sovereign Post-Exploitation Framework

This framework provides advanced post-exploitation capabilities with a focus on evasion and automation.
Features

    -Enhanced Evasion Techniques: Polymorphic code, sandbox detection, time-based evasion.
    -Advanced Post-Exploitation Modules: Credential harvesting, persistence, privilege escalation, 
    -reconnaissance, data exfiltration, keylogging, lateral movement.
    -Secure Communication: Encrypted communication between agent and C2 server.
    -Modular Design: Easily add new modules and functionalities.
    -Logging and Reporting: Detailed logging and report generation.

Usage
Setting Up the C2 Server

    Create a Python virtual environment and activate it:

    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate

    Install the required dependencies:

    pip install -r c2_server/requirements.txt

    Run the C2 server:

    python c2_server/c2_server.py

Using the CLI

The CLI provides various commands to interact with the framework.
List all registered agents:

python cli/cli.py list_agents

