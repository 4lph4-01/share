# APT Simulation Tool

This tool is designed to simulate techniques used by Advanced Persistent Threat (APT) groups based on data from the MITRE ATT&CK framework. The tool allows users to select APT groups and simulate their techniques, providing detailed descriptions and generating reports.

## Features

- Load APT group data from a JSON file.
- Display details of APT groups and their techniques.
- Simulate selected techniques.
- Generate reports in text or HTML format.

## Installation

### Prerequisites

- Python 3.6 or later
- `json` and `time` modules (included in the Python standard library)

### Setting Up a Virtual Environment on Linux

1. **Install Python and `venv` module** (if not already installed):
    ```sh
    sudo apt update
    sudo apt install python3 python3-venv python3-pip
    ```

2. **Create a virtual environment:**
    ```sh
    python3 -m venv venv
    ```

3. **Activate the virtual environment:**
    ```sh
    source venv/bin/activate
    ```

4. **Install required Python packages:**
    pip install -r /path/to/requirements.txt. For this script, there are no additional packages to install since `json` and `time` are part of the standard library.

### Running the Simulation

1. Ensure the `apt_groups.json` file is present in the project directory. This JSON file should contain the detailed information of APT groups and their techniques.

2. Run the simulation script:
    ```sh
    python3 mitre_attack.py
    ```

3. Follow the on-screen instructions to select an APT group and techniques to simulate.

## Example JSON Structure

The `apt_groups_with_descriptions.json` file should follow this structure:

```json
{
  "APT40": {
    "name": "APT40",
    "description": "APT40 is a China-based cyber espionage group known for targeting maritime industries and government organizations.",
    "techniques": [
      {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Uses application layer protocols to communicate with command and control servers."
      },
      {
        "id": "T1059",
        "name": "Command-Line Interface",
        "tactic": "Execution",
        "description": "Executes commands and scripts via the command-line interface."
      }
    ]
  }
}

Report Generation

The tool can generate reports in two formats:

    Text: A plain text file containing the details of the simulated techniques.
    HTML: An HTML file with formatted details of the simulated techniques.
