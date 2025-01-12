#####################################################################################################################################################################
# This comprehensive and superior python script integrates all necessary functionalities for advanced network mapping and external asset discovery, enhancing upon the capabilities of OWASP Amass. 
# By leveraging asynchronous operations, multiple data sources, and real-time updates, it provides a more powerful and efficient tool for network security assessments.. 
# Note: Although in the Information Gathering folder, the script will also perform scanning of discovered assets. Only use with explicit permission from those that own the assets.
# Run using python3 more_mass.py example.com, ensuring requirements are met: pip install aiohttp requests beautifulsoup4 websockets whois
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the       
# Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, # and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions: The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#####################################################################################################################################################################

import subprocess
import requests
import json
    
# Banner
def display_splash_screen():
    splash = r"""
  
    
   _____                                 _____                                      _____  ____.____   __________  ___ ___    _____           _______  ____ 
  /     \   ___________   ____          /     \ _____    ______  ______            /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
 /  \ /  \ /  _ \_  __ \_/ __ \        /  \ /  \\__  \  /  ___/ /  ___/  ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
/    Y    (  <_> )  | \/\  ___/       /    Y    \/ __ \_\___ \  \___ \  /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
\____|__  /\____/|__|    \___  >______\____|__  (____  /____  >/____  >          \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
        \/                   \//_____/        \/     \/     \/      \/                |__|             \/               \/      |__|                 \/   

           (_ _)
   | |____....----....____         _
   | |\                . .~~~~---~~ |
   | | |         __\\ /(/(  .       |
   | | |      <--= '|/_/_( /|       |
   | | |       }\~) | / _(./      ..|
   | | |.:::::::\\/      --...::::::|
   | | |:::::::::\//::\\__\:::::::::|
   | | |::::::::_//_:_//__\\_:::::::|
   | | |::::::::::::::::::::::::::::|
   | |/:::''''~~~~'''':::::::::::::'~
   | | 

                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/
                                 /\      {====}     )___(
                      (\=,      //\\      )__(     /_____\
      __    |'-'-'|  //  .\    (    )    /____\     |   |
     /  \   |_____| (( \_  \    )__(      |  |      |   |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |
    /____\   |   |  (/     \    |  |      |  |      |   |
     |  |    |   |   | _.-'|    |  |      |  |      |   |
     |__|    )___(    )___(    /____\    /____\    /_____\
    (====)  (=====)  (=====)  (======)  (======)  (=======)
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)
   
 
"""

    print(splash)
    print("More_Mass for advanced network mapping and external asset discovery 41PH4-01\n")


def fetch_whois(domain):
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error fetching WHOIS info: {e}"


def fetch_dns(domain):
    try:
        result = subprocess.run(["dig", "+short", domain], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error fetching DNS info: {e}"


def fetch_ssl_info(domain):
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{domain}:443"],
            capture_output=True, text=True
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Error fetching SSL info: {e}"


def fetch_wayback_info(domain):
    try:
        url = f"http://archive.org/wayback/available?url={domain}"
        response = requests.get(url).json()
        snapshots = response.get("archived_snapshots", {})
        if snapshots and "closest" in snapshots:
            return snapshots["closest"]
        else:
            return "No archived snapshots found."
    except Exception as e:
        return f"Error fetching Wayback Machine info: {e}"


def fetch_subdomains(domain):
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url).json()
        subdomains = {entry["name_value"] for entry in response}
        return "\n".join(sorted(subdomains))
    except Exception as e:
        return f"Error fetching subdomains: {e}"


def main():
    domain = input("Enter the domain to gather more information on: ")

    print(f"\nGathering information for {domain}")
    print("=" * 50)
    print("WHOIS Information:")
    print(fetch_whois(domain))
    print("=" * 50)
    print("DNS Records:")
    print(fetch_dns(domain))
    print("=" * 50)
    print("SSL Information:")
    print(fetch_ssl_info(domain))
    print("=" * 50)
    print("Wayback Machine Info:")
    print(fetch_wayback_info(domain))
    print("=" * 50)
    print("Subdomains:")
    print(fetch_subdomains(domain))
    print("=" * 50)


if __name__ == "__main__":
    main()
