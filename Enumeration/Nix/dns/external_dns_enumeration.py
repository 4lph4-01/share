######################################################################################################################################################################## 
# A basic python script to perform enumeration of DNS (Domain Name Services) externally. By 41ph4-01 23/04/2024 & our community. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the through bruteforce      
# Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, # and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################


import dns.resolver
import dns.query
import dns.zone
import subprocess

# Banner 
def display_splash_screen():
    splash = r"""
   
    
 ___________          __                                .__    ________                  ___________                                           __  .__                            _____  ____.____   __________  ___ ___    _____           _______  ____ 
\_   _____/___  ____/  |_   ____ _______  ____ _____   |  |   \______ \   ____   ______ \_   _____/ ____  __ __  _____   ____ ____________  _/  |_|__| ____   ____              /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
 |    __)_ \  \/  /\   __\_/ __ \\_  __ \/    \\__  \  |  |    |    |  \ /    \ /  ___/  |    __)_ /    \|  |  \/     \_/ __ \\_  __ \__  \ \   __\  |/  _ \ /    \   ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |        \ >    <  |  |  \  ___/ |  | \/   |  \/ __ \_|  |__  |    `   \   |  \\___ \   |        \   |  \  |  /  Y Y  \  ___/ |  | \// __ \_|  | |  (  <_> )   |  \ /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
/_______  //__/\_ \ |__|   \___  >|__|  |___|  (____  /|____/ /_______  /___|  /____  > /_______  /___|  /____/|__|_|  /\___  >|__|  (____  /|__| |__|\____/|___|  /          \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
        \/       \/            \/            \/     \/                \/     \/     \/          \/     \/            \/     \/            \/                     \/                |__|             \/               \/      |__|                 \/   
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
   (______)(_______)(_______)(________)(________)(__________)    | |
    
"""

    print(splash)
    print("External Dns Enumeration - 41PH4-01 & Our Community\n")

def enumerate_dns_records(domain, dns_server):
    record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SRV"]

    for record_type in record_types:
        print(f"Enumerating {record_type} records for {domain}")
        try:
            answers = dns.resolver.resolve(domain, record_type, tcp=True, lifetime=5, source=dns_server)
            for answer in answers:
                print(f"{record_type} record: {answer}")
        except dns.resolver.NoAnswer:
            print(f"No {record_type} records found for {domain}")
        except Exception as e:
            print(f"Error enumerating {record_type} records for {domain}: {e}")

def test_dns_zone_transfer(domain, dns_server):
    print(f"Testing for DNS zone transfer vulnerability for {domain}")
    try:
        answers = dns.resolver.resolve(domain, 'NS', tcp=True, lifetime=5, source=dns_server)
        for ns in answers:
            ns_server = str(ns.target)
            print(f"Attempting zone transfer with {ns_server}")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
                if zone:
                    print(f"Zone transfer successful with {ns_server}")
                    for name, node in zone.nodes.items():
                        print(zone[name].to_text(name))
                else:
                    print(f"Zone transfer failed with {ns_server}")
            except Exception as e:
                print(f"Error during zone transfer attempt with {ns_server}: {e}")
    except Exception as e:
        print(f"Error resolving NS records for {domain}: {e}")

def perform_dns_queries(domain, dns_server):
    print(f"Performing basic DNS queries for {domain}")

    try:
        answers = dns.resolver.resolve(domain, 'A', tcp=True, lifetime=5, source=dns_server)
        for answer in answers:
            print(f"A record for {domain}: {answer}")
    except Exception as e:
        print(f"Error resolving A records for {domain}: {e}")

    try:
        answers = dns.resolver.resolve(domain, 'MX', tcp=True, lifetime=5, source=dns_server)
        for answer in answers:
            print(f"MX record: {answer.exchange} - Preference: {answer.preference}")
    except Exception as e:
        print(f"Error resolving MX records for {domain}: {e}")

    try:
        answers = dns.resolver.resolve(domain, 'TXT', tcp=True, lifetime=5, source=dns_server)
        for answer in answers:
            print(f"TXT record: {answer}")
    except Exception as e:
        print(f"Error resolving TXT records for {domain}: {e}")

def run_pen_test(domain, dns_server):
    enumerate_dns_records(domain, dns_server)
    test_dns_zone_transfer(domain, dns_server)
    perform_dns_queries(domain, dns_server)

# Define the domain and DNS server to test
domain = "example.com"
dns_server = "8.8.8.8"  # Google DNS server

# Run the penetration test
run_pen_test(domain, dns_server)
