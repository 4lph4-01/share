import dns.resolver
import dns.query
import dns.zone
import subprocess

def display_splash_screen():
    splash = """

________    _______    _________ ___________                                         __  .__                             _____ ______________  ___ ___    _____           _______  ____ 
\______ \   \      \  /   _____/ \_   _____/ ____  __ __  _____   ________________ _/  |_|__| ____   ____               /  |  /_   \______   \/   |   \  /  |  |          \   _  \/_   |
 |    |  \  /   |   \ \_____  \   |    __)_ /    \|  |  \/     \_/ __ \_  __ \__  \\   __\  |/  _ \ /    \    ______   /   |  ||   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |    `   \/    |    \/        \  |        \   |  \  |  /  Y Y  \  ___/|  | \// __ \|  | |  (  <_> )   |  \  /_____/  /    ^   /   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
/_______  /\____|__  /_______  / /_______  /___|  /____/|__|_|  /\___  >__|  (____  /__| |__|\____/|___|  /           \____   ||___||____|    \___|_  /\____   |           \_____  /___|
        \/         \/        \/          \/     \/            \/     \/           \/                    \/                 |__|                     \/      |__|                 \/   
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
    print("Web Application Tool 41PH4-01\n")

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
