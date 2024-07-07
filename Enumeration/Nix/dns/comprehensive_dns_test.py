import dns.resolver
import dns.query
import dns.zone
import dns.reversename
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


def enumerate_dns_records(domain, dns_server):
    record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SRV", "SOA", "PTR"]

    for record_type in record_types:
        print(f"Enumerating {record_type} records for {domain} using DNS server {dns_server}")
        try:
            answers = dns.resolver.resolve(domain, record_type, tcp=True, source=dns_server)
            for answer in answers:
                print(f"{record_type} record: {answer}")
        except dns.resolver.NoAnswer:
            print(f"No {record_type} records found for {domain}")
        except Exception as e:
            print(f"Error enumerating {record_type} records for {domain}: {e}")

def test_dns_zone_transfer(domain, dns_server):
    print(f"Testing for DNS zone transfer vulnerability for {domain} using DNS server {dns_server}")
    try:
        answers = dns.resolver.resolve(domain, 'NS', tcp=True, source=dns_server)
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
    print(f"Performing basic DNS queries for {domain} using DNS server {dns_server}")

    try:
        answers = dns.resolver.resolve(domain, 'A', tcp=True, source=dns_server)
        for answer in answers:
            print(f"A record for {domain}: {answer}")
    except Exception as e:
        print(f"Error resolving A records for {domain}: {e}")

    try:
        answers = dns.resolver.resolve(domain, 'MX', tcp=True, source=dns_server)
        for answer in answers:
            print(f"MX record: {answer.exchange} - Preference: {answer.preference}")
    except Exception as e:
        print(f"Error resolving MX records for {domain}: {e}")

    try:
        answers = dns.resolver.resolve(domain, 'TXT', tcp=True, source=dns_server)
        for answer in answers:
            print(f"TXT record: {answer}")
    except Exception as e:
        print(f"Error resolving TXT records for {domain}: {e}")

def reverse_dns_lookup(ip_address, dns_server):
    print(f"Performing reverse DNS lookup for {ip_address}")
    try:
        rev_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(rev_name, 'PTR', tcp=True, source=dns_server)
        for answer in answers:
            print(f"PTR record: {answer}")
    except Exception as e:
        print(f"Error performing reverse DNS lookup for {ip_address}: {e}")

def check_dnssec(domain, dns_server):
    print(f"Checking DNSSEC configuration for {domain}")
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY', tcp=True, source=dns_server)
        for answer in answers:
            print(f"DNSKEY record: {answer}")
        print("DNSSEC is enabled for this domain.")
    except dns.resolver.NoAnswer:
        print("DNSSEC is not enabled for this domain.")
    except Exception as e:
        print(f"Error checking DNSSEC for {domain}: {e}")

def subdomain_enumeration(domain, dns_server, wordlist):
    print(f"Enumerating subdomains for {domain} using DNS server {dns_server}")
    try:
        with open(wordlist, 'r') as file:
            subdomains = file.readlines()
        
        for subdomain in subdomains:
            subdomain = subdomain.strip()
            full_domain = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A', tcp=True, source=dns_server)
                for answer in answers:
                    print(f"A record for {full_domain}: {answer}")
            except dns.resolver.NoAnswer:
                print(f"No A records found for {full_domain}")
            except Exception as e:
                print(f"Error resolving {full_domain}: {e}")
    except Exception as e:
        print(f"Error reading wordlist: {e}")

def run_pen_test(domain, internal_dns_server, external_dns_server, wordlist):
    print("Running penetration test against internal DNS server")
    enumerate_dns_records(domain, internal_dns_server)
    test_dns_zone_transfer(domain, internal_dns_server)
    perform_dns_queries(domain, internal_dns_server)
    subdomain_enumeration(domain, internal_dns_server, wordlist)
    check_dnssec(domain, internal_dns_server)

    print("Running penetration test against external DNS server")
    enumerate_dns_records(domain, external_dns_server)
    test_dns_zone_transfer(domain, external_dns_server)
    perform_dns_queries(domain, external_dns_server)
    subdomain_enumeration(domain, external_dns_server, wordlist)
    check_dnssec(domain, external_dns_server)

# Define the domain and DNS servers to test
domain = "example.com"
internal_dns_server = "192.168.1.1"  # Change to your internal DNS server IP
external_dns_server = "8.8.8.8"  # Google DNS server for external testing
wordlist = "subdomains.txt"  # Path to your wordlist for subdomain enumeration

# Run the penetration test
run_pen_test(domain, internal_dns_server, external_dns_server, wordlist)
