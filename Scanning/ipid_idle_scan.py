from scapy.all import *
import re

def is_valid_ip(ip):
    """Validate an IPv4 address."""
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(pattern, ip):
        return all(0 <= int(octet) <= 255 for octet in ip.split("."))
    return False

def send_probe(zombie_ip, target_ip, port, timeout=2):
    """Send SYN probe to target and record IPID of zombie."""
    # Send SYN packet to the target using the zombie's spoofed IP
    syn_packet = IP(src=zombie_ip, dst=target_ip) / TCP(dport=port, flags="S")
    send(syn_packet, verbose=False)

    # Check IPID on the zombie after the target's response
    probe_packet = IP(dst=zombie_ip) / ICMP()
    response = sr1(probe_packet, timeout=timeout, verbose=False)
    
    if response:
        return response.id
    return None

def ipid_idle_scan(zombie_ip, target_ip, ports, timeout=2):
    """Perform an IPID Idle Scan."""
    open_ports = []
    print(f"Starting IPID Idle Scan using {zombie_ip} as the zombie...")
    
    for port in ports:
        print(f"Scanning port {port}...")
        
        # Send initial probe to zombie and record IPID
        initial_ipid = send_probe(zombie_ip, target_ip, port, timeout)
        if initial_ipid is None:
            print(f"Zombie {zombie_ip} did not respond. Skipping scan.")
            return

        # Send SYN to target spoofed as the zombie
        send_probe(zombie_ip, target_ip, port, timeout)

        # Send a follow-up probe to the zombie
        final_ipid = send_probe(zombie_ip, target_ip, port, timeout)

        # Determine if port is open based on IPID increment
        if final_ipid and final_ipid == initial_ipid + 2:
            print(f"Port {port} is OPEN!")
            open_ports.append(port)
        else:
            print(f"Port {port} is CLOSED or FILTERED.")

    print("\nScan completed.")
    print(f"Open Ports: {open_ports}")

if __name__ == "__main__":
    try:
        # Prompt for inputs with validation
        while True:
            zombie_ip = input("Enter the zombie IP address: ").strip()
            if is_valid_ip(zombie_ip):
                break
            print("Invalid IP address. Please try again.")

        while True:
            target_ip = input("Enter the target IP address: ").strip()
            if is_valid_ip(target_ip):
                break
            print("Invalid IP address. Please try again.")

        ports_input = input("Enter the target ports (comma-separated, e.g., 22,80,443) [Default: 22,80,443]: ").strip()
        if ports_input:
            try:
                ports = [int(port.strip()) for port in ports_input.split(",")]
                if all(0 < port <= 65535 for port in ports):
                    pass
                else:
                    raise ValueError
            except ValueError:
                print("Invalid port numbers. Please provide valid ports.")
                exit(1)
        else:
            ports = [22, 80, 443]  # Default ports

        timeout_input = input("Enter timeout for responses in seconds [Default: 2]: ").strip()
        timeout = int(timeout_input) if timeout_input.isdigit() else 2

        ipid_idle_scan(zombie_ip, target_ip, ports, timeout)
    except KeyboardInterrupt:
        print("\nScan interrupted.")
    except Exception as e:
        print(f"Error: {e}")

