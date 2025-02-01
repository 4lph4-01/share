import socket

# Description: Performs a port scan on a specified host

HOST = "192.168.1.1"
PORTS = [22, 80, 443]

def port_scan(host, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Perform port scan
open_ports = port_scan(HOST, PORTS)
print("Open ports:", open_ports)

