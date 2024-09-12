import socket
import threading
from scapy.all import *

def scan_port(ip, port):
    """Check if a port is open on the given IP."""
    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))  # Attempt connection to the port
        
        if result == 0:  # Port is open
            print(f"[+] {ip}:{port} is open")
        sock.close()
    except:
        pass

def scan_ip(ip):
    """Check if the IP is alive (ping) and scan for open ports."""
    # Ping the IP using Scapy (ICMP request)
    icmp_request = IP(dst=ip)/ICMP()
    resp = sr1(icmp_request, timeout=1, verbose=False)

    if resp:
        print(f"[+] Host {ip} is alive")
        # Scan ports
        for port in range(1, 1025):  # Scan ports 1 to 1024
            scan_port(ip, port)
    else:
        print(f"[-] Host {ip} is unreachable")

def scan_network(network):
    """Scan an entire network range."""
    threads = []
    for ip in network:
        thread = threading.Thread(target=scan_ip, args=(ip,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

# Example: Scanning network 192.168.1.0/24
ip_range = ["192.168.10." + str(i) for i in range(1, 255)]
scan_network(ip_range)
