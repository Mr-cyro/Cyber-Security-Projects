import os
from scapy.all import ICMP, IP, sr1, TCP, sr  # Import necessary modules from Scapy for network scanning
from ipaddress import ip_network  # Import for working with IP ranges and subnets
from concurrent.futures import ThreadPoolExecutor, as_completed  # For parallel task execution
from threading import Lock  # For thread-safe printing

# Lock object to prevent simultaneous print statements from threads
print_lock = Lock()

# Function to send an ICMP echo request (ping) to a single host
def ping(host):
    """
    Sends an ICMP echo request (ping) to the specified host.
    
    Parameters:
    - host (str): The IP address to ping.

    Returns:
    - str: The IP address if the host responds, otherwise None.
    """
    response = sr1(IP(dst=str(host)) / ICMP(), timeout=1, verbose=0)  # Send ICMP packet
    if response is not None:
        return str(host)  # Return host if it responds
    return None

# Function to perform a ping sweep over a network
def ping_sweep(network, netmask):
    """
    Scans a network to identify live hosts by sending ICMP echo requests.
    
    Parameters:
    - network (str): The base network address (e.g., '192.168.1.0').
    - netmask (str): The subnet mask (e.g., '24').

    Returns:
    - live_hosts (list): A list of IP addresses that responded to pings.
    """
    live_hosts = []  # List to store live hosts

    num_threads = os.cpu_count()  # Number of threads equals CPU cores for parallelism
    hosts = list(ip_network(network + '/' + netmask).hosts())  # Generate a list of all host IPs
    total_hosts = len(hosts)  # Count total hosts in the network
    
    # Use ThreadPoolExecutor for multithreaded pinging
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(ping, host): host for host in hosts}  # Submit ping tasks
        for i, future in enumerate(as_completed(futures), start=1):
            host = futures[future]
            result = future.result()
            with print_lock:
                print(f"Scanning: {i}/{total_hosts}", end="\r")  # Show progress dynamically
                if result is not None:
                    print(f"\nHost {host} is online.")  # Print live host
                    live_hosts.append(result)  # Add live host to the list

    return live_hosts

# Function to scan a specific port on a host
def scan_port(args):
    """
    Scans a specific port on a given host using a TCP SYN request.
    
    Parameters:
    - args (tuple): A tuple containing the IP address and port to scan.

    Returns:
    - int: The port number if the port is open, otherwise None.
    """
    ip, port = args
    # Send a TCP SYN packet and wait for a response
    response = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=0)
    if response is not None and response[TCP].flags == "SA":  # Check if SYN-ACK response is received
        return port  # Port is open
    return None

# Function to scan multiple ports on a host
def port_scan(ip, ports):
    """
    Scans a range of ports on a given host to identify open ports.
    
    Parameters:
    - ip (str): The IP address of the host to scan.
    - ports (range): The range of ports to scan.

    Returns:
    - open_ports (list): A list of open ports on the host.
    """
    open_ports = []  # List to store open ports

    num_threads = os.cpu_count()  # Number of threads for parallelism
    total_ports = len(ports)  # Total number of ports to scan
    
    # Use ThreadPoolExecutor for multithreaded port scanning
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_port, (ip, port)): port for port in ports}  # Submit scan tasks
        for i, future in enumerate(as_completed(futures), start=1):
            port = futures[future]
            result = future.result()
            with print_lock:
                print(f"Scanning {ip}: {i}/{total_ports}", end="\r")  # Show progress dynamically
                if result is not None:
                    print(f"\nPort {port} is open on host {ip}")  # Print open port
                    open_ports.append(result)  # Add open port to the list

    return open_ports

# Function to perform a complete scan: live hosts and their open ports
def get_live_hosts_and_ports(network, netmask):
    """
    Combines ping sweep and port scanning to identify live hosts and their open ports.
    
    Parameters:
    - network (str): The base network address (e.g., '192.168.1.0').
    - netmask (str): The subnet mask (e.g., '24').

    Returns:
    - host_port_mapping (dict): A dictionary mapping live hosts to their open ports.
    """
    live_hosts = ping_sweep(network, netmask)  # Perform ping sweep to find live hosts

    host_port_mapping = {}  # Dictionary to store host-to-port mappings
    ports = range(1, 1024)  # Common port range to scan
    for host in live_hosts:
        open_ports = port_scan(host, ports)  # Scan ports on the live host
        host_port_mapping[host] = open_ports  # Map host to its open ports

    return host_port_mapping

# Main script entry point
if __name__ == "__main__":
    import sys  # Import sys for command-line arguments

    # Get network and netmask from command-line arguments
    # Example usage: python script.py 192.168.1.0 24
    network = sys.argv[1]  # Base network address (e.g., '192.168.1.0')
    netmask = sys.argv[2]  # Subnet mask (e.g., '24')

    # Perform a full scan and get live hosts and open ports
    host_port_mapping = get_live_hosts_and_ports(network, netmask)

    # Print the results: live hosts and their open ports
    for host, open_ports in host_port_mapping.items():
        print(f"\nHost {host} has the following open ports: {open_ports}")
