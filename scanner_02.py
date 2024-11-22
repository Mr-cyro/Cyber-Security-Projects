import os  # For accessing CPU count and other OS-level operations
from scapy.all import ICMP, IP, sr1, TCP, sr  # For sending and receiving network packets
from ipaddress import ip_network  # For handling IP ranges and subnets
from concurrent.futures import ThreadPoolExecutor, as_completed  # For parallel task execution
from threading import Lock  # To ensure thread-safe printing

# Create a lock for synchronized printing in multithreaded execution
print_lock = Lock()

# Function to ping a single host
def ping(host):
    """
    Sends an ICMP echo request (ping) to a host and checks if it responds.

    Parameters:
    - host (str): The IP address of the host to ping.

    Returns:
    - str: The IP address of the host if it responds, otherwise None.
    """
    response = sr1(IP(dst=str(host)) / ICMP(), timeout=1, verbose=0)  # Send ICMP echo request
    if response is not None:  # Check if a response was received
        return str(host)  # Return the host's IP if it responded
    return None  # Return None if no response

# Function to perform a ping sweep over a network
def ping_sweep(network, netmask):
    """
    Performs a ping sweep on a network to identify live hosts.

    Parameters:
    - network (str): The base network address (e.g., "192.168.1.0").
    - netmask (str): The subnet mask (e.g., "24").

    Returns:
    - live_hosts (list): A list of IP addresses that responded to pings.
    """
    live_hosts = []  # List to store live hosts
    num_threads = os.cpu_count()  # Use the number of CPU cores for parallelism
    hosts = list(ip_network(network + '/' + netmask).hosts())  # Generate all host IPs in the network
    total_hosts = len(hosts)  # Get the total number of hosts

    # Use a ThreadPoolExecutor for parallel execution of ping tasks
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit ping tasks for all hosts
        futures = {executor.submit(ping, host): host for host in hosts}
        for i, future in enumerate(as_completed(futures), start=1):  # Process completed tasks
            host = futures[future]
            result = future.result()
            with print_lock:  # Use lock to prevent race conditions during print
                print(f"Scanning: {i}/{total_hosts}", end="\r")  # Update progress
                if result is not None:  # If the host responded
                    print(f"\nHost {host} is online.")  # Print the live host
                    live_hosts.append(result)  # Add the host to the list of live hosts

    return live_hosts  # Return the list of live hosts

# Function to scan a specific port on a host
def scan_port(args):
    """
    Scans a specific port on a given host to check if it's open.

    Parameters:
    - args (tuple): A tuple containing the IP address and port to scan.

    Returns:
    - int: The port number if it's open, otherwise None.
    """
    ip, port = args
    response = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=0)  # Send TCP SYN
    if response is not None and response[TCP].flags == "SA":  # Check for SYN-ACK response
        return port  # Port is open
    return None  # Port is closed

# Function to scan multiple ports on a host
def port_scan(ip, ports):
    """
    Scans a range of ports on a given host to identify open ports.

    Parameters:
    - ip (str): The IP address of the host.
    - ports (range): A range of ports to scan.

    Returns:
    - open_ports (list): A list of open ports on the host.
    """
    open_ports = []  # List to store open ports
    num_threads = os.cpu_count()  # Use the number of CPU cores for parallelism
    total_ports = len(ports)  # Total number of ports to scan

    # Use a ThreadPoolExecutor for parallel execution of port scan tasks
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit port scan tasks for all specified ports
        futures = {executor.submit(scan_port, (ip, port)): port for port in ports}
        for i, future in enumerate(as_completed(futures), start=1):  # Process completed tasks
            port = futures[future]
            result = future.result()
            with print_lock:  # Use lock to prevent race conditions during print
                print(f"Scanning {ip}: {i}/{total_ports}", end="\r")  # Update progress
                if result is not None:  # If the port is open
                    print(f"\nPort {port} is open on host {ip}")  # Print open port
                    open_ports.append(result)  # Add the open port to the list

    return open_ports  # Return the list of open ports

# Function to perform a full network scan for live hosts and open ports
def get_live_hosts_and_ports(network, netmask):
    """
    Performs a network scan to identify live hosts and their open ports.

    Parameters:
    - network (str): The base network address (e.g., "192.168.1.0").
    - netmask (str): The subnet mask (e.g., "24").

    Returns:
    - host_port_mapping (dict): A dictionary mapping each live host to its open ports.
    """
    live_hosts = ping_sweep(network, netmask)  # Perform a ping sweep to find live hosts
    host_port_mapping = {}  # Dictionary to store host-to-port mappings
    ports = range(1, 1024)  # Common range of ports to scan
    for host in live_hosts:  # Iterate through each live host
        open_ports = port_scan(host, ports)  # Perform a port scan on the host
        host_port_mapping[host] = open_ports  # Map the host to its open ports

    return host_port_mapping  # Return the host-to-port mapping

# Main block to execute the script
if __name__ == "__main__":
    """
    Executes the network scan when the script is run directly.
    """
    import sys  # For command-line arguments
    network = sys.argv[1]  # Get the network address from the command line
    netmask = sys.argv[2]  # Get the netmask from the command line
    host_port_mapping = get_live_hosts_and_ports(network, netmask)  # Perform the network scan

    # Print the results of the scan
    for host, open_ports in host_port_mapping.items():
        print(f"\nHost {host} has the following open ports: {open_ports}")
