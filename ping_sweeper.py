import sys
from scapy.all import ICMP, IP, sr1  # Import necessary Scapy modules for packet crafting and sending
from netaddr import IPNetwork  # Import for working with IP ranges and subnetting

# Function to perform a ping sweep across a network
def ping_sweep(network, netmask):
    """
    Scans a given IP network to identify live hosts by sending ICMP echo requests (ping).
    
    Parameters:
    - network (str): The base network address (e.g., '192.168.1.0').
    - netmask (str): The subnet mask (e.g., '24') to define the range of IP addresses.
    
    Returns:
    - live_hosts (list): A list of IP addresses that responded to the ICMP ping.
    """
    live_hosts = []  # List to store IPs of live hosts
    total_hosts = 0  # Total number of hosts in the network
    scanned_hosts = 0  # Counter for scanned hosts

    # Create an IP network object that includes all possible IPs in the subnet
    ip_network = IPNetwork(network + '/' + netmask)

    # Count total hosts in the network
    for host in ip_network.iter_hosts():
        total_hosts += 1

    # Iterate through all possible IPs in the subnet to perform the ping sweep
    for host in ip_network.iter_hosts():
        scanned_hosts += 1
        print(f"Scanning: {scanned_hosts}/{total_hosts}", end="\r")  # Display progress dynamically

        # Send an ICMP echo request (ping) to the current host and wait for a response
        response = sr1(IP(dst=str(host)) / ICMP(), timeout=1, verbose=0)

        # If a response is received, consider the host as live
        if response is not None:
            live_hosts.append(str(host))  # Add the live host to the list
            print(f"Host {host} is online.")  # Print the live host's IP

    return live_hosts  # Return the list of live hosts

# Main script entry point
if __name__ == "__main__":
    # Get the network and netmask from command-line arguments
    # Example usage: python script.py 192.168.1.0 24
    network = sys.argv[1]  # Base network address (e.g., '192.168.1.0')
    netmask = sys.argv[2]  # Subnet mask (e.g., '24')

    # Perform the ping sweep and store live hosts
    live_hosts = ping_sweep(network, netmask)

    # Print summary of the scan
    print("Completed\n")  # Indicate completion of the scan
    print(f"Live hosts: {live_hosts}")  # Display all live hosts found during the scan
