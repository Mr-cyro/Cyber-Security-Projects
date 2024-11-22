import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP

# Define a threshold for packet rate (packets per second) to block IPs
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Function to read IPs from a file (used for whitelist and blacklist)
def read_ip_file(filename):
    """
    Reads a list of IP addresses from the specified file.
    Each line in the file should contain one IP address.
    """
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)

# Function to check if a packet contains Nimda worm signature
def is_nimda_worm(packet):
    """
    Detects the presence of the Nimda worm signature in a TCP packet.
    The worm sends a specific HTTP GET request to exploit a vulnerability.
    """
    if packet.haslayer(TCP) and packet[TCP].dport == 80:  # Check if the packet is TCP and targets port 80 (HTTP)
        payload = packet[TCP].payload  # Extract TCP payload
        return "GET /scripts/root.exe" in str(payload)  # Check for the Nimda worm signature
    return False

# Function to log events into a file
def log_event(message):
    """
    Logs an event message into a timestamped file within the "logs" folder.
    """
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)  # Ensure the logs directory exists
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())  # Generate a timestamp for the log
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")  # Log file name based on timestamp
    
    with open(log_file, "a") as file:  # Open log file in append mode
        file.write(f"{message}\n")  # Write the log message

# Callback function to process each packet captured by Scapy
def packet_callback(packet):
    """
    Processes captured packets, checking for:
    - Whitelist and blacklist status
    - Nimda worm signatures
    - Packet rate threshold violations
    """
    src_ip = packet[IP].src  # Extract source IP address from the packet

    # Skip processing if the source IP is in the whitelist
    if src_ip in whitelist_ips:
        return

    # Block and log if the source IP is in the blacklist
    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")  # Block IP using iptables
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return

    # Check for Nimda worm signature and block if detected
    if is_nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")  # Block IP using iptables
        log_event(f"Blocking Nimda source IP: {src_ip}")
        return

    # Increment packet count for the source IP
    packet_count[src_ip] += 1

    current_time = time.time()  # Get the current time
    time_interval = current_time - start_time[0]  # Calculate time elapsed since last reset

    # Check packet rate every second
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval  # Calculate packets per second

            # Block IP if packet rate exceeds threshold and it's not already blocked
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")  # Block IP using iptables
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)  # Add IP to the blocked list

        # Clear packet counts and reset the start time for the next interval
        packet_count.clear()
        start_time[0] = current_time

# Main function to initialize and start the packet monitoring
if __name__ == "__main__":
    # Ensure the script is run with root privileges
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    # Load whitelist and blacklist IPs from files
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    # Initialize data structures for packet rate tracking
    packet_count = defaultdict(int)  # Track the number of packets per IP
    start_time = [time.time()]  # Track the start time for rate calculations
    blocked_ips = set()  # Track already blocked IPs

    print("Monitoring network traffic...")

    # Start capturing packets and process each with the callback
    sniff(filter="ip", prn=packet_callback)
