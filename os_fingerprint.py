#run the script with the follwoing command- python script.py 192.168.1.10 -p 22,80,443 -o output.csv


import argparse  # For parsing command-line arguments
import nmap  # For performing network scans
import csv  # For writing scan results to a CSV file
import os  # For file-related operations
import sys  # For stdout and flushing output

# Function to scan a single host for open ports and services
def scan_host(ip, ports):
    """
    Scans a specified host for open ports and retrieves service information.

    Parameters:
    - ip (str): The IP address of the host to scan.
    - ports (str): The range of ports to scan (e.g., "22,80,443" or "1-1024").

    Returns:
    - host_infos (list): A list of dictionaries containing information about the host's open ports and services.
    """
    nm = nmap.PortScanner()  # Initialize the nmap PortScanner object
    nm.scan(ip, ports)  # Perform a scan on the specified IP and port range
    host_infos = []  # List to store information about each open port

    # Iterate through all protocols (e.g., TCP, UDP) detected on the host
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()  # Get all open ports for the protocol
        for port in lport:
            # Collect information about each open port and its service
            host_info = {
                'ip': ip,
                'os': nm[ip].get('osclass', {}).get('osfamily', 'Unknown'),  # OS family (if detected)
                'port': port,  # Open port number
                'name': nm[ip][proto][port]['name'],  # Service name
                'product': nm[ip][proto][port]['product'],  # Product name (if available)
                'version': nm[ip][proto][port]['version'],  # Product version (if available)
            }
            host_infos.append(host_info)  # Add the port information to the list

    return host_infos

# Function to write scan results to a CSV file
def output_to_csv(output_file, host_info):
    """
    Writes scan information for a single host to a CSV file.

    Parameters:
    - output_file (str): The file path for the CSV output.
    - host_info (dict): A dictionary containing the scan results for a single host.
    """
    fieldnames = ["ip", "os", "port", "name", "product", "version"]  # Define CSV column headers
    file_exists = os.path.isfile(output_file)  # Check if the file already exists

    with open(output_file, "a") as f:  # Open the file in append mode
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:  # If the file doesn't exist, write the header first
            writer.writeheader()
        writer.writerow(host_info)  # Write the host's scan information as a row

# Main function to parse arguments, perform the scan, and output results
def main():
    """
    Parses command-line arguments, performs a host scan, and saves the results to a CSV file.
    """
    # Set up argument parser for the command-line interface
    parser = argparse.ArgumentParser(description="Scan a single host for open ports and services")
    parser.add_argument("host", help="The target host IP address")  # Target IP address
    parser.add_argument("-p", "--ports", help="Ports to scan", type=str, required=True)  # Ports to scan (required)
    parser.add_argument("-o", "--output", help="The output file", default="scan_results.csv")  # Output CSV file (default)
    args = parser.parse_args()  # Parse command-line arguments

    # Extract arguments
    ip = args.host  # Target IP address
    ports = args.ports  # Port range to scan
    output_file = args.output  # Output file path

    # Display scan details to the user
    print(f"Scanning IP: {ip}")
    print(f"Scanning ports: {ports}")

    sys.stdout.write("Scanning ")  # Display scanning status
    sys.stdout.flush()

    # Perform the scan and retrieve results
    host_infos = scan_host(ip, ports)
    
    # Write each host's information to the output file
    for host_info in host_infos:
        output_to_csv(output_file, host_info)

    # Display scan results to the user
    print("\n\nScan results:")
    for host_info in host_infos:
        print(f"IP: {host_info['ip']}")
        print(f"OS: {host_info['os']}")
        print(f"Port: {host_info['port']}")
        print(f"Name: {host_info['name']}")
        print(f"Product: {host_info['product']}")
        print(f"Version: {host_info['version']}\n")

# Entry point of the script
if __name__ == "__main__":
    """
    Executes the main function when the script is run directly.
    """
    main()
