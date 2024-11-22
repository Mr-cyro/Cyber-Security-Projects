#to run script -  python script.py 192.168.1.1 -p 22,80,443 -o results.csv


import argparse  # For parsing command-line arguments
import nmap  # For performing network scans
import csv  # For writing scan results to a CSV file
import os  # For file operations
import sys  # For stdout operations and command-line argument handling

# Function to scan a host for open ports and services
def scan_host(ip, ports):
    """
    Scans a specified host for open ports and retrieves service details.

    Parameters:
    - ip (str): The IP address of the host to scan.
    - ports (str): A string representing the range of ports to scan (e.g., "22,80,443" or "1-1024").

    Returns:
    - host_infos (list): A list of dictionaries containing information about each open port and service.
    """
    nm = nmap.PortScanner()  # Initialize the nmap PortScanner
    nm.scan(ip, ports)  # Perform a scan on the specified IP and ports
    host_infos = []  # List to store information about open ports and services

    # Iterate through all protocols detected on the host (e.g., TCP, UDP)
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()  # Get all open ports for the protocol
        for port in lport:
            # Collect information about the open port and its associated service
            host_info = {
                'ip': ip,  # The target IP address
                'os': nm[ip].get('osclass', {}).get('osfamily', 'Unknown'),  # OS family, if detected
                'port': port,  # The open port number
                'name': nm[ip][proto][port]['name'],  # The name of the service
                'product': nm[ip][proto][port]['product'],  # The product associated with the service
                'version': nm[ip][proto][port]['version'],  # The version of the product
            }
            host_infos.append(host_info)  # Add the port's details to the list

    return host_infos  # Return the list of host information

# Function to write scan results to a CSV file
def output_to_csv(output_file, host_info):
    """
    Writes a single host's scan results to a CSV file.

    Parameters:
    - output_file (str): The path to the output CSV file.
    - host_info (dict): A dictionary containing scan results for a single host.
    """
    fieldnames = ["ip", "os", "port", "name", "product", "version"]  # Define the CSV column headers
    file_exists = os.path.isfile(output_file)  # Check if the file already exists

    with open(output_file, "a") as f:  # Open the file in append mode
        writer = csv.DictWriter(f, fieldnames=fieldnames)  # Create a CSV writer object
        if not file_exists:  # If the file doesn't exist, write the header first
            writer.writeheader()
        writer.writerow(host_info)  # Write the host's information as a row in the CSV

# Main function to parse arguments, perform the scan, and save results
def main():
    """
    Parses command-line arguments, scans the specified host and ports, and outputs the results.
    """
    # Set up the argument parser for command-line input
    parser = argparse.ArgumentParser(description="Scan a single host for open ports and services")
    parser.add_argument("host", help="The target host IP address")  # Positional argument for the IP address
    parser.add_argument("-p", "--ports", help="Ports to scan", type=str, required=True)  # Required ports argument
    parser.add_argument("-o", "--output", help="The output file", default="scan_results.csv")  # Optional output file argument

    args = parser.parse_args()  # Parse the arguments

    # Extract the parsed arguments
    ip = args.host  # Target IP address
    ports = args.ports  # Ports to scan
    output_file = args.output  # Output file for the results

    # Notify the user about the scanning process
    print(f"Scanning IP: {ip}")
    print(f"Scanning ports: {ports}")

    sys.stdout.write("Scanning ")  # Display scanning status dynamically
    sys.stdout.flush()

    # Perform the scan and retrieve results
    host_infos = scan_host(ip, ports)
    
    # Write the scan results to the output file
    for host_info in host_infos:
        output_to_csv(output_file, host_info)

    # Print the scan results to the console
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
