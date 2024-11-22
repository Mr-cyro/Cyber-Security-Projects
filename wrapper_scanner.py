#to run script -  python scanner_05.py 192.168.1.0 24

import sys  # For command-line arguments and script execution handling
import scanner_02  # Custom module containing ping sweep and port scan functions
import scanner_04  # Custom module for detailed host scanning and CSV output

# Main function to orchestrate the scanning workflow
def main():
    """
    Orchestrates the process of performing a ping sweep, scanning open ports on live hosts,
    and retrieving detailed service information for those ports.
    """
    # Ensure the correct number of command-line arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python scanner_05.py <subnet> <mask>")  # Display usage information
        sys.exit(1)  # Exit the program with an error code

    # Extract subnet and mask from command-line arguments
    subnet = sys.argv[1]  # Subnet address (e.g., "192.168.1.0")
    mask = int(sys.argv[2])  # Subnet mask (e.g., 24)

    # Perform a ping sweep to identify live hosts
    live_hosts = scanner_02.ping_sweep(subnet, str(mask))
    print("Ping sweep completed.\n")

    # Iterate through each live host found during the ping sweep
    for host in live_hosts:
        # Perform a port scan on the host for ports 1-1023
        open_ports = scanner_02.port_scan(host, list(range(1, 1024)))
        print(f"Open ports on host {host}: {open_ports}\n")

        # Iterate through each open port on the host
        for port in open_ports:
            # Use scanner_04 to get detailed information about the service on the port
            host_infos = scanner_04.scan_host(host, str(port))
            for host_info in host_infos:
                # Save the scan results to a CSV file
                scanner_04.output_to_csv("scan_results.csv", host_info)

                # Print the detailed scan results for the host and port
                print("\nScan results:")
                for k, v in host_info.items():
                    print(f"{k}: {v}")  # Print each key-value pair of the scan result
                print()  # Add a blank line for readability

# Entry point of the script
if __name__ == "__main__":
    """
    Executes the main function when the script is run directly.
    """
    main()
