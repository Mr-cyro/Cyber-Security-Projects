import sys
import argparse  # For parsing command-line arguments
import socket  # For creating and managing network connections

# Function to retrieve the service banner from a specified IP and port
def get_service_banner(ip, port):
    """
    Connects to a given IP and port using a TCP socket and retrieves the service banner.

    Parameters:
    - ip (str): The IP address of the target host.
    - port (int): The port number on the target host.

    Returns:
    - str: The service banner as a decoded string, or None if no banner is found or an error occurs.
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Set a timeout for the connection attempt

        # Connect to the target IP and port
        sock.connect((ip, int(port)))

        # Send a basic HTTP GET request to elicit a banner
        sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")

        # Receive the banner from the target
        banner = sock.recv(1024)  # Read up to 1024 bytes of the response
        sock.close()  # Close the socket connection

        # Decode the banner and return it as a string
        return banner.decode('utf-8', errors='ignore')  # Ignore decoding errors
    except Exception:
        return None  # Return None if any error occurs (e.g., timeout, connection error)

# Main function to handle command-line arguments and perform the scanning
def main():
    """
    Parses command-line arguments, scans the specified IP and ports, 
    and retrieves and displays service banners for each port.
    """
    # Set up the argument parser for command-line input
    parser = argparse.ArgumentParser(description='Service Banner Scanner')
    parser.add_argument('ip', help='IP address to scan')  # Positional argument for the target IP
    parser.add_argument('-p', '--ports', required=True, help='Ports to scan (comma-separated)')  # Required ports argument

    args = parser.parse_args()  # Parse the command-line arguments

    # Extract the IP address and list of ports from the arguments
    ip = args.ip
    ports = [port.strip() for port in args.ports.split(',')]  # Split and clean the ports input

    print(f"Scanning IP: {ip}")  # Notify the user about the target IP
    for port in ports:
        print(f"Scanning port {port} on IP {ip}")  # Notify the user about the port being scanned

        # Retrieve the service banner for the current port
        banner = get_service_banner(ip, port)
        if banner:
            # Display the service banner if found
            print(f"Service banner for port {port} on IP {ip}:\n{banner}\n")
        else:
            # Notify the user if no banner was found or an error occurred
            print(f"No service banner found for port {port} on IP {ip}\n")

# Entry point of the script
if __name__ == "__main__":
    """
    Executes the main function when the script is run directly.
    """
    main()
