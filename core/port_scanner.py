import socket
from colorama import Fore

# A dictionary of common ports and their associated risk
COMMON_PORTS = {
    21: ("FTP", "High Risk if anonymous login is enabled"),
    22: ("SSH", "Medium Risk (Ensure strong passwords)"),
    23: ("Telnet", "CRITICAL Risk! Traffic is unencrypted"),
    80: ("HTTP", "Medium Risk (Unencrypted web traffic)"),
    443: ("HTTPS", "Low Risk (Encrypted)"),
    445: ("SMB", "High Risk (Check for eternalblue vulnerability)"),
    3389: ("RDP", "High Risk if exposed to the internet")
}

def scan_ports(ip_address):
    """
    Scans a specific IP for common vulnerable open ports.
    """
    open_ports = []
    
    for port, (service, risk) in COMMON_PORTS.items():
        try:
            # Create a socket and set a very short timeout so the scan is fast
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5) 
            
            # Try to connect to the port
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append((port, service, risk))
            sock.close()
            
        except Exception:
            pass
            
    return open_ports