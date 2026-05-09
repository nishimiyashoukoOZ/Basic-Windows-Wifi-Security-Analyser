import sys
from colorama import init, Fore, Style
from core.arp_scanner import get_local_subnet, scan_network
from core.mac_oui import get_mac_vendor
from core.port_scanner import scan_ports

# Initialize colorama for Windows terminal colors
init(autoreset=True)

def print_header():
    print(Fore.CYAN + Style.BRIGHT + "="*65)
    print(Fore.CYAN + Style.BRIGHT + "       Wi-Fi Security Analyzer: Device Mapper v2.0")
    print(Fore.CYAN + Style.BRIGHT + "="*65 + "\n")

def main():
    print_header()
    
    print(Fore.YELLOW + "[*] Detecting local network configuration...")
    local_ip, subnet = get_local_subnet()
    
    if not local_ip:
        print(Fore.RED + "[!] Could not detect local IP. Ensure you are connected to a network.")
        sys.exit(1)
        
    print(Fore.GREEN + f"[+] Local IP: {local_ip}")
    print(Fore.GREEN + f"[+] Target Subnet: {subnet}\n")
    
    print(Fore.YELLOW + f"[*] Broadcasting ARP requests to {subnet}...")
    print(Fore.YELLOW + "[*] Please wait, mapping devices...\n")
    
    devices = scan_network(subnet)
    
    if not devices:
        print(Fore.RED + "[!] No devices found. Check your Npcap installation and network connection.")
        return

    print(Fore.CYAN + Style.BRIGHT + "Live Devices Found:")
    print("-" * 75)
    print(f"{'IP Address':<18} {'MAC Address':<20} {'Manufacturer / Device Type'}")
    print("-" * 75)
    
    for device in devices:
        # 1. Print the IP and MAC without starting a new line yet
        print(f"{device['ip']:<18} {device['mac']:<20} ", end="")
        sys.stdout.flush() 
        
        # 2. Look up the vendor
        vendor = get_mac_vendor(device['mac'])
        
        # 3. Print the vendor on the same line
        if device['ip'] == local_ip:
            print(Fore.GREEN + f"{vendor} (This Machine)")
        else:
            print(Fore.LIGHTBLACK_EX + vendor)
            
        # 4. === NEW PORT SCANNER INTEGRATION ===
        # Scan this specific device for open vulnerable ports
        open_ports = scan_ports(device['ip'])
        
        # If the scanner found any open ports, print them indented underneath
        if open_ports:
            print(Fore.RED + "    [!] Vulnerabilities Found:")
            for port, service, risk in open_ports:
                print(Fore.RED + f"        -> Port {port} ({service}): {risk}")
            print() # Add a blank line for readability
            
    print("-" * 75)
    print(Fore.CYAN + f"Total devices discovered: {len(devices)}")

if __name__ == "__main__":
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print(Fore.RED + Style.BRIGHT + "[!] ERROR: This script must be run as an Administrator.")
        sys.exit(1)
        
    main()