from scapy.all import ARP, Ether, srp
import socket

def get_local_subnet():
    """
    Automatically detects the machine's local IP address and 
    assumes a standard /24 subnet mask for scanning.
    """
    try:
        # Create a dummy socket to find our active local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Strip the last octet and append .0/24 (e.g., 192.168.1.5 -> 192.168.1.0/24)
        subnet = local_ip.rsplit('.', 1)[0] + '.0/24'
        return local_ip, subnet
    except Exception as e:
        return None, None

def scan_network(ip_range):
    """
    Performs an ARP scan on the specified IP range.
    Returns a list of dictionaries containing IP and MAC addresses.
    """
    # 1. Create an ARP request packet asking for the IP range
    arp_request = ARP(pdst=ip_range)
    
    # 2. Create an Ethernet frame directed to the broadcast MAC address
    broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # 3. Combine the Ethernet frame and ARP request
    packet = broadcast_frame / arp_request
    
    # 4. Send the packet and capture the responses (srp = send/receive at layer 2)
    # timeout=2 dictates how long to wait for a reply. verbose=0 hides Scapy's default output.
    answered_list = srp(packet, timeout=2, verbose=0)[0]
    
    # 5. Parse the responses
    devices = []
    for sent, received in answered_list:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc
        })
        
    return devices