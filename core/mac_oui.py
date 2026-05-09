import requests
import time

def get_mac_vendor(mac_address):
    """
    Looks up the manufacturer of a device using its MAC address.
    """
    try:
        # We use a free API to check the MAC address signature
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=3)
        
        # The free API requires us to wait 1 second between requests
        # to avoid getting temporarily banned (rate-limited).
        time.sleep(1) 
        
        if response.status_code == 200:
            return response.text.strip()
        else:
            # Modern phones randomize their MAC addresses for privacy, 
            # which usually results in an unknown vendor.
            return "Unknown / Randomized MAC"
            
    except requests.exceptions.RequestException:
        return "Lookup Failed (Check Internet)"