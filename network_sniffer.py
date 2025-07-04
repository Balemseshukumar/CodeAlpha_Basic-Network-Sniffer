# Import necessary modules from Scapy
from scapy.all import sniff, IP, TCP, UDP, Raw, Ether, IPv6

# Define the network interface to sniff on.
# IMPORTANT: Replace "Realtek RTL8821CE 802.11ac PCIe Adapter" with the exact
# name of your primary network interface if it's different.
# You found this name by running conf.ifaces previously.
NETWORK_INTERFACE = "Realtek RTL8821CE 802.11ac PCIe Adapter"

def analyze_packet(packet):
    """
    Analyzes a captured packet and prints relevant information.

    Args:
        packet: A Scapy packet object.
    """
    print("\n--- New Packet ---")

    # Display Ethernet Layer information if present
    if packet.haslayer(Ether):
        print(f"Ethernet Layer:")
        print(f"  Source MAC: {packet[Ether].src}")
        print(f"  Destination MAC: {packet[Ether].dst}")
        print(f"  Type: {packet[Ether].type}") # 0x800 for IPv4, 0x86DD for IPv6

    # Display IP Layer information (IPv4 or IPv6)
    if packet.haslayer(IP):
        print(f"IP Layer (IPv4):")
        print(f"  Source IP: {packet[IP].src}")
        print(f"  Destination IP: {packet[IP].dst}")
        print(f"  Protocol: {packet[IP].proto} ({packet[IP].sprintf('%IP.proto%')})")
    elif packet.haslayer(IPv6):
        print(f"IP Layer (IPv6):")
        print(f"  Source IP: {packet[IPv6].src}")
        print(f"  Destination IP: {packet[IPv6].dst}")
        print(f"  Next Header (Protocol): {packet[IPv6].nh} ({packet[IPv6].sprintf('%IPv6.nh%')})")

    # Display TCP Layer information
    if packet.haslayer(TCP):
        print(f"TCP Layer:")
        print(f"  Source Port: {packet[TCP].sport}")
        print(f"  Destination Port: {packet[TCP].dport}")
        print(f"  Flags: {packet[TCP].flags}")
        # Check for payload in TCP
        if packet[TCP].payload:
            print(f"  Payload (TCP): {bytes(packet[TCP].payload)}")

    # Display UDP Layer information
    elif packet.haslayer(UDP): # Using elif because a packet is either TCP or UDP, not both
        print(f"UDP Layer:")
        print(f"  Source Port: {packet[UDP].sport}")
        print(f"  Destination Port: {packet[UDP].dport}")
        # Check for payload in UDP
        if packet[UDP].payload:
            print(f"  Payload (UDP): {bytes(packet[UDP].payload)}")

    # Display Raw Payload if present and not dissected by higher layers
    if packet.haslayer(Raw):
        print(f"Raw Payload:")
        # Decode payload if it's likely text, otherwise print as bytes
        try:
            decoded_payload = packet[Raw].load.decode('utf-8', errors='ignore')
            print(f"  {decoded_payload}")
        except UnicodeDecodeError:
            print(f"  {packet[Raw].load}") # Print as bytes if decoding fails
    
    # You can uncomment the line below to see the full packet summary for every packet
    # print(packet.summary())
    # You can uncomment the line below to see the full packet dissection for every packet
    # packet.show()

def start_sniffer(count=10):
    """
    Starts the network sniffer to capture a specified number of packets.

    Args:
        count (int): The number of packets to capture. Set to 0 for infinite capture.
    """
    print(f"Starting network sniffer on interface: '{NETWORK_INTERFACE}'")
    print(f"Capturing {count} packets (or press Ctrl+C to stop if count is 0)...")
    print("---------------------------------------------------------")

    try:
        # The sniff function captures packets.
        # prn=analyze_packet calls our analyze_packet function for each captured packet.
        # iface specifies the network interface.
        # count specifies how many packets to capture (0 for infinite).
        sniff(prn=analyze_packet, iface=NETWORK_INTERFACE, count=count)
        print("\nSniffing finished.")
    except PermissionError:
        print("\nERROR: Permission denied. You must run this script as an Administrator.")
        print("Please close this command prompt, open a new one by right-clicking")
        print("and selecting 'Run as administrator', then try again.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        print("Please ensure Npcap (or WinPcap) is installed correctly and")
        print("that the interface name is accurate.")

if __name__ == "__main__":
    # You can change the 'count' parameter to sniff more or fewer packets.
    # Set count=0 for infinite sniffing (until Ctrl+C is pressed).
    start_sniffer(count=10)
