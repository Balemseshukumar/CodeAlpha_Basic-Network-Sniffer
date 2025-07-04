# Import necessary modules from Scapy
from scapy.all import IP, ICMP, sr1, conf

def send_and_receive_ping(target_ip="8.8.8.8"):
    """
    Crafts and sends an ICMP (ping) request to a target IP address,
    then waits for and analyzes the response.

    Args:
        target_ip (str): The IP address to ping. Defaults to Google's DNS (8.8.8.8).
    """
    print(f"Attempting to ping {target_ip}...")
    print("-----------------------------------")

    # 1. Craft the ICMP (ping) packet
    # IP() creates an IP layer with the destination IP.
    # ICMP() creates an ICMP echo request (type 8, code 0 by default).
    ping_packet = IP(dst=target_ip)/ICMP()

    # Display the crafted packet before sending
    print("Crafted Packet Summary:")
    ping_packet.summary()
    # ping_packet.show() # Uncomment to see full packet details

    # 2. Send the packet and wait for a single response
    # sr1() sends the packet and returns the first response received.
    # timeout: How long to wait for a response (in seconds).
    # verbose: Set to 0 to suppress Scapy's default output during sending/receiving.
    response_packet = sr1(ping_packet, timeout=2, verbose=0)

    # 3. Analyze the response
    if response_packet:
        print("\n--- Response Received ---")
        response_packet.summary() # Show a summary of the response

        # Check if the response is an ICMP Echo Reply (type 0)
        if response_packet.haslayer(ICMP) and response_packet[ICMP].type == 0:
            print(f"  Received ICMP Echo Reply from: {response_packet[IP].src}")
            print(f"  Round Trip Time (RTT) is not directly calculated by sr1,")
            print(f"  but the successful reply indicates connectivity.")
        else:
            print(f"  Received a non-ICMP Echo Reply packet.")
            print(f"  Protocol: {response_packet.proto}")
            print(f"  Source: {response_packet.src}")
            print(f"  Destination: {response_packet.dst}")
    else:
        print("\n--- No Response Received ---")
        print(f"  Could not reach {target_ip} or no reply within the timeout period.")
        print("  Possible reasons: target is down, firewall blocking ICMP, or network issues.")

if __name__ == "__main__":
    # IMPORTANT: You must run this script as an Administrator for it to work.
    # Otherwise, you will get a PermissionError.

    # You can change the target IP address here
    send_and_receive_ping(target_ip="8.8.8.8") # Google DNS
    # send_and_receive_ping(target_ip="192.168.1.1") # Your router (common default)
    # send_and_receive_ping(target_ip="www.example.com") # You can use a hostname too
