CodeAlpha_Basic-Network-Sniffer
This repository contains Python programs designed for basic network traffic analysis and interaction using the powerful Scapy library. These tools help in understanding network protocols, data flow, and packet structures.

🚀 Features
network_sniffer.py: A simple network packet sniffer that captures live traffic on a specified interface, dissects packets, and displays key information like source/destination IPs, MACs, protocols (TCP, UDP, ICMP), and raw payloads.

scapy_ping.py: A tool to craft and send custom ICMP (ping) request packets to a target IP address and analyze the received reply, demonstrating active network interaction.

📋 Prerequisites
Before running these scripts, ensure you have the following installed on your Windows machine:

Python 3.x:

Download from python.org.

Crucially, during installation, check the box "Add Python to PATH".

Verify installation by opening Command Prompt and typing python --version.

Npcap: (Recommended for Windows)

Scapy relies on a packet capture driver. Npcap is the modern successor to WinPcap.

Download the latest stable version from nmap.org/npcap/.

During installation, ensure "Install Npcap in WinPcap API-compatible Mode" is checked. This is vital for Scapy's functionality.

Scapy:

Once Python and Npcap are installed, open your Command Prompt as an Administrator.

Run the following command:

pip install scapy

Verify installation by opening Python interpreter (python in CMD) and typing from scapy.all import *. You should see the Scapy banner.

Screenshot: Scapy Installation Verification
(Replace scapy_install_verify.png with your actual screenshot file name if you have one)

📦 Installation & Setup
Clone the Repository (or Download):

git clone https://github.com/Balemseshukumar/CodeAlpha_Basic-Network-Sniffer.git
cd CodeAlpha_Basic-Network-Sniffer

(This command now uses your specific GitHub username)

Ensure Dependencies are Met: Follow the "Prerequisites" section above to install Python, Npcap, and Scapy.

💻 Usage
IMPORTANT: Both scripts require Administrator privileges to run, as they interact with raw network sockets. Always open your Command Prompt or PowerShell "Run as administrator".

1. network_sniffer.py (Packet Sniffer)
This script captures and displays details of network packets.

Identify Your Network Interface:

Open Command Prompt (as Administrator).

Start Python: python

In the Python interpreter, type: from scapy.all import * then conf.ifaces

Note the exact Name of your primary network adapter (e.g., "Realtek RTL8821CE 802.11ac PCIe Adapter").

Screenshot: conf.ifaces Output
(Replace conf_ifaces_output.png with your actual screenshot file name if you have one)

Update the Script:

Open network_sniffer.py in a text editor.

Modify the NETWORK_INTERFACE variable to match the name you found:

NETWORK_INTERFACE = "Your_Exact_Network_Interface_Name_Here"

Run the Sniffer:

Open Command Prompt as Administrator.

Navigate to the directory where you saved the script.

Run:

python network_sniffer.py

By default, it captures 10 packets. You can change count=10 to count=0 in the start_sniffer function call within the script to sniff indefinitely (press Ctrl+C to stop).

Screenshot: network_sniffer.py Output
(Replace sniffer_output.png with your actual screenshot file name if you have one)

2. scapy_ping.py (Ping Example)
This script crafts and sends an ICMP ping packet.

Run the Ping Script:

Open Command Prompt as Administrator.

Navigate to the directory where you saved the script.

Run:

python scapy_ping.py

By default, it pings 8.8.8.8. You can modify the target_ip variable in the send_and_receive_ping function call within the script to ping a different IP address or hostname.

Screenshot: scapy_ping.py Output
(Replace ping_output.png with your actual screenshot file name if you have one)

📊 Understanding the Output (Packet Execution)
network_sniffer.py: You will see detailed information for each captured packet, including MAC addresses (Ethernet layer), IP addresses (IPv4/IPv6 layer), port numbers (TCP/UDP layer), and attempts to display raw data payloads. This helps you visualize the structure of data as it travels across your network.

scapy_ping.py: You will see a summary of the crafted ICMP request and, if successful, a summary of the ICMP echo reply from the target. This demonstrates a basic request-response cycle of a network protocol.

⚠️ Troubleshooting
PermissionError: [Errno 1] Operation not permitted: This is the most common error. It means you are not running the script with Administrator privileges. Close your command prompt and reopen it by right-clicking and selecting "Run as administrator."

No such device or Interface not found: Double-check that the NETWORK_INTERFACE name in network_sniffer.py exactly matches one of the names from conf.ifaces output.

No packets captured / No response received:

Ensure Npcap is installed correctly with "WinPcap API-compatible Mode" enabled.

Check your firewall settings to ensure they are not blocking Scapy's access or the specific traffic you are trying to capture/send.

Ensure there is actual network activity on the selected interface for the sniffer to capture.

For scapy_ping.py, verify the target IP is reachable and not blocking ICMP.

🤝 Contributing
Feel free to fork this repository, make improvements, or add new examples of Scapy usage. Pull requests are welcome!

📄 License
This project is open-source and available under the MIT License.
