# Wireshark

🧠 Purpose: Captures and analyzes 10 IP packets from the network interface using Scapy.

📦 Library used: scapy is a powerful packet manipulation and sniffing library in Python.

🧲 Sniffing packets: sniff() listens for network traffic.

prn=packet_callback: Runs packet_callback for each captured packet.

filter="ip": Captures only IP packets (can be customized).

count=10: Stops after capturing 10 packets.

🔍 Packet callback function:

Checks if packet has an IP layer and prints source and destination IPs.

If it has a TCP layer, prints source and destination ports.

If it has both DNS and DNS Query (DNSQR) layers, it prints the queried domain name.

📡 Use case: Useful for simple network monitoring, debugging, or educational purposes.

🛑 Stopping: Automatically stops after capturing 10 packets, or can be stopped manually with Ctrl + C if count is removed.
