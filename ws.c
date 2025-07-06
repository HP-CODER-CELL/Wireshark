from scapy.all import sniff, IP, TCP, DNS, DNSQR

# Define a packet callback function
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[IP] {ip_layer.src} -> {ip_layer.dst}")
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"  [TCP] Port {tcp_layer.sport} -> {tcp_layer.dport}")

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_layer = packet[DNS]
            print(f"  [DNS] Query: {dns_layer.qd.qname.decode()}")

# Sniff packets (press Ctrl+C to stop)
print("Sniffing packets...")
sniff(prn=packet_callback, filter="ip", count=10)
