[network_sniffer.py](https://github.com/user-attachments/files/26322255/network_sniffer.py)
from scapy.all import sniff, IP, Raw

def analyze_packet(packet):
    print("\n--- Packet Captured ---")

    if packet.haslayer(IP):
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

    print("Protocol:", packet.summary())

    if packet.haslayer(Raw):
        print("Payload:", packet[Raw].load)

print("Sniffing started...")
sniff(prn=analyze_packet, count=10)
