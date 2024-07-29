# Enhancing the Network Sniffer

from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Source Port: {src_port} --> Destination Port: {dst_port}")
            print(f"TCP Data: {str(packet[TCP].payload)}")
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Source Port: {src_port} --> Destination Port: {dst_port}")
            print(f"UDP Data: {str(packet[UDP].payload)}")

# Sniffing network packets
sniff(prn=packet_callback, store=0)
