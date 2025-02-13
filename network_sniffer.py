import scapy.all as scapy
import re
from collections import Counter

# Define a list of known suspicious IP ranges (e.g., IPs known for attacks, non-local IPs, etc.)
SUSPICIOUS_IPS = ['192.168.1.100', '10.0.0.1']  # Add suspicious IPs

# Define common anomalous ports
ANOMALOUS_PORTS = [445, 139, 23]  # For example, SMB and Telnet ports (often used for exploits)

# Function to analyze packets
def analyze_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst

        # Check for suspicious IP addresses
        if ip_src in SUSPICIOUS_IPS or ip_dst in SUSPICIOUS_IPS:
            print(f"Suspicious activity detected from IP: {ip_src} -> {ip_dst}")

        # Check for anomalous ports
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            if src_port in ANOMALOUS_PORTS or dst_port in ANOMALOUS_PORTS:
                print(f"Anomalous port usage detected: {src_port} -> {dst_port}")

        # Check for common attacks (e.g., SYN flooding)
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
            print(f"SYN packet detected from {ip_src} -> {ip_dst} (Potential SYN Flood Attack)")

# Function to capture packets and start sniffing
def start_sniffing(interface=None, packet_count=100):
    print("Starting the network sniffer...")
    scapy.sniff(iface=interface, prn=analyze_packet, count=packet_count)

# Main execution point
if __name__ == "__main__":
    # Set the network interface to sniff on (replace 'eth0' with the appropriate interface for your system)
    network_interface = "eth0"  # Default Ethernet interface, change for your system (use "wlan0" for Wi-Fi)
    
    # Start sniffing on the network interface for the first 100 packets
    start_sniffing(interface=network_interface, packet_count=100)
