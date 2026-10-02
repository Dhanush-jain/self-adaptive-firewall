from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime


def parse_packet(packet):

    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    source_ip = ip_layer.src
    destination_ip = ip_layer.dst
    packet_size = len(packet)

    source_port = None
    destination_port = None
    protocol = "OTHER"

    if packet.haslayer(TCP):

        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):

        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ip_layer.proto == 1:

        protocol = "ICMP"

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_size": packet_size
    }
