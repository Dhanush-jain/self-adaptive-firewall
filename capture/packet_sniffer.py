from scapy.all import sniff

from capture.packet_parser import parse_packet
from capture.traffic_logger import save_packet


def process_packet(packet):

    data = parse_packet(packet)

    if data:

        print(data)

        save_packet(data)


print("================================")
print(" AI FIREWALL TRAFFIC MONITOR")
print("================================")
print("Capturing and logging packets...\n")


sniff(
    iface="enp0s3",
    prn=process_packet,
    store=False
)
