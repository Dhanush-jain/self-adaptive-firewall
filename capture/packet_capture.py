from scapy.all import sniff, IP


def process_packet(packet):

    if packet.haslayer(IP):

        source = packet[IP].src
        destination = packet[IP].dst
        protocol = packet[IP].proto
        size = len(packet)

        print(
            f"Source: {source} | "
            f"Destination: {destination} | "
            f"Protocol: {protocol} | "
            f"Size: {size}"
        )


print("AI Firewall Packet Monitor Started...")
print("Capturing packets...\n")

sniff(
    prn=process_packet,
    store=False
)
