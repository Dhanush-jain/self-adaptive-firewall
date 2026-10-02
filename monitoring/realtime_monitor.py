from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import Counter
import time
import csv
import os


INTERFACE = "enp0s3"
WINDOW_SECONDS = 5

LOG_FILE = "logs/behavior_live.csv"


def analyze_window(packets, start_time, end_time):

    packet_count = len(packets)

    total_bytes = sum(
        len(packet)
        for packet in packets
    )

    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    source_ips = set()
    destination_ips = set()
    destination_ports = set()

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        ip_layer = packet[IP]

        source_ips.add(ip_layer.src)
        destination_ips.add(ip_layer.dst)

        if packet.haslayer(TCP):

            tcp_count += 1
            destination_ports.add(
                packet[TCP].dport
            )

        elif packet.haslayer(UDP):

            udp_count += 1
            destination_ports.add(
                packet[UDP].dport
            )

        elif ip_layer.proto == 1:

            icmp_count += 1

    packets_per_second = (
        packet_count / WINDOW_SECONDS
    )

    bytes_per_second = (
        total_bytes / WINDOW_SECONDS
    )

    return {

        "time_window":
            start_time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "packet_count":
            packet_count,

        "total_bytes":
            total_bytes,

        "packets_per_second":
            packets_per_second,

        "bytes_per_second":
            bytes_per_second,

        "tcp_count":
            tcp_count,

        "udp_count":
            udp_count,

        "icmp_count":
            icmp_count,

        "unique_source_ips":
            len(source_ips),

        "unique_destination_ips":
            len(destination_ips),

        "unique_destination_ports":
            len(destination_ports)
    }


def save_features(features):

    os.makedirs("logs", exist_ok=True)

    file_exists = os.path.exists(LOG_FILE)

    with open(
        LOG_FILE,
        "a",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=features.keys()
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(features)


def capture_window():

    print(
        f"\nCapturing traffic for "
        f"{WINDOW_SECONDS} seconds..."
    )

    packets = sniff(
        iface=INTERFACE,
        timeout=WINDOW_SECONDS,
        store=True
    )

    return packets


print("======================================")
print("     AI FIREWALL REAL-TIME MONITOR")
print("======================================")

print(f"Interface : {INTERFACE}")
print(f"Window    : {WINDOW_SECONDS} seconds")

print("\nMonitoring started...\n")


while True:

    start_time = datetime.now()

    packets = capture_window()

    end_time = datetime.now()

    features = analyze_window(
        packets,
        start_time,
        end_time
    )

    save_features(features)

    print("--------------------------------------")

    for key, value in features.items():

        print(
            f"{key}: {value}"
        )
