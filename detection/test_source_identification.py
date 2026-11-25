from scapy.all import IP, TCP

from detection.live_detector import analyze_packets
from detection.live_detector import identify_suspicious_sources


# Simulate traffic from one source IP
packets = []

attacker_ip = "10.10.10.2"

for port in range(1, 31):

    packet = (
        IP(
            src=attacker_ip,
            dst="10.10.10.1"
        )
        /
        TCP(
            sport=50000 + port,
            dport=port,
            flags="S"
        )
    )

    packets.append(packet)


# Extract features
features = analyze_packets(packets)

# Identify suspicious sources
results = identify_suspicious_sources(features)


print("\nSOURCE IDENTIFICATION TEST")

print("Observed sources:", features["source_ips"])

print("\nSuspicious sources:")

for source in results:

    print(source)
