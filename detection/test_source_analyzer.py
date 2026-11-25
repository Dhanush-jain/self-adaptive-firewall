from scapy.all import IP, TCP

from detection.source_analyzer import (
    analyze_packets,
    identify_suspicious_sources
)


# ==========================================
# SIMULATED SUSPICIOUS TRAFFIC
# ==========================================

packets = []

attacker_ip = "198.51.100.10"

for port in range(1, 31):

    packet = (
        IP(
            src=attacker_ip,
            dst="198.51.100.20"
        )
        /
        TCP(
            sport=50000 + port,
            dport=port,
            flags="S"
        )
    )

    packets.append(packet)


# ==========================================
# ANALYSIS
# ==========================================

features = analyze_packets(packets)

results = identify_suspicious_sources(features)


# ==========================================
# DISPLAY
# ==========================================

print("\nSOURCE ANALYZER TEST")

print("Observed IPs:", features["source_ips"])

print("\nSuspicious Candidates:")

for result in results:

    print(result)


# ==========================================
# VALIDATION
# ==========================================

assert len(results) == 1

assert results[0]["source_ip"] == attacker_ip

assert results[0]["risk_score"] == 65

print("\nTEST PASSED")
