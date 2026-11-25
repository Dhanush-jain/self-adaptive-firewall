from scapy.all import IP, TCP

from detection.source_analyzer import (
    analyze_packets,
    identify_suspicious_sources
)

from detection.attack_analyzer import analyze_attack

from detection.risk_engine import calculate_risk

from firewall.decision_engine import make_firewall_decision

from firewall.firewall_controller import execute_action


# ==========================================
# TEST CONFIGURATION
# ==========================================

ATTACKER_IP = "198.51.100.10"
TARGET_IP = "198.51.100.20"


def run_pipeline(packets, ai_status):

    # 1. Source analysis
    features = analyze_packets(packets)

    suspicious_sources = identify_suspicious_sources(
        features
    )

    # 2. Attack analysis
    attack_result = analyze_attack(features)

    # 3. AI result (controlled test input)
    ai_result = {
        "status": ai_status,
        "anomaly_score": -0.05 if ai_status == "ANOMALY" else 0.20
    }

    # 4. Risk engine
    risk_result = calculate_risk(
        ai_result,
        attack_result
    )

    # 5. Decision engine
    firewall_result = make_firewall_decision(
        risk_result,
        attack_result
    )

    # 6. Select a qualified source
    qualified_sources = [
        source
        for source in suspicious_sources
        if source["risk_score"] >= 65
    ]

    if (
        firewall_result["action"] in (
            "BLOCK",
            "BLOCK_AND_ALERT"
        )
        and qualified_sources
    ):

        firewall_result["source_ip"] = (
            qualified_sources[0]["source_ip"]
        )

    else:

        firewall_result["source_ip"] = None

    # Display results
    print("\nAI RESULT:", ai_result["status"])

    print("ATTACK RESULT:", attack_result)

    print("RISK RESULT:", risk_result)

    print("FIREWALL RESULT:", firewall_result)

    # 7. Controller
    execute_action(firewall_result)

    return firewall_result


# ==========================================
# TEST 1 - NORMAL TRAFFIC
# ==========================================

print("\n========== TEST 1: NORMAL TRAFFIC ==========")

normal_packets = [
    IP(src=ATTACKER_IP, dst=TARGET_IP) /
    TCP(sport=50001, dport=80, flags="A"),

    IP(src=ATTACKER_IP, dst=TARGET_IP) /
    TCP(sport=50001, dport=80, flags="A")
]

result1 = run_pipeline(normal_packets, "NORMAL")

assert result1["action"] == "ALLOW"
assert result1["source_ip"] is None


# ==========================================
# TEST 2 - MEDIUM RISK
# ==========================================

print("\n========== TEST 2: MEDIUM RISK ==========")

medium_packets = [
    IP(src=ATTACKER_IP, dst=TARGET_IP) /
    TCP(sport=50002, dport=80, flags="A")
]

result2 = run_pipeline(medium_packets, "ANOMALY")

assert result2["action"] == "MONITOR"


# ==========================================
# TEST 3 - PORT SCAN
# ==========================================

print("\n========== TEST 3: PORT SCAN ==========")

scan_packets = []

for port in range(1, 31):

    scan_packets.append(
        IP(
            src=ATTACKER_IP,
            dst=TARGET_IP
        ) /
        TCP(
            sport=50000 + port,
            dport=port,
            flags="S"
        )
    )

result3 = run_pipeline(scan_packets, "NORMAL")

assert result3["action"] == "BLOCK"
assert result3["source_ip"] == ATTACKER_IP


# ==========================================
# TEST 4 - CRITICAL TRAFFIC
# ==========================================

print("\n========== TEST 4: CRITICAL TRAFFIC ==========")

result4 = run_pipeline(scan_packets, "ANOMALY")

assert result4["action"] == "BLOCK_AND_ALERT"
assert result4["source_ip"] == ATTACKER_IP


# ==========================================
# FINAL RESULTS
# ==========================================

print("\n==========================================")
print("ALL INTEGRATION TESTS COMPLETED")
print("==========================================")
