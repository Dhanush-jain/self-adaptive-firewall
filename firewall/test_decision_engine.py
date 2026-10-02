from firewall.decision_engine import make_firewall_decision


# ==========================================
# TEST 1 - NORMAL TRAFFIC
# ==========================================

risk_result = {
    "risk_score": 0,
    "severity": "LOW"
}

attack_result = {
    "attack_type": "Unknown",
    "risk_score": 0,
    "reasons": []
}

result = make_firewall_decision(
    risk_result,
    attack_result
)

print("\nTEST 1 - NORMAL TRAFFIC")
print(result)


# ==========================================
# TEST 2 - MEDIUM RISK
# ==========================================

risk_result = {
    "risk_score": 40,
    "severity": "MEDIUM"
}

attack_result = {
    "attack_type": "Suspicious Traffic",
    "risk_score": 40,
    "reasons": [
        "Unusual traffic pattern"
    ]
}

result = make_firewall_decision(
    risk_result,
    attack_result
)

print("\nTEST 2 - MEDIUM RISK")
print(result)


# ==========================================
# TEST 3 - HIGH RISK
# ==========================================

risk_result = {
    "risk_score": 70,
    "severity": "HIGH"
}

attack_result = {
    "attack_type": "Traffic Anomaly",
    "risk_score": 0,
    "reasons": []
}

result = make_firewall_decision(
    risk_result,
    attack_result
)

print("\nTEST 3 - HIGH RISK")
print(result)


# ==========================================
# TEST 4 - CRITICAL PORT SCAN
# ==========================================

risk_result = {
    "risk_score": 90,
    "severity": "CRITICAL"
}

attack_result = {
    "attack_type": "Possible Port Scan",
    "risk_score": 90,
    "reasons": [
        "Many destination ports",
        "High TCP SYN activity"
    ]
}

result = make_firewall_decision(
    risk_result,
    attack_result
)

print("\nTEST 4 - CRITICAL PORT SCAN")
print(result)
