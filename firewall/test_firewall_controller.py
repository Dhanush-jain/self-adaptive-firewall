from firewall.firewall_controller import execute_action


# ==========================================
# NORMAL
# ==========================================

normal_result = {
    "action": "ALLOW",
    "risk_score": 0,
    "severity": "LOW",
    "attack_type": "Unknown"
}

print("\nTEST 1 - NORMAL")

execute_action(normal_result)


# ==========================================
# MEDIUM
# ==========================================

medium_result = {
    "action": "MONITOR",
    "risk_score": 40,
    "severity": "MEDIUM",
    "attack_type": "Suspicious Traffic"
}

print("\nTEST 2 - MEDIUM")

execute_action(medium_result)


# ==========================================
# HIGH
# ==========================================

high_result = {
    "action": "BLOCK",
    "risk_score": 70,
    "severity": "HIGH",
    "attack_type": "Traffic Anomaly"
}

print("\nTEST 3 - HIGH")

execute_action(high_result)


# ==========================================
# CRITICAL
# ==========================================

critical_result = {
    "action": "BLOCK_AND_ALERT",
    "risk_score": 100,
    "severity": "CRITICAL",
    "attack_type": "Possible Port Scan"
}

print("\nTEST 4 - CRITICAL")

execute_action(critical_result)
