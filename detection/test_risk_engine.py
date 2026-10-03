from detection.risk_engine import calculate_risk


# ==========================================
# TEST 1 - NORMAL
# ==========================================

ai_result = {
    "status": "NORMAL",
    "anomaly_score": 0.20
}

attack_result = {
    "attack_type": "Unknown",
    "risk_score": 0,
    "reasons": []
}

print("\nTEST 1 - NORMAL")

print(
    calculate_risk(
        ai_result,
        attack_result
    )
)


# ==========================================
# TEST 2 - AI ANOMALY ONLY
# ==========================================

ai_result = {
    "status": "ANOMALY",
    "anomaly_score": -0.02
}

attack_result = {
    "attack_type": "Unknown",
    "risk_score": 0,
    "reasons": []
}

print("\nTEST 2 - AI ANOMALY ONLY")

print(
    calculate_risk(
        ai_result,
        attack_result
    )
)


# ==========================================
# TEST 3 - ATTACK ANALYZER
# ==========================================

ai_result = {
    "status": "NORMAL",
    "anomaly_score": 0.05
}

attack_result = {
    "attack_type": "Possible Port Scan",
    "risk_score": 65,
    "reasons": [
        "Many destination ports",
        "High TCP SYN activity"
    ]
}

print("\nTEST 3 - ATTACK DETECTED")

print(
    calculate_risk(
        ai_result,
        attack_result
    )
)


# ==========================================
# TEST 4 - BOTH SYSTEMS
# ==========================================

ai_result = {
    "status": "ANOMALY",
    "anomaly_score": -0.10
}

attack_result = {
    "attack_type": "Possible Port Scan",
    "risk_score": 90,
    "reasons": [
        "Many destination ports",
        "High TCP SYN activity",
        "High packet rate"
    ]
}

print("\nTEST 4 - AI + ATTACK ANALYZER")

print(
    calculate_risk(
        ai_result,
        attack_result
    )
)
