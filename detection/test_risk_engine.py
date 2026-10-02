from detection.risk_engine import calculate_risk


# --------------------------------
# Test 1: Normal traffic
# --------------------------------

ai_result = {
    "status": "NORMAL",
    "anomaly_score": 0.20
}

attack_result = {
    "attack_type": "Unknown",
    "risk_score": 0,
    "reasons": []
}

result = calculate_risk(ai_result, attack_result)

print("\nTEST 1 - NORMAL TRAFFIC")
print(result)


# --------------------------------
# Test 2: Possible port scan
# --------------------------------

ai_result = {
    "status": "NORMAL",
    "anomaly_score": 0.05
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

result = calculate_risk(ai_result, attack_result)

print("\nTEST 2 - PORT SCAN")
print(result)


# --------------------------------
# Test 3: AI anomaly
# --------------------------------

ai_result = {
    "status": "ANOMALY",
    "anomaly_score": -0.03
}

attack_result = {
    "attack_type": "Unknown",
    "risk_score": 0,
    "reasons": []
}

result = calculate_risk(ai_result, attack_result)

print("\nTEST 3 - AI ANOMALY")
print(result)


# --------------------------------
# Test 4: Both detect something
# --------------------------------

ai_result = {
    "status": "ANOMALY",
    "anomaly_score": -0.10
}

attack_result = {
    "attack_type": "Possible Port Scan",
    "risk_score": 90,
    "reasons": [
        "Many destination ports",
        "High TCP SYN activity"
    ]
}

result = calculate_risk(ai_result, attack_result)

print("\nTEST 4 - BOTH SYSTEMS")
print(result)
