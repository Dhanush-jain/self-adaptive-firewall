def calculate_risk(ai_result, attack_result):
    """
    Combine Isolation Forest and Attack Analyzer results
    into one overall risk score.
    """

    # --------------------------------
    # 1. AI anomaly component
    # --------------------------------

    if ai_result["status"] == "ANOMALY":
        anomaly_risk = 70
    else:
        anomaly_risk = 0

    # --------------------------------
    # 2. Attack analyzer component
    # --------------------------------

    attack_risk = attack_result["risk_score"]

    # --------------------------------
    # 3. Combine the two signals
    # --------------------------------

    risk_score = max(anomaly_risk, attack_risk)

    # If both systems agree that traffic is suspicious,
    # increase the confidence/risk.
    if ai_result["status"] == "ANOMALY" and attack_risk > 0:
        risk_score += 20

    risk_score = min(risk_score, 100)

    # --------------------------------
    # 4. Determine severity
    # --------------------------------

    if risk_score >= 80:
        severity = "CRITICAL"

    elif risk_score >= 60:
        severity = "HIGH"

    elif risk_score >= 30:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return {
        "risk_score": risk_score,
        "severity": severity
    }
