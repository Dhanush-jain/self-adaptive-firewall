def calculate_risk(ai_result, attack_result):
    """
    Combine AI anomaly detection and attack analysis
    into a safer overall risk assessment.
    """

    ai_status = ai_result["status"]
    attack_risk = attack_result["risk_score"]
    attack_type = attack_result["attack_type"]

    # ==========================================
    # CASE 1 - NORMAL TRAFFIC
    # ==========================================

    if ai_status == "NORMAL" and attack_risk == 0:

        risk_score = 0
        severity = "LOW"


    # ==========================================
    # CASE 2 - AI ANOMALY ONLY
    # ==========================================

    elif (
        ai_status == "ANOMALY"
        and attack_risk == 0
    ):

        # Unusual traffic, but no known
        # attack behavior detected.
        risk_score = 40
        severity = "MEDIUM"


    # ==========================================
    # CASE 3 - ATTACK PATTERN DETECTED
    # ==========================================

    elif attack_risk > 0:

        risk_score = attack_risk

        # If AI also agrees, increase confidence.
        if ai_status == "ANOMALY":

            risk_score += 10

        risk_score = min(risk_score, 100)

        # --------------------------------------
        # Severity
        # --------------------------------------

        if risk_score >= 80:

            severity = "CRITICAL"

        elif risk_score >= 60:

            severity = "HIGH"

        elif risk_score >= 30:

            severity = "MEDIUM"

        else:

            severity = "LOW"


    # ==========================================
    # FALLBACK
    # ==========================================

    else:

        risk_score = 0
        severity = "LOW"


    return {
        "risk_score": risk_score,
        "severity": severity
    }
