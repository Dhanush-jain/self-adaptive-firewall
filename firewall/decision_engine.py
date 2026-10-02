def make_firewall_decision(risk_result, attack_result):
    """
    Convert the Risk Engine result into a firewall action.
    """

    risk_score = risk_result["risk_score"]
    severity = risk_result["severity"]

    attack_type = attack_result["attack_type"]

    # -----------------------------
    # LOW RISK
    # -----------------------------
    if risk_score < 30:
        action = "ALLOW"

    # -----------------------------
    # MEDIUM RISK
    # -----------------------------
    elif risk_score < 60:
        action = "MONITOR"

    # -----------------------------
    # HIGH RISK
    # -----------------------------
    elif risk_score < 80:
        action = "BLOCK"

    # -----------------------------
    # CRITICAL RISK
    # -----------------------------
    else:
        action = "BLOCK_AND_ALERT"

    return {
        "action": action,
        "risk_score": risk_score,
        "severity": severity,
        "attack_type": attack_type
    }
