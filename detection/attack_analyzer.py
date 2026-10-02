def analyze_attack(features):

    reasons = []

    risk = 0


    # --------------------------------
    # High number of destination ports
    # --------------------------------

    if features["unique_destination_ports"] >= 15:

        risk += 40

        reasons.append(
            "Many destination ports"
        )


    # --------------------------------
    # Large number of SYN packets
    # --------------------------------

    if features["tcp_syn_count"] >= 20:

        risk += 25

        reasons.append(
            "High TCP SYN activity"
        )


    # --------------------------------
    # High packet rate
    # --------------------------------

    if features["packets_per_second"] >= 50:

        risk += 25

        reasons.append(
            "High packet rate"
        )


    # --------------------------------
    # Determine behavior
    # --------------------------------

    if (
        features["unique_destination_ports"] >= 15
        and
        features["tcp_syn_count"] >= 20
    ):

        attack_type = "Possible Port Scan"

    elif features["packets_per_second"] >= 50:

        attack_type = "Traffic Spike"

    else:

        attack_type = "Unknown"


    # --------------------------------
    # Limit risk
    # --------------------------------

    risk = min(risk, 100)


    return {
        "attack_type": attack_type,
        "risk_score": risk,
        "reasons": reasons
    }
