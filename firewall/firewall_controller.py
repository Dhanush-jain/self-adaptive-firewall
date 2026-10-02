from datetime import datetime


# ==========================================
# FIREWALL CONTROLLER
# ==========================================

def execute_action(firewall_result):
    """
    Execute the firewall decision.

    Currently running in SAFE SIMULATION MODE.
    No real firewall rules are modified.
    """

    action = firewall_result["action"]
    risk_score = firewall_result["risk_score"]
    severity = firewall_result["severity"]
    attack_type = firewall_result["attack_type"]

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    print("\n==========================================")
    print("          FIREWALL CONTROLLER")
    print("==========================================")

    print(f"Time        : {timestamp}")
    print(f"Action      : {action}")
    print(f"Risk Score  : {risk_score}")
    print(f"Severity    : {severity}")
    print(f"Attack Type : {attack_type}")

    # --------------------------------------
    # ALLOW
    # --------------------------------------

    if action == "ALLOW":

        print("\n[SIMULATION] Traffic allowed.")

    # --------------------------------------
    # MONITOR
    # --------------------------------------

    elif action == "MONITOR":

        print("\n[SIMULATION] Traffic being monitored.")

    # --------------------------------------
    # BLOCK
    # --------------------------------------

    elif action == "BLOCK":

        print("\n[SIMULATION] Traffic would be BLOCKED.")

    # --------------------------------------
    # BLOCK + ALERT
    # --------------------------------------

    elif action == "BLOCK_AND_ALERT":

        print("\n[SIMULATION] Traffic would be BLOCKED.")
        print("[SIMULATION] Security ALERT generated.")

    else:

        print("\nUnknown firewall action.")

    print("==========================================")
