import os
from datetime import datetime

from firewall.blocklist_manager import (
    add_temporary_blocked_ip
)


# ==========================================
# FIREWALL CONFIGURATION
# ==========================================

REAL_ENFORCEMENT = (
    os.getenv("FIREWALL_ENFORCEMENT", "0") == "1"
)

TEMP_BLOCK_DURATION = 60


# ==========================================
# TEMPORARY SOURCE IP BLOCKING
# ==========================================

def temporarily_block_source_ip(source_ip):

    if not source_ip:

        print("[NFTABLES] No source IP provided.")
        print("[NFTABLES] Blocking cancelled.")

        return False

    print(
        f"[NFTABLES] Applying temporary block "
        f"to {source_ip}"
    )

    success = add_temporary_blocked_ip(
        source_ip,
        timeout_seconds=TEMP_BLOCK_DURATION
    )

    if success:

        print(
            f"[NFTABLES] Temporary block successful: "
            f"{source_ip}"
        )

        print(
            f"[NFTABLES] Block duration: "
            f"{TEMP_BLOCK_DURATION} seconds"
        )

        return True

    print(
        f"[NFTABLES] Temporary blocking failed: "
        f"{source_ip}"
    )

    return False


# ==========================================
# FIREWALL CONTROLLER
# ==========================================

def execute_action(firewall_result):

    action = firewall_result.get(
        "action", "UNKNOWN"
    )

    risk_score = firewall_result.get(
        "risk_score", 0
    )

    severity = firewall_result.get(
        "severity", "UNKNOWN"
    )

    attack_type = firewall_result.get(
        "attack_type", "Unknown"
    )

    source_ip = firewall_result.get(
        "source_ip"
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    success = None

    # ======================================
    # DISPLAY FIREWALL INFORMATION
    # ======================================

    print("\n==========================================")
    print("          FIREWALL CONTROLLER")
    print("==========================================")

    print(f"Time        : {timestamp}")
    print(f"Action      : {action}")
    print(f"Risk Score  : {risk_score}")
    print(f"Severity    : {severity}")
    print(f"Attack Type : {attack_type}")
    print(f"Source IP   : {source_ip}")

    print(
        f"Enforcement : "
        f"{'ON' if REAL_ENFORCEMENT else 'OFF'}"
    )

    # ======================================
    # ALLOW
    # ======================================

    if action == "ALLOW":

        print(
            "\n[CONTROLLER] Traffic allowed."
        )

    # ======================================
    # MONITOR
    # ======================================

    elif action == "MONITOR":

        print(
            "\n[CONTROLLER] Traffic monitored."
        )

    # ======================================
    # BLOCK
    # ======================================

    elif action == "BLOCK":

        if not REAL_ENFORCEMENT:

            print(
                "\n[SIMULATION] Traffic would be blocked."
            )

            print(
                f"[SIMULATION] Target source IP: "
                f"{source_ip}"
            )

        else:

            print(
                "\n[REAL FIREWALL] Applying temporary blocking..."
            )

            success = temporarily_block_source_ip(
                source_ip
            )

            if success:

                print(
                    "[REAL FIREWALL] "
                    "Traffic source temporarily blocked."
                )

            else:

                print(
                    "[REAL FIREWALL] Blocking failed."
                )

    # ======================================
    # BLOCK AND ALERT
    # ======================================

    elif action == "BLOCK_AND_ALERT":

        if not REAL_ENFORCEMENT:

            print(
                "\n[SIMULATION] Traffic would be blocked."
            )

            print(
                f"[SIMULATION] Target source IP: "
                f"{source_ip}"
            )

        else:

            print(
                "\n[REAL FIREWALL] Applying temporary blocking..."
            )

            success = temporarily_block_source_ip(
                source_ip
            )

            if success:

                print(
                    "[REAL FIREWALL] "
                    "Suspicious source temporarily blocked."
                )

            else:

                print(
                    "[REAL FIREWALL] Blocking failed."
                )

        print(
            "[ALERT] Critical security alert generated."
        )

    # ======================================
    # UNKNOWN ACTION
    # ======================================

    else:

        print(
            "\n[CONTROLLER] Unknown firewall action."
        )

        success = False

    print("==========================================")

    # ======================================
    # RETURN RESULT
    # ======================================

    if action in (
        "BLOCK",
        "BLOCK_AND_ALERT"
    ) and REAL_ENFORCEMENT:

        return success

    return None
