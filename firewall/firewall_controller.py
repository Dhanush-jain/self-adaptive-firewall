import os
import subprocess
from datetime import datetime


# ==========================================
# FIREWALL CONFIGURATION
# ==========================================

NFT_TABLE = "ai_firewall"
NFT_CHAIN = "input"

# Controlled laboratory target
TEST_TARGET_IP = "127.0.0.2"
TEST_TARGET_PORT = 8080

# Real enforcement is OFF by default
REAL_ENFORCEMENT = (
    os.getenv("FIREWALL_ENFORCEMENT", "0") == "1"
)


# ==========================================
# CHECK WHETHER RULE ALREADY EXISTS
# ==========================================

def rule_exists():

    result = subprocess.run(
        [
            "nft",
            "list",
            "chain",
            "inet",
            NFT_TABLE,
            NFT_CHAIN
        ],
        capture_output=True,
        text=True
    )

    rule_text = result.stdout

    target = (
        f"ip daddr {TEST_TARGET_IP} "
        f"tcp dport {TEST_TARGET_PORT}"
    )

    return target in rule_text


# ==========================================
# CREATE BLOCK RULE
# ==========================================

def block_test_target():

    if rule_exists():

        print(
            "[NFTABLES] Block rule already exists."
        )

        return True


    command = [
        "nft",
        "add",
        "rule",
        "inet",
        NFT_TABLE,
        NFT_CHAIN,
        "ip",
        "daddr",
        TEST_TARGET_IP,
        "tcp",
        "dport",
        str(TEST_TARGET_PORT),
        "counter",
        "drop"
    ]


    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )


    if result.returncode == 0:

        print(
            "[NFTABLES] Block rule created."
        )

        print(
            f"[NFTABLES] Target: "
            f"{TEST_TARGET_IP}:{TEST_TARGET_PORT}"
        )

        return True


    print(
        "[NFTABLES] Failed to create block rule."
    )

    if result.stderr:

        print(
            f"[NFTABLES] Error: "
            f"{result.stderr.strip()}"
        )

    return False


# ==========================================
# FIREWALL CONTROLLER
# ==========================================

def execute_action(firewall_result):

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

    elif action in (
        "BLOCK",
        "BLOCK_AND_ALERT"
    ):

        if not REAL_ENFORCEMENT:

            print(
                "\n[SIMULATION] Traffic would be BLOCKED."
            )

            if action == "BLOCK_AND_ALERT":

                print(
                    "[SIMULATION] "
                    "Security ALERT generated."
                )

        else:

            print(
                "\n[REAL FIREWALL] "
                "Attempting to block traffic..."
            )

            success = block_test_target()


            if success:

                print(
                    "[REAL FIREWALL] "
                    "Traffic BLOCKED."
                )

            else:

                print(
                    "[REAL FIREWALL] "
                    "Blocking failed."
                )


            if action == "BLOCK_AND_ALERT":

                print(
                    "[ALERT] Security ALERT generated."
                )


    else:

        print(
            "\n[CONTROLLER] Unknown firewall action."
        )


    print("==========================================")
