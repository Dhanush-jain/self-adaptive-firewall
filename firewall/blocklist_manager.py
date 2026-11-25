import os
import ipaddress
import subprocess


# ==========================================
# NFTABLES CONFIGURATION
# ==========================================

NFT_FAMILY = "inet"
NFT_TABLE = "ai_firewall"

NFT_SET = "blocked_sources"
NFT_TEMP_SET = "temporary_blocked_sources"

NFT_CHAIN = "forward"

# Optional network namespace.
# Leave unset for normal Ubuntu operation.
# Set NFT_NETNS=firewall for isolated testing.
NFT_NETNS = os.getenv("NFT_NETNS", "").strip()


# ==========================================
# NFTABLES COMMAND HELPER
# ==========================================

def nft_command(*args):
    """
    Execute nftables commands.
    Optionally execute them inside a network namespace.
    """

    command = ["nft", *args]

    if NFT_NETNS:
        command = [
            "ip",
            "netns",
            "exec",
            NFT_NETNS,
            *command
        ]

    return command


def run_nft(command):

    result = subprocess.run(
        nft_command("-f", "-"),
        input=command.strip() + "\n",
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[NFTABLES] Command failed.")

        if result.stderr:
            print(result.stderr.strip())

        return False

    return True


# ==========================================
# VALIDATE SOURCE IP
# ==========================================

def validate_ip(ip_address):

    try:
        address = ipaddress.ip_address(ip_address)

    except (ValueError, TypeError):
        print("[BLOCKLIST] Invalid IP address.")
        return False

    if address.version != 4:
        print("[BLOCKLIST] Only IPv4 addresses are supported.")
        return False

    if (
        address.is_loopback
        or address.is_multicast
        or address.is_unspecified
        or address.is_link_local
        or address == ipaddress.IPv4Address("255.255.255.255")
    ):
        print("[BLOCKLIST] Unsafe IP address rejected.")
        return False

    return True


# ==========================================
# CHECK NFTABLES OBJECT
# ==========================================

def nft_object_exists(object_type, object_name=None):

    if object_type == "table":

        command = nft_command(
            "list", "table",
            NFT_FAMILY, NFT_TABLE
        )

    elif object_type in ("set", "chain") and object_name:

        command = nft_command(
            "list", object_type,
            NFT_FAMILY, NFT_TABLE, object_name
        )

    else:
        return False

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.returncode == 0


# ==========================================
# INITIALIZE BLOCKLIST
# ==========================================

def initialize_blocklist():

    # 1. Create table

    if not nft_object_exists("table"):

        if not run_nft(
            f"add table {NFT_FAMILY} {NFT_TABLE}"
        ):
            return False

    # 2. Create permanent set

    if not nft_object_exists("set", NFT_SET):

        command = f"""
add set {NFT_FAMILY} {NFT_TABLE} {NFT_SET} {{
    type ipv4_addr;
}}
"""

        if not run_nft(command):
            return False

    # 3. Create temporary set

    if not nft_object_exists("set", NFT_TEMP_SET):

        command = f"""
add set {NFT_FAMILY} {NFT_TABLE} {NFT_TEMP_SET} {{
    type ipv4_addr;
    flags timeout;
}}
"""

        if not run_nft(command):
            return False

    # 4. Create forwarding chain

    if not nft_object_exists("chain", NFT_CHAIN):

        command = f"""
add chain {NFT_FAMILY} {NFT_TABLE} {NFT_CHAIN} {{
    type filter hook forward priority -100;
    policy accept;
}}
"""

        if not run_nft(command):
            return False

    # 5. Read existing rules

    result = subprocess.run(
        nft_command(
            "list", "chain",
            NFT_FAMILY, NFT_TABLE, NFT_CHAIN
        ),
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[NFTABLES] Unable to inspect forwarding chain.")

        if result.stderr:
            print(result.stderr.strip())

        return False

    existing_rules = result.stdout

    # 6. Add permanent blocking rule

    if f"ip saddr @{NFT_SET}" not in existing_rules:

        command = (
            f"add rule {NFT_FAMILY} {NFT_TABLE} "
            f"{NFT_CHAIN} ip saddr @{NFT_SET} counter drop"
        )

        if not run_nft(command):
            return False

    # 7. Add temporary blocking rule

    if f"ip saddr @{NFT_TEMP_SET}" not in existing_rules:

        command = (
            f"add rule {NFT_FAMILY} {NFT_TABLE} "
            f"{NFT_CHAIN} ip saddr @{NFT_TEMP_SET} counter drop"
        )

        if not run_nft(command):
            return False

    print("[BLOCKLIST] Initialization successful.")

    return True


# ==========================================
# ADD PERMANENT BLOCKED IP
# ==========================================

def add_blocked_ip(ip_address):

    if not validate_ip(ip_address):
        return False

    ip_address = str(ipaddress.ip_address(ip_address))

    if not initialize_blocklist():
        return False

    command = f"""
add element {NFT_FAMILY} {NFT_TABLE} {NFT_SET} {{
    {ip_address}
}}
"""

    if not run_nft(command):
        print(
            "[BLOCKLIST] Could not add IP. "
            "It may already be present."
        )
        return False

    print(f"[BLOCKLIST] IP added successfully: {ip_address}")

    return True


# ==========================================
# ADD TEMPORARY BLOCKED IP
# ==========================================

def add_temporary_blocked_ip(ip_address, timeout_seconds=60):

    if not validate_ip(ip_address):
        return False

    ip_address = str(ipaddress.ip_address(ip_address))

    try:
        timeout_seconds = int(timeout_seconds)

    except (TypeError, ValueError):
        print("[BLOCKLIST] Invalid timeout.")
        return False

    if timeout_seconds <= 0:
        print("[BLOCKLIST] Timeout must be positive.")
        return False

    if not initialize_blocklist():
        return False

    command = f"""
add element {NFT_FAMILY} {NFT_TABLE} {NFT_TEMP_SET} {{
    {ip_address} timeout {timeout_seconds}s
}}
"""

    if not run_nft(command):
        print("[BLOCKLIST] Temporary block failed.")
        return False

    print(
        f"[BLOCKLIST] Temporary block added: {ip_address} "
        f"for {timeout_seconds} seconds"
    )

    return True


# ==========================================
# REMOVE PERMANENT BLOCKED IP
# ==========================================

def remove_blocked_ip(ip_address):

    if not validate_ip(ip_address):
        return False

    ip_address = str(ipaddress.ip_address(ip_address))

    command = f"""
delete element {NFT_FAMILY} {NFT_TABLE} {NFT_SET} {{
    {ip_address}
}}
"""

    if not run_nft(command):
        return False

    print(f"[BLOCKLIST] Permanent IP removed: {ip_address}")

    return True


# ==========================================
# REMOVE TEMPORARY BLOCKED IP
# ==========================================

def remove_temporary_blocked_ip(ip_address):

    if not validate_ip(ip_address):
        return False

    ip_address = str(ipaddress.ip_address(ip_address))

    command = f"""
delete element {NFT_FAMILY} {NFT_TABLE} {NFT_TEMP_SET} {{
    {ip_address}
}}
"""

    if not run_nft(command):
        return False

    print(f"[BLOCKLIST] Temporary IP removed: {ip_address}")

    return True


# ==========================================
# DISPLAY PERMANENT BLOCKLIST
# ==========================================

def show_blocked_ips():

    result = subprocess.run(
        nft_command(
            "list", "set",
            NFT_FAMILY, NFT_TABLE, NFT_SET
        ),
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[BLOCKLIST] Unable to read permanent blocklist.")

        if result.stderr:
            print(result.stderr.strip())

        return

    print("\n========== PERMANENTLY BLOCKED IPs ==========")
    print(result.stdout)
    print("==============================================")


# ==========================================
# DISPLAY TEMPORARY BLOCKLIST
# ==========================================

def show_temporary_blocked_ips():

    result = subprocess.run(
        nft_command(
            "list", "set",
            NFT_FAMILY, NFT_TABLE, NFT_TEMP_SET
        ),
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[BLOCKLIST] Unable to read temporary blocklist.")

        if result.stderr:
            print(result.stderr.strip())

        return

    print("\n========== TEMPORARILY BLOCKED IPs ==========")
    print(result.stdout)
    print("==============================================")


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    print("\n==========================================")
    print("       NFTABLES BLOCKLIST MANAGER")
    print("==========================================")

    print(
        f"[INFO] Network namespace: "
        f"{NFT_NETNS if NFT_NETNS else 'Main namespace'}"
    )

    if initialize_blocklist():

        test_ip = "198.51.100.10"

        print("\nTEST 1 - PERMANENT BLOCKING")

        if add_blocked_ip(test_ip):

            show_blocked_ips()

            print("\nRemoving permanent test IP...")

            remove_blocked_ip(test_ip)

            show_blocked_ips()

        print("\nTEST 2 - TEMPORARY BLOCKING")

        if add_temporary_blocked_ip(
            test_ip,
            timeout_seconds=60
        ):
            show_temporary_blocked_ips()

        print("\nTEST COMPLETED")

    else:
        print("\n[ERROR] Blocklist initialization failed.")
