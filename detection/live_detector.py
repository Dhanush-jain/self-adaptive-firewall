from scapy.all import sniff, IP, TCP, UDP
from pathlib import Path
from datetime import datetime
import pandas as pd
import joblib
import os

from detection.attack_analyzer import analyze_attack
from detection.risk_engine import calculate_risk
from firewall.decision_engine import make_firewall_decision


# ==========================================
# CONFIGURATION
# ==========================================

INTERFACE = os.getenv(
    "FIREWALL_INTERFACE",
    "enp0s3"
)

WINDOW_SECONDS = 5

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_FILE = (
    PROJECT_ROOT /
    "models" /
    "trained" /
    "isolation_forest.pkl"
)


# ==========================================
# FEATURES USED BY ISOLATION FOREST
# ==========================================

FEATURES = [
    "packets_per_second",
    "bytes_per_second",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "unique_source_ips",
    "unique_destination_ips",
    "unique_destination_ports"
]


# ==========================================
# LOAD MODEL
# ==========================================

print("==========================================")
print("       AI FIREWALL LIVE DETECTOR")
print("==========================================\n")

print("Loading AI model...")

model = joblib.load(MODEL_FILE)

print("Model loaded successfully.")

print(f"Interface : {INTERFACE}")
print(f"Window    : {WINDOW_SECONDS} seconds")

print("\nStarting live detection...\n")


# ==========================================
# FEATURE EXTRACTION
# ==========================================

def analyze_packets(packets):

    packet_count = len(packets)

    total_bytes = sum(
        len(packet)
        for packet in packets
    )

    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    tcp_syn_count = 0
    tcp_rst_count = 0

    source_ports = set()

    source_ips = set()
    destination_ips = set()
    destination_ports = set()

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        ip_layer = packet[IP]

        source_ips.add(
            ip_layer.src
        )

        destination_ips.add(
            ip_layer.dst
        )

        # -----------------------------
        # TCP
        # -----------------------------

        if packet.haslayer(TCP):

            tcp_count += 1

            destination_ports.add(
                packet[TCP].dport
            )

            source_ports.add(
                packet[TCP].sport
            )

            flags = int(packet[TCP].flags)

            if flags & 0x02:
                tcp_syn_count += 1

            if flags & 0x04:
                tcp_rst_count += 1

        # -----------------------------
        # UDP
        # -----------------------------

        elif packet.haslayer(UDP):

            udp_count += 1

            destination_ports.add(
                packet[UDP].dport
            )

        # -----------------------------
        # ICMP
        # -----------------------------

        elif ip_layer.proto == 1:

            icmp_count += 1


    return {

        # ML features
        "packets_per_second":
            packet_count / WINDOW_SECONDS,

        "bytes_per_second":
            total_bytes / WINDOW_SECONDS,

        "tcp_count":
            tcp_count,

        "udp_count":
            udp_count,

        "icmp_count":
            icmp_count,

        "unique_source_ips":
            len(source_ips),

        "unique_destination_ips":
            len(destination_ips),

        "unique_destination_ports":
            len(destination_ports),

        # Attack-analysis features
        "tcp_syn_count":
            tcp_syn_count,

        "tcp_rst_count":
            tcp_rst_count,

        "unique_source_ports":
            len(source_ports)
    }


# ==========================================
# LIVE DETECTION LOOP
# ==========================================

while True:

    print("------------------------------------------")

    print(
        f"Capturing traffic for "
        f"{WINDOW_SECONDS} seconds..."
    )

    start_time = datetime.now()

    # Capture traffic
    packets = sniff(
        iface=INTERFACE,
        timeout=WINDOW_SECONDS,
        store=True
    )

    # Extract features
    features = analyze_packets(
        packets
    )


    # ======================================
    # 1. ISOLATION FOREST
    # ======================================

    X = pd.DataFrame(
        [features],
        columns=FEATURES
    )

    prediction = model.predict(X)[0]

    score = model.decision_function(X)[0]

    if prediction == 1:
        result = "NORMAL"
    else:
        result = "ANOMALY"


    ai_result = {
        "status": result,
        "anomaly_score": float(score)
    }


    # ======================================
    # 2. ATTACK ANALYZER
    # ======================================

    attack_result = analyze_attack(
        features
    )


    # ======================================
    # 3. RISK ENGINE
    # ======================================

    risk_result = calculate_risk(
        ai_result,
        attack_result
    )


    # ======================================
    # 4. FIREWALL DECISION
    # ======================================

    firewall_result = make_firewall_decision(
        risk_result,
        attack_result
    )


    # ======================================
    # DISPLAY TRAFFIC FEATURES
    # ======================================

    print("\nTraffic Features:")

    for key, value in features.items():

        print(
            f"{key}: {value}"
        )


    # ======================================
    # AI RESULT
    # ======================================

    print("\nAI RESULT")

    print(
        f"Status        : {result}"
    )

    print(
        f"Anomaly Score : {score:.4f}"
    )


    # ======================================
    # ATTACK ANALYSIS
    # ======================================

    print("\nATTACK ANALYSIS")

    print(
        f"Attack Type   : "
        f"{attack_result['attack_type']}"
    )

    print(
        f"Attack Risk   : "
        f"{attack_result['risk_score']}"
    )

    if attack_result["reasons"]:

        print("Reasons       :")

        for reason in attack_result["reasons"]:

            print(
                f"  - {reason}"
            )


    # ======================================
    # RISK ENGINE
    # ======================================

    print("\nRISK ENGINE")

    print(
        f"Risk Score    : "
        f"{risk_result['risk_score']}"
    )

    print(
        f"Severity      : "
        f"{risk_result['severity']}"
    )


    # ======================================
    # FIREWALL DECISION
    # ======================================

    print("\nFIREWALL DECISION")

    print(
        f"Action        : "
        f"{firewall_result['action']}"
    )

    print(
        f"Window Time   : "
        f"{start_time.strftime('%H:%M:%S')}"
    )
