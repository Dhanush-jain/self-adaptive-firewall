from scapy.all import sniff
from pathlib import Path
from datetime import datetime
import pandas as pd
import joblib
import os
import time

# ==========================================
# PROJECT MODULES
# ==========================================

from detection.attack_analyzer import analyze_attack

from detection.risk_engine import calculate_risk

from detection.source_analyzer import (
    analyze_packets,
    identify_suspicious_sources
)

from firewall.decision_engine import make_firewall_decision

from firewall.firewall_controller import execute_action


# ==================================================
# 1. CONFIGURATION
# ==================================================

INTERFACE = os.getenv(
    "FIREWALL_INTERFACE",
    "veth-fw-in"
)

WINDOW_SECONDS = 5

# Minimum source-specific risk required for blocking
SOURCE_BLOCK_THRESHOLD = 65

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "trained"
    / "isolation_forest.pkl"
)


# ==================================================
# 2. ISOLATION FOREST FEATURES
# ==================================================

# IMPORTANT:
# These must remain the same features used
# when the Isolation Forest was trained.

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


# ==================================================
# 3. LOAD AI MODEL
# ==================================================

print("\n==========================================")
print("          AI FIREWALL LIVE DETECTOR")
print("==========================================")

print("\n[INFO] Loading Isolation Forest model...")

if not MODEL_FILE.exists():

    raise FileNotFoundError(
        f"Model file not found: {MODEL_FILE}"
    )

model = joblib.load(MODEL_FILE)

print("[SUCCESS] AI Model loaded successfully.")

print(f"[INFO] Network Interface : {INTERFACE}")

print(f"[INFO] Capture Window    : {WINDOW_SECONDS} seconds")

print(
    f"[INFO] Source Block Threshold : "
    f"{SOURCE_BLOCK_THRESHOLD}"
)

print("\n[INFO] Starting live traffic detection...")


# ==================================================
# 4. DISPLAY TRAFFIC FEATURES
# ==================================================

def display_traffic_features(features):

    print("\n========== TRAFFIC FEATURES ==========")

    display_features = [
        "packets_per_second",
        "bytes_per_second",
        "tcp_count",
        "udp_count",
        "icmp_count",
        "unique_source_ips",
        "unique_destination_ips",
        "unique_destination_ports",
        "tcp_syn_count",
        "tcp_rst_count",
        "unique_source_ports"
    ]

    for feature in display_features:

        print(
            f"{feature}: {features.get(feature, 0)}"
        )


# ==================================================
# 5. DISPLAY SOURCE IP ANALYSIS
# ==================================================

def display_source_analysis(features, suspicious_sources):

    print("\n========== SOURCE IP ANALYSIS ==========")

    print(
        "Observed Source IPs:",
        features.get("source_ips", [])
    )

    source_activity = features.get(
        "source_activity",
        {}
    )

    for source_ip, stats in source_activity.items():

        print("\n--------------------------------------")

        print(f"Source IP       : {source_ip}")

        print(
            f"Packets         : "
            f"{stats['packet_count']}"
        )

        print(
            f"Packets/sec     : "
            f"{stats['packets_per_second']:.2f}"
        )

        print(
            f"TCP Count       : "
            f"{stats['tcp_count']}"
        )

        print(
            f"TCP SYN Count   : "
            f"{stats['tcp_syn_count']}"
        )

        print(
            f"TCP RST Count   : "
            f"{stats['tcp_rst_count']}"
        )

        print(
            f"Destination Ports: "
            f"{stats['unique_destination_ports']}"
        )


    # ======================================
    # SUSPICIOUS SOURCE RESULTS
    # ======================================

    print("\n========== SUSPICIOUS SOURCES ==========")

    if not suspicious_sources:

        print("[INFO] No suspicious source identified.")

        return

    for source in suspicious_sources:

        print("\nSuspicious Candidate")

        print(
            f"Source IP  : {source['source_ip']}"
        )

        print(
            f"Risk Score : {source['risk_score']}"
        )

        print(
            f"Reasons    : {source['reasons']}"
        )


# ==================================================
# 6. SELECT BLOCKING SOURCE IP
# ==================================================

def select_blocking_source(
    firewall_result,
    suspicious_sources
):

    selected_source_ip = None

    action = firewall_result.get(
        "action",
        "UNKNOWN"
    )

    # Blocking is considered only when
    # the decision engine requests blocking.

    if action not in (
        "BLOCK",
        "BLOCK_AND_ALERT"
    ):

        firewall_result["source_ip"] = None

        return None


    # Select sources that meet the threshold.

    qualified_sources = [

        source

        for source in suspicious_sources

        if source["risk_score"] >= SOURCE_BLOCK_THRESHOLD

    ]


    if qualified_sources:

        # Highest-risk source is selected first.

        selected_source = qualified_sources[0]

        selected_source_ip = selected_source["source_ip"]

        firewall_result["source_ip"] = selected_source_ip

        firewall_result["source_risk"] = (
            selected_source["risk_score"]
        )

    else:

        firewall_result["source_ip"] = None

        print(
            "\n[INFO] No source IP reached "
            "the blocking threshold."
        )


    return selected_source_ip


# ==================================================
# 7. MAIN LIVE DETECTION LOOP
# ==================================================

try:

    while True:

        print("\n\n==========================================")

        print("          NEW DETECTION WINDOW")

        print("==========================================")


        # ======================================
        # CAPTURE NETWORK TRAFFIC
        # ======================================

        print(
            f"\n[INFO] Capturing traffic for "
            f"{WINDOW_SECONDS} seconds..."
        )

        start_time = datetime.now()

        packets = sniff(
            iface=INTERFACE,
            timeout=WINDOW_SECONDS,
            store=True
        )

        print(
            f"[INFO] Captured {len(packets)} packets."
        )


        # ======================================
        # HANDLE EMPTY CAPTURE WINDOW
        # ======================================

        if len(packets) == 0:

            print(
                "[INFO] No packets captured "
                "during this window."
            )

            print(
                "[INFO] Skipping detection and "
                "firewall decision."
            )

            continue


        # ======================================
        # FEATURE EXTRACTION
        # ======================================

        # Uses detection/source_analyzer.py

        features = analyze_packets(packets)


        # ======================================
        # SOURCE IP IDENTIFICATION
        # ======================================

        # Uses detection/source_analyzer.py

        suspicious_sources = identify_suspicious_sources(
            features
        )


        # ======================================
        # ISOLATION FOREST AI DETECTION
        # ======================================

        # Only the original eight features
        # are passed to the trained model.

        X = pd.DataFrame(
            [
                {
                    feature: features[feature]
                    for feature in FEATURES
                }
            ],
            columns=FEATURES
        )

        prediction = model.predict(X)[0]

        anomaly_score = model.decision_function(X)[0]


        if prediction == 1:

            ai_status = "NORMAL"

        else:

            ai_status = "ANOMALY"


        ai_result = {

            "status": ai_status,

            "anomaly_score": float(anomaly_score)

        }


        # ======================================
        # ATTACK ANALYZER
        # ======================================

        attack_result = analyze_attack(
            features
        )


        # ======================================
        # RISK ENGINE
        # ======================================

        risk_result = calculate_risk(
            ai_result,
            attack_result
        )


        # ======================================
        # FIREWALL DECISION ENGINE
        # ======================================

        firewall_result = make_firewall_decision(
            risk_result,
            attack_result
        )


        # ======================================
        # SELECT SUSPICIOUS SOURCE IP
        # ======================================

        selected_source_ip = select_blocking_source(
            firewall_result,
            suspicious_sources
        )


        # ======================================
        # DISPLAY TRAFFIC FEATURES
        # ======================================

        display_traffic_features(
            features
        )


        # ======================================
        # DISPLAY SOURCE ANALYSIS
        # ======================================

        display_source_analysis(
            features,
            suspicious_sources
        )


        # ======================================
        # DISPLAY AI DETECTION RESULT
        # ======================================

        print("\n========== AI DETECTION ==========")

        print(
            f"Status        : {ai_status}"
        )

        print(
            f"Anomaly Score : {anomaly_score:.4f}"
        )


        # ======================================
        # DISPLAY ATTACK ANALYSIS
        # ======================================

        print("\n========== ATTACK ANALYSIS ==========")

        print(
            f"Attack Type : "
            f"{attack_result['attack_type']}"
        )

        print(
            f"Attack Risk : "
            f"{attack_result['risk_score']}"
        )

        if attack_result.get("reasons"):

            print("\nDetection Reasons:")

            for reason in attack_result["reasons"]:

                print(f" - {reason}")

        else:

            print("[INFO] No known attack indicators.")


        # ======================================
        # DISPLAY RISK ENGINE RESULT
        # ======================================

        print("\n========== RISK ENGINE ==========")

        print(
            f"Risk Score : "
            f"{risk_result['risk_score']}"
        )

        print(
            f"Severity   : "
            f"{risk_result['severity']}"
        )


        # ======================================
        # DISPLAY FIREWALL DECISION
        # ======================================

        print("\n========== FIREWALL DECISION ==========")

        print(
            f"Action      : "
            f"{firewall_result['action']}"
        )

        print(
            f"Window Time : "
            f"{start_time.strftime('%H:%M:%S')}"
        )


        # ======================================
        # DISPLAY SELECTED BLOCKING TARGET
        # ======================================

        print("\n========== SELECTED BLOCKING TARGET ==========")

        if selected_source_ip:

            print(
                f"Source IP : {selected_source_ip}"
            )

            print(
                f"Source Risk : "
                f"{firewall_result['source_risk']}"
            )

        else:

            print(
                "No qualified source IP for blocking."
            )


        # ======================================
        # EXECUTE FIREWALL ACTION
        # ======================================

        print("\n========== FIREWALL EXECUTION ==========")

        execute_action(
            firewall_result
        )


        # ======================================
        # DETECTION CYCLE COMPLETED
        # ======================================

        print(
            "\n[INFO] Detection cycle completed."
        )

        print("------------------------------------------")


# ==================================================
# 8. STOP DETECTOR
# ==================================================

except KeyboardInterrupt:

    print(
        "\n\n[INFO] AI Firewall stopped by user."
    )


except Exception as error:

    print(
        "\n[ERROR] Live Detection Failed!"
    )

    print(
        f"Reason: {error}"
    )

    raise
