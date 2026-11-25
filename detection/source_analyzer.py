from scapy.all import IP, TCP, UDP


# ==========================================
# CONFIGURATION
# ==========================================

WINDOW_SECONDS = 5


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

    source_ips = set()
    destination_ips = set()
    destination_ports = set()
    source_ports = set()

    # Individual source IP tracking
    source_activity = {}

    # ======================================
    # PROCESS PACKETS
    # ======================================

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        source_ips.add(src_ip)
        destination_ips.add(dst_ip)

        # Initialize source statistics
        if src_ip not in source_activity:

            source_activity[src_ip] = {

                "packet_count": 0,
                "total_bytes": 0,

                "tcp_count": 0,
                "udp_count": 0,
                "icmp_count": 0,

                "tcp_syn_count": 0,
                "tcp_rst_count": 0,

                "destination_ports": set()
            }

        stats = source_activity[src_ip]

        stats["packet_count"] += 1

        stats["total_bytes"] += len(packet)

        # ==================================
        # TCP ANALYSIS
        # ==================================

        if packet.haslayer(TCP):

            tcp_count += 1

            tcp_layer = packet[TCP]

            stats["tcp_count"] += 1

            destination_ports.add(
                tcp_layer.dport
            )

            source_ports.add(
                tcp_layer.sport
            )

            stats["destination_ports"].add(
                tcp_layer.dport
            )

            flags = int(tcp_layer.flags)

            # SYN detection
            if flags & 0x02:

                tcp_syn_count += 1

                stats["tcp_syn_count"] += 1

            # RST detection
            if flags & 0x04:

                tcp_rst_count += 1

                stats["tcp_rst_count"] += 1

        # ==================================
        # UDP ANALYSIS
        # ==================================

        elif packet.haslayer(UDP):

            udp_count += 1

            udp_layer = packet[UDP]

            stats["udp_count"] += 1

            destination_ports.add(
                udp_layer.dport
            )

            stats["destination_ports"].add(
                udp_layer.dport
            )

        # ==================================
        # ICMP ANALYSIS
        # ==================================

        elif ip_layer.proto == 1:

            icmp_count += 1

            stats["icmp_count"] += 1

    # ======================================
    # SOURCE-SPECIFIC FEATURE CALCULATION
    # ======================================

    for src_ip, stats in source_activity.items():

        stats["packets_per_second"] = (
            stats["packet_count"] / WINDOW_SECONDS
        )

        stats["bytes_per_second"] = (
            stats["total_bytes"] / WINDOW_SECONDS
        )

        stats["unique_destination_ports"] = (
            len(stats["destination_ports"])
        )

        # Convert set into a list for display
        stats["destination_ports"] = sorted(
            stats["destination_ports"]
        )

    # ======================================
    # RETURN FEATURES
    # ======================================

    return {

        # Original Isolation Forest features

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

        # Attack Analyzer features

        "tcp_syn_count":
            tcp_syn_count,

        "tcp_rst_count":
            tcp_rst_count,

        "unique_source_ports":
            len(source_ports),

        # Source identification features

        "source_ips":
            sorted(source_ips),

        "source_activity":
            source_activity
    }


# ==========================================
# SUSPICIOUS SOURCE IDENTIFICATION
# ==========================================

def identify_suspicious_sources(features):

    suspicious_sources = []

    source_activity = features.get(
        "source_activity",
        {}
    )

    # ======================================
    # ANALYZE EACH SOURCE IP
    # ======================================

    for src_ip, stats in source_activity.items():

        reasons = []

        source_risk = 0

        # ----------------------------------
        # MANY DESTINATION PORTS
        # ----------------------------------

        if stats["unique_destination_ports"] >= 15:

            source_risk += 40

            reasons.append(
                "Many destination ports"
            )

        # ----------------------------------
        # HIGH TCP SYN ACTIVITY
        # ----------------------------------

        if stats["tcp_syn_count"] >= 20:

            source_risk += 25

            reasons.append(
                "High TCP SYN activity"
            )

        # ----------------------------------
        # HIGH PACKET RATE
        # ----------------------------------

        if stats["packets_per_second"] >= 50:

            source_risk += 25

            reasons.append(
                "High packet rate"
            )

        # ----------------------------------
        # LIMIT RISK SCORE
        # ----------------------------------

        source_risk = min(
            source_risk,
            100
        )

        # ----------------------------------
        # RECORD SUSPICIOUS SOURCE
        # ----------------------------------

        if source_risk > 0:

            suspicious_sources.append({

                "source_ip": src_ip,

                "risk_score": source_risk,

                "packet_count":
                    stats["packet_count"],

                "tcp_syn_count":
                    stats["tcp_syn_count"],

                "unique_destination_ports":
                    stats["unique_destination_ports"],

                "packets_per_second":
                    stats["packets_per_second"],

                "reasons": reasons

            })

    # ======================================
    # SORT BY RISK SCORE
    # ======================================

    suspicious_sources.sort(
        key=lambda item: item["risk_score"],
        reverse=True
    )

    return suspicious_sources
