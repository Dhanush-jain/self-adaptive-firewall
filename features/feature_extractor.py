import pandas as pd


def extract_features(df):

    if df is None or df.empty:
        return None

    # Convert timestamp to datetime
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Calculate total packets
    packet_count = len(df)

    # Calculate total bytes
    total_bytes = df["packet_size"].sum()

    # Calculate duration
    duration = (
        df["timestamp"].max() -
        df["timestamp"].min()
    ).total_seconds()

    # Avoid division by zero
    if duration <= 0:
        duration = 1

    # Calculate packet rate
    packets_per_second = packet_count / duration

    # Calculate byte rate
    bytes_per_second = total_bytes / duration

    # Protocol counts
    tcp_count = (df["protocol"] == "TCP").sum()
    udp_count = (df["protocol"] == "UDP").sum()
    icmp_count = (df["protocol"] == "ICMP").sum()

    # Unique values
    unique_source_ips = df["source_ip"].nunique()
    unique_destination_ips = df["destination_ip"].nunique()
    unique_destination_ports = df["destination_port"].nunique()

    return {
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "icmp_count": icmp_count,
        "unique_source_ips": unique_source_ips,
        "unique_destination_ips": unique_destination_ips,
        "unique_destination_ports": unique_destination_ports
    }
