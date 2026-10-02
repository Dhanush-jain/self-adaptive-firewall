import pandas as pd
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

TRAFFIC_FILE = PROJECT_ROOT / "logs" / "traffic.csv"
BEHAVIOR_FILE = PROJECT_ROOT / "logs" / "behavior.csv"


def extract_behavior():

    try:
        df = pd.read_csv(TRAFFIC_FILE)

    except FileNotFoundError:

        print("traffic.csv not found.")
        return

    if df.empty:

        print("No traffic data available.")
        return

    # Convert timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Sort packets by time
    df = df.sort_values("timestamp")

    # Create 5-second time windows
    df["time_window"] = (
        df["timestamp"]
        .dt.floor("5s")
    )

    # Group packets into windows
    grouped = df.groupby("time_window")

    results = []

    for window, group in grouped:

        packet_count = len(group)

        total_bytes = group["packet_size"].sum()

        tcp_count = (
            group["protocol"] == "TCP"
        ).sum()

        udp_count = (
            group["protocol"] == "UDP"
        ).sum()

        icmp_count = (
            group["protocol"] == "ICMP"
        ).sum()

        unique_source_ips = (
            group["source_ip"].nunique()
        )

        unique_destination_ips = (
            group["destination_ip"].nunique()
        )

        unique_destination_ports = (
            group["destination_port"].nunique()
        )

        results.append({

            "time_window": window,

            "packet_count": packet_count,

            "total_bytes": total_bytes,

            "packets_per_second":
                packet_count / 5,

            "bytes_per_second":
                total_bytes / 5,

            "tcp_count": tcp_count,

            "udp_count": udp_count,

            "icmp_count": icmp_count,

            "unique_source_ips":
                unique_source_ips,

            "unique_destination_ips":
                unique_destination_ips,

            "unique_destination_ports":
                unique_destination_ports
        })

    behavior_df = pd.DataFrame(results)

    behavior_df.to_csv(
        BEHAVIOR_FILE,
        index=False
    )

    print("Behavior dataset created.")
    print(f"Saved to: {BEHAVIOR_FILE}")
