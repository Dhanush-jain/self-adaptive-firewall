import pandas as pd
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "logs" / "behavior_live.csv"
OUTPUT_FILE = PROJECT_ROOT / "data" / "normal_baseline.csv"


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


def create_baseline():

    print("===================================")
    print("       NORMAL TRAFFIC BASELINE")
    print("===================================\n")

    try:

        df = pd.read_csv(INPUT_FILE)

    except FileNotFoundError:

        print("behavior_live.csv not found.")
        return

    if df.empty:

        print("No traffic data available.")
        return

    # Keep only required ML features
    baseline = df[FEATURES].copy()

    # Remove missing values
    baseline = baseline.dropna()

    # Create data directory
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Save baseline
    baseline.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("Normal baseline created.\n")

    print(f"Samples: {len(baseline)}")

    print(f"Saved to:")
    print(OUTPUT_FILE)

    print("\nBaseline statistics:\n")

    print(
        baseline.describe()
    )


if __name__ == "__main__":

    create_baseline()
