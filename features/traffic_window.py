import pandas as pd
from pathlib import Path


# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Location of traffic.csv
TRAFFIC_FILE = PROJECT_ROOT / "logs" / "traffic.csv"


def load_traffic():

    try:

        df = pd.read_csv(TRAFFIC_FILE)

        if df.empty:
            print("Traffic file is empty.")
            return None

        return df

    except FileNotFoundError:

        print(f"Traffic file not found: {TRAFFIC_FILE}")

        return None
