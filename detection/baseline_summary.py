import pandas as pd
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

FILE = PROJECT_ROOT / "data" / "normal_baseline.csv"


df = pd.read_csv(FILE)


print("===================================")
print("       NORMAL TRAFFIC SUMMARY")
print("===================================\n")


for column in df.columns:

    print(f"\n{column}")

    print(
        f"  Average : {df[column].mean():.2f}"
    )

    print(
        f"  Minimum : {df[column].min():.2f}"
    )

    print(
        f"  Maximum : {df[column].max():.2f}"
    )

    print(
        f"  Std Dev : {df[column].std():.2f}"
    )
