import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
import joblib


# --------------------------------
# PROJECT PATHS
# --------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    PROJECT_ROOT /
    "data" /
    "normal_baseline.csv"
)

MODEL_DIR = (
    PROJECT_ROOT /
    "models" /
    "trained"
)

MODEL_FILE = (
    MODEL_DIR /
    "isolation_forest.pkl"
)


# --------------------------------
# FEATURES
# --------------------------------

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


# --------------------------------
# LOAD DATA
# --------------------------------

print("======================================")
print("   ISOLATION FOREST TRAINING")
print("======================================\n")


try:

    df = pd.read_csv(DATA_FILE)

except FileNotFoundError:

    print("normal_baseline.csv not found.")

    exit()


print(f"Training samples: {len(df)}")


# --------------------------------
# SELECT FEATURES
# --------------------------------

X = df[FEATURES].copy()


# Remove missing values

X = X.dropna()


print(f"Valid samples: {len(X)}")


# --------------------------------
# CREATE MODEL
# --------------------------------

model = IsolationForest(

    n_estimators=200,

    contamination=0.05,

    random_state=42,

    n_jobs=-1
)


# --------------------------------
# TRAIN
# --------------------------------

print("\nTraining model...")

model.fit(X)


# --------------------------------
# SAVE MODEL
# --------------------------------

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_FILE
)


print("\n======================================")
print("MODEL TRAINING COMPLETE")
print("======================================")

print(f"\nModel saved to:")

print(MODEL_FILE)
