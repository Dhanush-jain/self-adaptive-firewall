import pandas as pd
from pathlib import Path
import joblib


# --------------------------------
# PATHS
# --------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_FILE = (
    PROJECT_ROOT /
    "models" /
    "trained" /
    "isolation_forest.pkl"
)

DATA_FILE = (
    PROJECT_ROOT /
    "logs" /
    "behavior_live.csv"
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


print("======================================")
print("      AI ANOMALY DETECTION TEST")
print("======================================\n")


# Load model

model = joblib.load(MODEL_FILE)


# Load traffic

df = pd.read_csv(DATA_FILE)


X = df[FEATURES].dropna()


# Predict

predictions = model.predict(X)

scores = model.decision_function(X)


for index, prediction in enumerate(predictions):

    if prediction == 1:

        result = "NORMAL"

    else:

        result = "ANOMALY"

    score = scores[index]

    print(
        f"Window {index + 1}: "
        f"{result} | "
        f"Score: {score:.4f}"
    )
