from traffic_window import load_traffic
from feature_extractor import extract_features


df = load_traffic()

features = extract_features(df)

print("\n==============================")
print("NETWORK BEHAVIOR FEATURES")
print("==============================\n")

if features:

    for key, value in features.items():

        print(f"{key}: {value}")
