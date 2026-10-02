from attack_analyzer import analyze_attack


normal_features = {

    "unique_destination_ports": 25,

    "tcp_syn_count": 40,

    "packets_per_second": 80
}


result = analyze_attack(
    normal_features
)


print("================================")
print(" ATTACK ANALYZER TEST")
print("================================")

print(
    f"Attack Type: "
    f"{result['attack_type']}"
)

print(
    f"Risk Score: "
    f"{result['risk_score']}"
)

print(
    f"Reasons: "
    f"{result['reasons']}"
)

