import csv
import os


FILE_PATH = "logs/traffic.csv"


def save_packet(data):

    os.makedirs("logs", exist_ok=True)

    file_exists = os.path.exists(FILE_PATH)

    with open(FILE_PATH, "a", newline="") as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp",
                "source_ip",
                "destination_ip",
                "source_port",
                "destination_port",
                "protocol",
                "packet_size"
            ]
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(data)
