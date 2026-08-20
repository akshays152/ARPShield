import pandas as pd
import random

# Load normal ARP traffic
df = pd.read_csv("arp_dataset.csv")

# Create simulated spoofing records
attack_data = []

# Generate 1000 simulated ARP spoofing packets
for i in range(1000):

    # Pick a random normal packet
    row = df.sample(n=1).iloc[0]

    # Create a fake MAC address
    fake_mac = ":".join(
        f"{random.randint(0, 255):02x}"
        for _ in range(6)
    )

    # Create spoofed packet
    attack_data.append([
        row["timestamp"],
        row["sender_ip"],
        fake_mac,
        row["target_ip"],
        row["target_mac"],
        "reply"
    ])

# Create DataFrame
attack_df = pd.DataFrame(
    attack_data,
    columns=[
        "timestamp",
        "sender_ip",
        "sender_mac",
        "target_ip",
        "target_mac",
        "operation"
    ]
)

# Save simulated attack data
attack_df.to_csv(
    "simulated_attack.csv",
    index=False
)

print("Simulated attack dataset created!")
print("Total attack records:", len(attack_df))