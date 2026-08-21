import pandas as pd
import random

# Load the combined normal ARP dataset
df = pd.read_csv("normal_arp_dataset_v2.csv")

attack_data = []

# Get existing MAC addresses from real captured traffic
existing_macs = df["sender_mac"].dropna().unique().tolist()

# Generate simulated suspicious IP-MAC mappings
NUM_ATTACKS = 4000

for i in range(NUM_ATTACKS):

    # Pick a real normal ARP record
    row = df.sample(n=1).iloc[0]

    # Choose a different MAC address already observed
    possible_macs = [
        mac for mac in existing_macs
        if mac != row["sender_mac"]
    ]

    spoofed_mac = random.choice(possible_macs)

    # Same IP associated with a different observed MAC
    attack_data.append([
        row["timestamp"],
        row["sender_ip"],
        spoofed_mac,
        row["target_ip"],
        row["target_mac"],
        "reply",
        1,
        "simulated_attack"
    ])

# Create attack DataFrame
attack_df = pd.DataFrame(
    attack_data,
    columns=[
        "timestamp",
        "sender_ip",
        "sender_mac",
        "target_ip",
        "target_mac",
        "operation",
        "label",
        "record_type"
    ]
)

# Save without overwriting previous versions
attack_df.to_csv(
    "simulated_attack_dataset_v2.csv",
    index=False
)

print("Simulated ARP attack v2 dataset created!")
print("Total simulated attack records:", len(attack_df))
print("Dataset saved as: simulated_attack_dataset_v2.csv")