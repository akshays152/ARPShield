import pandas as pd

# All normal ARP capture sessions
files = [
    "arp_dataset.csv",
    "arp_dataset_v2.csv",
    "arp_capture_session_3.csv",
    "arp_capture_session_4.csv",
    "arp_capture_session_5.csv"
]

# Read and combine all capture sessions
datasets = []

for file in files:
    df = pd.read_csv(file)
    datasets.append(df)
    print(f"{file}: {len(df)} records")

normal_df = pd.concat(
    datasets,
    ignore_index=True
)

# Keep the schema consistent
FIELDS = [
    "timestamp",
    "sender_ip",
    "sender_mac",
    "target_ip",
    "target_mac",
    "operation"
]

normal_df = normal_df[FIELDS]

# Save the combined normal dataset
normal_df.to_csv(
    "normal_arp_dataset_v2.csv",
    index=False
)

print("\nNormal dataset v2 created successfully!")
print(f"Total normal records: {len(normal_df)}")
print(f"Dataset saved as: normal_arp_dataset_v2.csv")

print("\nSchema:")
print(normal_df.columns.tolist())