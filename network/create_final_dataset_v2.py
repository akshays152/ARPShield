import pandas as pd

# Load normal ARP traffic
normal_df = pd.read_csv("normal_arp_dataset_v2.csv")

# Load simulated attack traffic
attack_df = pd.read_csv("simulated_attack_dataset_v2.csv")

# Add labels and record types to normal traffic
normal_df["label"] = 0
normal_df["record_type"] = "normal"

# Ensure attack traffic has correct labels and record types
attack_df["label"] = 1
attack_df["record_type"] = "simulated_attack"

# Combine both datasets
final_df = pd.concat(
    [normal_df, attack_df],
    ignore_index=True
)

# Shuffle records so normal and attack samples are mixed
final_df = final_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# Save final v2 dataset
final_df.to_csv(
    "final_arp_dataset_v2.csv",
    index=False
)

print("Final ARP dataset v2 created successfully!")
print(f"Total records: {len(final_df)}")

print("\nClass distribution:")
print(final_df["label"].value_counts())

print("\nRecord types:")
print(final_df["record_type"].value_counts())

print("\nDataset saved as: final_arp_dataset_v2.csv")