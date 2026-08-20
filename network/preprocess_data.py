import pandas as pd

# Load the normal ARP traffic dataset
normal_data = pd.read_csv("arp_dataset.csv")

# Label normal traffic as 0
normal_data["label"] = 0

# Load the simulated ARP spoofing dataset
spoofed_data = pd.read_csv("simulated_attack.csv")

# Label spoofed traffic as 1
spoofed_data["label"] = 1

# Combine both datasets
dataset = pd.concat(
    [normal_data, spoofed_data],
    ignore_index=True
)

# Shuffle the dataset
dataset = dataset.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# Save final dataset
dataset.to_csv(
    "final_arp_dataset.csv",
    index=False
)

print("Dataset preparation complete!")
print("Total records:", len(dataset))

print("\nClass distribution:")
print(dataset["label"].value_counts())

print("\nFinal dataset saved as: final_arp_dataset.csv")
