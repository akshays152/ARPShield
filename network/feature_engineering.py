import pandas as pd

# Load the combined dataset
df = pd.read_csv("final_arp_dataset.csv")

print("--- FEATURE ENGINEERING ---")
print("Original dataset shape:", df.shape)

# Convert ARP operation into numbers
# request = 0, reply = 1
df["operation"] = df["operation"].map({
    "request": 0,
    "reply": 1
})

# Check whether the target IP is unspecified
df["is_unspecified_target"] = (
    df["target_ip"] == "0.0.0.0"
).astype(int)

# Check whether the target MAC is a broadcast address
df["is_broadcast_target"] = (
    df["target_mac"].str.lower() == "ff:ff:ff:ff:ff:ff"
).astype(int)

# Count how many unique MAC addresses are associated
# with each sender IP
df["macs_per_ip"] = (
    df.groupby("sender_ip")["sender_mac"]
    .transform("nunique")
)

# Count how frequently each sender IP appears
df["sender_ip_frequency"] = (
    df.groupby("sender_ip")["sender_ip"]
    .transform("count")
)

# Convert timestamp into time-based features
df["timestamp"] = pd.to_datetime(df["timestamp"])

df["hour"] = df["timestamp"].dt.hour
df["minute"] = df["timestamp"].dt.minute
df["second"] = df["timestamp"].dt.second

# Remove raw values that we are not directly using as ML features
df = df.drop(columns=[
    "timestamp",
    "sender_ip",
    "sender_mac",
    "target_ip",
    "target_mac"
])

# Save the engineered dataset
df.to_csv("engineered_arp_dataset.csv", index=False)

print("\nFeature engineering complete!")
print("New dataset shape:", df.shape)

print("\nFeatures created:")
print(df.columns.tolist())

print("\nDataset saved as: engineered_arp_dataset.csv")