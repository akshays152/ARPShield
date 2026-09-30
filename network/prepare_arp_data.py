import pandas as pd

file_path = r"D:\ARPShield_Data\processed\arp_raw.csv"

df = pd.read_csv(file_path)

print("Shape:", df.shape)

print("\nMissing values:")
print(df.isnull().sum())

print("\nDuplicate rows:")
print(df.duplicated().sum())
print("\nUnique Source IP -> Source MAC mappings:")
print(
    df.groupby("Source_IP")["Source_MAC"]
    .nunique()
    .sort_values(ascending=False)
    .head(20)
)
print("\nIPs with multiple Source MACs (excluding 0.0.0.0):")

mapping = (
    df[df["Source_IP"] != "0.0.0.0"]
    .groupby("Source_IP")["Source_MAC"]
    .nunique()
)

print(mapping[mapping > 1])
# Create final cleaned dataset
final_df = df.rename(columns={
    "Time": "timestamp",
    "Source_IP": "source_ip",
    "Destination_IP": "destination_ip",
    "Source_MAC": "source_mac",
    "Destination_MAC": "destination_mac",
    "ARP_OPCode": "arp_opcode",
    "ARP_Attack": "label"
})

# Add ARP type
final_df["arp_type"] = final_df["arp_opcode"].map({
    1: "Request",
    2: "Reply"
})

output_path = r"D:\ARPShield_Data\processed\final_arp_dataset.csv"

final_df.to_csv(output_path, index=False)

print("Final dataset created!")
print("Shape:", final_df.shape)
print("ARP types:")
print(final_df["arp_type"].value_counts())
print("Saved to:", output_path)