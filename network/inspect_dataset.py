import pandas as pd

file_path = r"D:\ARPShield_Data\raw\CSV\ARP + Command Injection_1200_labled.csv"

# Read only the ARP-related columns
cols = [
    "Time",
    "Source_IP",
    "Destination_IP",
    "Source_MAC",
    "Destination_MAC",
    "ARP_OPCode",
    "ARP_Attack"
]

df = pd.read_csv(file_path, usecols=cols)

print("\nDataset shape:")
print(df.shape)

print("\nARP Attack labels:")
print(df["ARP_Attack"].value_counts(dropna=False))

print("\nARP Opcode:")
print(df["ARP_OPCode"].value_counts(dropna=False))

print("\nAttack records - unique IP/MAC mappings:")
print(
    df[df["ARP_Attack"] == "Attack"]
    [["Source_IP", "Destination_IP", "Source_MAC", "Destination_MAC", "ARP_OPCode"]]
    .drop_duplicates()
    .to_string(index=False)
)
print("\nAttack distribution by Source IP:")
print(df[df["ARP_Attack"] == "Attack"]["Source_IP"].value_counts())

print("\nAttack distribution by ARP Opcode:")
print(df[df["ARP_Attack"] == "Attack"]["ARP_OPCode"].value_counts(dropna=False))
print("\nNormal ARP records:")
normal_arp = df[
    (df["ARP_Attack"] == "Normal") &
    (df["ARP_OPCode"].notna())
]

print(normal_arp["ARP_OPCode"].value_counts())

print("\nNormal ARP unique mappings:")
print(
    normal_arp[
        ["Source_IP", "Destination_IP", "Source_MAC", "Destination_MAC", "ARP_OPCode"]
    ]
    .drop_duplicates()
    .head(30)
    .to_string(index=False)
)