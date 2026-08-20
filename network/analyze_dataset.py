import csv
from collections import Counter

total_packets = 0
operations = Counter()
source_ips = set()
source_macs = set()
special_ips = Counter()

with open("arp_dataset.csv", "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        total_packets += 1

        operations[row["operation"]] += 1
        source_ips.add(row["sender_ip"])
        source_macs.add(row["sender_mac"])

        if row["sender_ip"] == "0.0.0.0":
            special_ips["0.0.0.0"] += 1


print("\n--- ARP DATASET ANALYSIS ---\n")

print(f"Total packets: {total_packets}")

print("\nARP Operations:")
for operation, count in operations.items():
    print(f"  {operation}: {count}")

print(f"\nUnique source IP addresses: {len(source_ips)}")
print(f"Unique source MAC addresses: {len(source_macs)}")

print("\nSpecial/unspecified IP entries:")
print(f"  0.0.0.0: {special_ips['0.0.0.0']}")

print("\nDataset analysis complete.")