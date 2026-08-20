import csv
from collections import defaultdict

filename = input("Enter the dataset filename: ")

ip_mac_mapping = defaultdict(set)

try:
    with open(filename, "r") as file:
        reader = csv.DictReader(file)

        for row in reader:
            sender_ip = row["sender_ip"]
            sender_mac = row["sender_mac"]

            # Ignore special/invalid IP address
            if sender_ip == "0.0.0.0":
                continue

            ip_mac_mapping[sender_ip].add(sender_mac)

    print("\n--- ARP SPOOFING DETECTION RESULTS ---\n")

    suspicious_found = False

    for ip, mac_addresses in ip_mac_mapping.items():
        if len(mac_addresses) > 1:
            suspicious_found = True

            print("[ALERT] Possible ARP Spoofing!")
            print(f"IP Address: {ip}")
            print(f"Associated MAC Addresses: {', '.join(mac_addresses)}\n")

    if not suspicious_found:
        print("No suspicious IP-to-MAC conflicts detected.")

except FileNotFoundError:
    print("Error: File not found.")