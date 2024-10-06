import requests
import json
import time

# File path for rules
RULES_FILE = "var/firewall/rules"

# AbuseIPDB API endpoint and configuration
API_URL = 'https://api.abuseipdb.com/api/v2/blacklist'
API_KEY = 'f3e2c91e30cd3ec7ffd38a7dbd748858f53dc50b92b5266186453466f929b45068fa24f060ffbaa4'

# Define query parameters (e.g., minimum confidence score)
QUERYSTRING = {
    'confidenceMinimum': '95'
}

HEADERS = {
    'Accept': 'application/json',
    'Key': API_KEY
}

# Fetch data from AbuseIPDB
def fetch_abuseip_data():
    try:
        response = requests.get(API_URL, headers=HEADERS, params=QUERYSTRING)
        response.raise_for_status()
        data = response.json()
        return data.get('data', [])
    except Exception as e:
        print(f"Error fetching data from AbuseIPDB: {e}")
        return []

# Load existing rules to check for duplicates
def load_existing_rules():
    existing_ips = set()
    try:
        with open(RULES_FILE, "r") as rules_file:
            for line in rules_file:
                if line.strip() and "src_ip" in line:
                    # Extract the IP address from each rule
                    rule_parts = line.strip().split(",")
                    for part in rule_parts:
                        if "src_ip" in part:
                            ip = part.split(":")[1].strip()
                            existing_ips.add(ip)
    except FileNotFoundError:
        print(f"Rules file not found, creating a new one: {RULES_FILE}")
    return existing_ips

# Update firewall rules with new IPs, avoiding duplicates
def update_firewall_rules(blacklisted_ips):
    existing_ips = load_existing_rules()
    new_rules_count = 0

    try:
        with open(RULES_FILE, "a") as rules_file:  # Append new rules to the file
            for entry in blacklisted_ips:
                ip_address = entry.get("ipAddress")
                if ip_address and ip_address not in existing_ips:
                    # Write the new rule if it's not a duplicate
                    rule = f"src_ip: {ip_address}, dst_ip: 0.0.0.0, protocol: tcp, dst_port: -\n"  # Modify rule format as needed
                    rules_file.write(rule)
                    new_rules_count += 1
        print(f"Added {new_rules_count} new rules to {RULES_FILE}.")
    except Exception as e:
        print(f"Error updating rules file: {e}")

# Main script function
def main():
    while True:
        # Fetch blacklisted IPs from AbuseIPDB
        blacklisted_ips = fetch_abuseip_data()

        if blacklisted_ips:
            # Update firewall rules with fetched IPs, avoiding duplicates
            update_firewall_rules(blacklisted_ips)

        # Sleep for an hour before the next update
        time.sleep(21600)  # Sleep for 1 hour (3600 seconds)

if __name__ == "__main__":
    main()
