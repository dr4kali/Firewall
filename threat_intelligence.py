import requests
import json
import time
import os
from datetime import datetime, timedelta

# File path for rules and last fetch time
RULES_FILE = "var/firewall/rules"
LAST_FETCH_FILE = "var/firewall/last_fetch_time.json"

# AbuseIPDB API endpoint and configuration
API_URL = 'https://api.abuseipdb.com/api/v2/blacklist'
API_KEY = '1a484b965a1c6c836d3bbb78376d8817ab86ab36116f64725f5fed1b73db8472f4ef756f840ddec1'

# Define query parameters (e.g., minimum confidence score)
QUERYSTRING = {
    'confidenceMinimum': '100'
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
        return data.get('data', [])[:5]  # Limit to the first 5 entries
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
                    rule = f"src_ip: {ip_address}, dst_ip: 0.0.0.0, protocol: tcp, dst_port: -\n"
                    rules_file.write(rule)
                    new_rules_count += 1
        print(f"Added {new_rules_count} new rules to {RULES_FILE}.")
    except Exception as e:
        print(f"Error updating rules file: {e}")

# Check if it's time to fetch new data
def should_fetch_new_data():
    if not os.path.exists(LAST_FETCH_FILE):
        return True, 0  # No record exists, fetch data

    with open(LAST_FETCH_FILE, "r") as f:
        data = json.load(f)

    last_fetch_datetime = datetime.fromisoformat(data['lastFetch'])
    fetch_count = data['fetchCount']
    now = datetime.now()

    # Check if a new day has started or if 6 hours have passed since the last fetch
    new_day = now.date() > last_fetch_datetime.date()
    if new_day:
        fetch_count = 0  # Reset fetch count for a new day
    elif fetch_count >= 4:
        return False, fetch_count  # Limit reached for the day

    return now >= last_fetch_datetime + timedelta(hours=6), fetch_count

# Update the last fetch time and fetch count
def update_last_fetch_time(fetch_count):
    now = datetime.now().isoformat()
    data = {
        'lastFetch': now,
        'fetchCount': fetch_count + 1
    }
    with open(LAST_FETCH_FILE, "w") as f:
        json.dump(data, f)

# Main script function
def main():
    should_fetch, fetch_count = should_fetch_new_data()
    
    if should_fetch:
        # Fetch blacklisted IPs from AbuseIPDB
        blacklisted_ips = fetch_abuseip_data()

        if blacklisted_ips:
            # Update firewall rules with fetched IPs, avoiding duplicates
            update_firewall_rules(blacklisted_ips)
            update_last_fetch_time(fetch_count)  # Update the last fetch time and count

    # Sleep for a bit before checking again, to avoid busy-waiting
    time.sleep(600)  # Sleep for 10 minutes before checking again

if __name__ == "__main__":
    main()
