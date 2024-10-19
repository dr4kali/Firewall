import requests
import json
import time
import os
import logging
from datetime import datetime, timedelta
import sys
sys.path.append('etc/firewall/')
from config import API_KEY, Enable_Threat_Intelligence

# Check if Threat Intelligence is enabled
if not (hasattr(Enable_Threat_Intelligence, '__str__') and Enable_Threat_Intelligence.lower() == "yes"):
    print("Threat Intelligence feature is disabled. Exiting...")
    sys.exit(0)

# File paths for rules and last fetch time
RULES_FILE = os.path.join("var", "firewall", "rules")
LAST_FETCH_FILE = os.path.join("var", "firewall", "last_fetch_time.json")
LOG_FILE = os.path.join("var", "firewall", "output.log")

# Set up logging configuration
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# AbuseIPDB API endpoint and configuration
API_URL = 'https://api.abuseipdb.com/api/v2/blacklist'

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
    """Fetch blacklisted IPs from AbuseIPDB API."""
    try:
        response = requests.get(API_URL, headers=HEADERS, params=QUERYSTRING)
        response.raise_for_status()
        data = response.json()
        return data.get('data', [])[:5]  # Limit to the first 5 entries
    except Exception as e:
        logging.error(f"Error fetching data from AbuseIPDB: {e}")
        return []

# Load existing rules to check for duplicates
def load_existing_rules():
    """Load existing rules from the rules file."""
    existing_ips = set()
    try:
        with open(RULES_FILE, "r") as rules_file:
            for line in rules_file:
                if line.strip() and "src_ip" in line:
                    rule_parts = line.strip().split(",")
                    for part in rule_parts:
                        if "src_ip" in part:
                            ip = part.split(":")[1].strip()
                            existing_ips.add(ip)
    except FileNotFoundError:
        logging.warning(f"Rules file not found, creating a new one: {RULES_FILE}")
    return existing_ips

# Update firewall rules with new IPs, avoiding duplicates
def update_firewall_rules(blacklisted_ips):
    """Update firewall rules with new IPs."""
    existing_ips = load_existing_rules()
    new_rules_count = 0

    try:
        with open(RULES_FILE, "a") as rules_file:
            for entry in blacklisted_ips:
                ip_address = entry.get("ipAddress")
                if ip_address and ip_address not in existing_ips:
                    rule = f"src_ip: {ip_address}, dst_ip: 0.0.0.0, protocol: tcp, dst_port: -\n"
                    rules_file.write(rule)
                    new_rules_count += 1
        logging.info(f"Added {new_rules_count} new rules to {RULES_FILE}.")
    except Exception as e:
        logging.error(f"Error updating rules file: {e}")

# Check if it's time to fetch new data
def should_fetch_new_data():
    """Determine if new data should be fetched based on last fetch time."""
    if not os.path.exists(LAST_FETCH_FILE):
        return True, 0  # No record exists, fetch data

    with open(LAST_FETCH_FILE, "r") as f:
        data = json.load(f)

    last_fetch_datetime = datetime.fromisoformat(data['lastFetch'])
    fetch_count = data['fetchCount']
    now = datetime.now()

    new_day = now.date() > last_fetch_datetime.date()
    if new_day:
        fetch_count = 0  # Reset fetch count for a new day
    elif fetch_count >= 4:
        logging.info("Fetch limit reached for today. Skipping fetch.")
        return False, fetch_count  # Limit reached for the day

    return now >= last_fetch_datetime + timedelta(hours=6), fetch_count

# Update the last fetch time and fetch count
def update_last_fetch_time(fetch_count):
    """Update the last fetch time and fetch count."""
    now = datetime.now().isoformat()
    data = {
        'lastFetch': now,
        'fetchCount': fetch_count + 1
    }
    with open(LAST_FETCH_FILE, "w") as f:
        json.dump(data, f)

# Main script function
def main():
    """Main function for fetching and updating rules."""
    should_fetch, fetch_count = should_fetch_new_data()
    
    if should_fetch:
        blacklisted_ips = fetch_abuseip_data()
        if blacklisted_ips:
            update_firewall_rules(blacklisted_ips)
            update_last_fetch_time(fetch_count)  # Update the last fetch time and count
        else:
            logging.warning("No blacklisted IPs fetched. Skipping update.")

# Run the script in a loop
if __name__ == "__main__":
    try:
        while True:
            main()
            time.sleep(600)  # Sleep for 10 minutes before checking again
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
        sys.exit(0)
