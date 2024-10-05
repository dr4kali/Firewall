import os
import time
import dpkt
import socket
import netfilterqueue
import ipaddress
import psutil
import asyncio
import aiofiles
import httpx  # For making API calls
from collections import defaultdict
from datetime import datetime, timedelta

# File paths
RULES_FILE = "var/firewall/rules"
LOG_FILE = "var/firewall/log"
THREAT_FEED_UPDATE_INTERVAL = 3600  # 1 hour

# Threat Intelligence API details (e.g., AbuseIPDB)
THREAT_FEED_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"
API_KEY = "f3e2c91e30cd3ec7ffd38a7dbd748858f53dc50b92b5266186453466f929b45068fa24f060ffbaa4"

# In-memory data structures
ips_signatures = set()  # Using set for fast O(1) lookups
blocked_ips = defaultdict(lambda: {'count': 0, 'timestamp': datetime.now()})

# Load firewall rules
def load_rules():
    """ Load firewall rules from a specified file. """
    rules = []
    if not os.path.exists(RULES_FILE):
        print(f"Rules file not found: {RULES_FILE}")
        return rules

    with open(RULES_FILE, "r") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                rule_parts = [part.split(":") for part in line.strip().split(",")]
                rule_dict = {key.strip(): (None if value.strip() == "-" else (int(value.strip()) if key.strip() == "dst_port" else value.strip())) 
                             for key, value in rule_parts}
                rules.append(rule_dict)
    return rules

# Fetch data from an external threat feed API
async def fetch_threat_feed():
    """ Fetch the latest threat feed from an external API. """
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(THREAT_FEED_API_URL, headers=headers)
            if response.status_code == 200:
                threat_data = response.json()
                malicious_ips = [entry['ipAddress'] for entry in threat_data['data']]  # Modify based on API format
                return malicious_ips
            else:
                print(f"Failed to fetch threat feed: {response.status_code}")
                return []
    except Exception as e:
        print(f"Error fetching threat feed: {e}")
        return []

# Periodically update signatures from a threat feed
async def update_threat_feed():
    """ Periodically update signatures from an external threat feed. """
    while True:
        threat_ips = await fetch_threat_feed()
        if threat_ips:
            ips_signatures.update(threat_ips)  # Add new IPs to the signature set
            print(f"Threat feed updated with {len(threat_ips)} new malicious IPs.")
        else:
            print("No new threat feed data.")

        await asyncio.sleep(THREAT_FEED_UPDATE_INTERVAL)

# Log packets or alerts
async def log_packet(action, src_ip, dst_ip, proto, sport=None, dport=None, is_alert=False):
    """ Logs packet or alert information to a file asynchronously. """
    log_entry = f"{time.ctime()} - {'ALERT' if is_alert else action}: {proto.upper()} {src_ip}:{sport or ''} -> {dst_ip}:{dport or ''}\n"
    async with aiofiles.open(LOG_FILE, "a") as log_file:
        await log_file.write(log_entry)

# Extract packet details
def extract_packet_details(packet_data):
    """ Extract details from the packet. """
    ip_packet = dpkt.ip.IP(packet_data)
    src_ip = socket.inet_ntoa(ip_packet.src)
    dst_ip = socket.inet_ntoa(ip_packet.dst)
    proto, sport, dport = None, None, None

    if isinstance(ip_packet.data, dpkt.tcp.TCP):
        proto = "tcp"
        sport = ip_packet.data.sport
        dport = ip_packet.data.dport
    elif isinstance(ip_packet.data, dpkt.udp.UDP):
        proto = "udp"
        sport = ip_packet.data.sport
        dport = ip_packet.data.dport
    elif isinstance(ip_packet.data, dpkt.icmp.ICMP):
        proto = "icmp"

    return src_ip, dst_ip, proto, sport, dport

# Detect and prevent DDoS attacks (basic rate-limiting)
def rate_limit(src_ip):
    """ Detect and block IPs sending too many requests within a short time frame. """
    global blocked_ips
    now = datetime.now()
    if blocked_ips[src_ip]['count'] >= 100:  # Set threshold
        # Check if rate limit exceeded within 1 minute
        if now - blocked_ips[src_ip]['timestamp'] < timedelta(minutes=1):
            return True  # Block this IP
        else:
            blocked_ips[src_ip]['count'] = 0  # Reset after 1 minute
    blocked_ips[src_ip]['count'] += 1
    blocked_ips[src_ip]['timestamp'] = now
    return False

# IPS Detection based on signatures
def detect_intrusion(src_ip, dst_ip, proto):
    """ Detect if the packet matches any intrusion signature. """
    return src_ip in ips_signatures or dst_ip in ips_signatures or proto in ips_signatures

# Process a packet based on the rules and IPS signatures
async def process_packet(packet, packet_data, rules):
    """ Handles packet based on rules, IPS signatures, and rate-limiting, logs actions or alerts. """
    try:
        # Extract packet details
        src_ip, dst_ip, proto, sport, dport = extract_packet_details(packet_data)

        # Rate-limiting detection (DoS/DDoS)
        if rate_limit(src_ip):
            await log_packet("Blocked", src_ip, dst_ip, proto, sport, dport, is_alert=True)
            packet.drop()  # Drop rate-limited packets
            return

        # Check for IPS signature matches
        if detect_intrusion(src_ip, dst_ip, proto):
            await log_packet("Blocked", src_ip, dst_ip, proto, sport, dport, is_alert=True)
            packet.drop()  # Block malicious packet
            return

        # Check firewall rules
        if proto and packet_matches(src_ip, dst_ip, proto, dport, rules):
            await log_packet("Blocked", src_ip, dst_ip, proto, sport, dport)
            packet.drop()  # Block packet
        else:
            packet.accept()  # Allow packet

    except Exception as e:
        await log_packet("Error", src_ip, dst_ip, "unknown", None, None)
        packet.accept()  # Allow packet if an error occurs

# Queue and packet processing
async def process_packet_queue(packet, rules):
    """ Submit packet processing task asynchronously. """
    packet_data = packet.get_payload()
    await process_packet(packet, packet_data, rules)

# Set up packet queue
def setup_queue():
    """ Set up the NetfilterQueue for packet processing. """
    rules = load_rules()  # Load rules once

    queue = netfilterqueue.NetfilterQueue()
    loop = asyncio.get_event_loop()

    # Bind the processing function to the packet queue
    queue.bind(0, lambda pkt: loop.run_until_complete(process_packet_queue(pkt, rules)))

    print("Queue running, waiting for packets...")
    try:
        queue.run()
    except KeyboardInterrupt:
        print("Firewall stopped.")

# Main execution for sniffing and queue setup
if __name__ == "__main__":
    interfaces = psutil.net_if_addrs()  # Get network interfaces
    asyncio.run(update_threat_feed())  # Start the threat feed update loop
    setup_queue()
