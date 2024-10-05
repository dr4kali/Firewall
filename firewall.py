import os
import time
import dpkt
import socket
import netfilterqueue
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import psutil
import asyncio
import aiofiles
#comment
# File paths
RULES_FILE = "var/firewall/rules"
LOG_FILE = "var/firewall/log"

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

# Log packets
async def log_packet(action, src_ip, dst_ip, proto, sport=None, dport=None):
    """ Logs packet information to a file asynchronously. """
    log_entry = f"{time.ctime()} - {action}: {proto.upper()} {src_ip}:{sport or ''} -> {dst_ip}:{dport or ''}\n"
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

# Match packet with rules
# Match packet with rules
def packet_matches(src_ip, dst_ip, proto, dport, rules):
    """ Check if the packet matches any firewall rule. """
    src_ip_obj = ipaddress.ip_address(src_ip)
    dst_ip_obj = ipaddress.ip_address(dst_ip)

    for rule in rules:
        rule_src_ip = rule["src_ip"]
        rule_dst_ip = rule["dst_ip"]
        rule_proto = rule["protocol"]
        rule_dst_port = rule["dst_port"]

        # Convert rule IPs to IP address objects for comparison
        rule_src_ip_obj = ipaddress.ip_network(rule_src_ip, strict=False)
        rule_dst_ip_obj = ipaddress.ip_network(rule_dst_ip, strict=False)

        # Check if all criteria match for blocking
        if (src_ip_obj in rule_src_ip_obj and
            dst_ip_obj in rule_dst_ip_obj and
            proto == rule_proto and
            (proto not in ["tcp", "udp"] or (dport is not None and dport == rule_dst_port))):
            return True  # Block this packet if all conditions match

    # If no match is found in the rules, accept the packet
    return False  # Accept the packet if no rules match


# Process a packet based on the rules
async def process_packet(packet, packet_data, rules):
    """ Handles packet based on rules and logs actions. """
    try:
        # Extract packet details
        src_ip, dst_ip, proto, sport, dport = extract_packet_details(packet_data)

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
    """ Submit packet processing task to the thread pool asynchronously. """
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
    setup_queue()
