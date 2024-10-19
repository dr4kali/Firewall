import os
import time
import dpkt
import socket
import netfilterqueue
import asyncio
import aiofiles
import ipaddress
import psutil
from concurrent.futures import ThreadPoolExecutor
from rate_limiter import rate_limiter

# File paths
RULES_FILE = "var/firewall/rules"
LOG_FILE = "var/firewall/log"

# Define threshold limits
CPU_THRESHOLD = 90  # for testing
MEMORY_THRESHOLD = 90  # for testing

# Log performance alerts
async def log_alert(message):
    async with aiofiles.open("var/firewall/output.log", "a") as log_file:
        await log_file.write(f"{time.ctime()} - ALERT: {message}\n")

# Check system performance
async def monitor_system():
    while True:
        # CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        if cpu_usage > CPU_THRESHOLD:
            await log_alert(f"CPU usage exceeded: {cpu_usage}%")

        # Memory usage
        memory_info = psutil.virtual_memory()
        memory_usage = memory_info.percent
        if memory_usage > MEMORY_THRESHOLD:
            await log_alert(f"Memory usage exceeded: {memory_usage}%")

        await asyncio.sleep(60)
        
# Load firewall rules
def load_rules():
    rules = []
    if not os.path.exists(RULES_FILE):
        print(f"Rules file not found: {RULES_FILE}")
        return rules

    with open(RULES_FILE, "r") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                rule_parts = [part.split(":") for part in line.strip().split(",")]
                
                # Check if each rule part has exactly two elements
                if any(len(part) != 2 for part in rule_parts):
                    print(f"Skipping malformed rule: {line.strip()}")
                    continue  # Skip malformed lines

                rule_dict = {key.strip(): (None if value.strip() == "-" else (int(value.strip()) if key.strip() == "dst_port" else value.strip())) 
                             for key, value in rule_parts}
                rules.append(rule_dict)
    return rules


# Log packets (no change)
async def log_packet(action, src_ip, dst_ip, proto, sport=None, dport=None):
    log_entry = f"{time.ctime()} - {action}: {proto.upper()} {src_ip}:{sport or ''} -> {dst_ip}:{dport or ''}\n"
    async with aiofiles.open(LOG_FILE, "a") as log_file:
        await log_file.write(log_entry)

# Extract packet details (no change)
def extract_packet_details(packet_data):
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

# Match packet with rules (no change)
def packet_matches(src_ip, dst_ip, proto, dport, rules):
    src_ip_obj = ipaddress.ip_address(src_ip)
    dst_ip_obj = ipaddress.ip_address(dst_ip)

    for rule in rules:
        rule_src_ip = rule["src_ip"]
        rule_dst_ip = rule["dst_ip"]
        rule_proto = rule["protocol"]
        rule_dst_port = rule["dst_port"]

        rule_src_ip_obj = ipaddress.ip_network(rule_src_ip, strict=False)
        rule_dst_ip_obj = ipaddress.ip_network(rule_dst_ip, strict=False)

        if (src_ip_obj in rule_src_ip_obj and
            dst_ip_obj in rule_dst_ip_obj and
            proto == rule_proto and
            (proto not in ["tcp", "udp"] or (dport is not None and dport == rule_dst_port))):
            return True

    return False

# Process a packet in a thread
def process_packet(packet, packet_data, rules):
    src_ip, dst_ip, proto, sport, dport = extract_packet_details(packet_data)
    
    # Call rate limiter to check if IP should be blocked
    if not rate_limiter(src_ip):
        asyncio.run(log_packet("Blocked due to DDoS", src_ip, dst_ip, proto, sport, dport))
        packet.drop()  # Block packet
        return
    if proto and packet_matches(src_ip, dst_ip, proto, dport, rules):
        asyncio.run(log_packet("Blocked", src_ip, dst_ip, proto, sport, dport))
        packet.drop()  # Block packet
    else:
        packet.accept()  # Allow packet

# Set up packet queue
def setup_queue():
    rules = load_rules()

    queue = netfilterqueue.NetfilterQueue()

    # Use ThreadPoolExecutor for handling CPU-bound tasks
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        queue.bind(0, lambda pkt: executor.submit(process_packet, pkt, pkt.get_payload(), rules))

        print("Queue running, waiting for packets...")
        try:
            queue.run()
        except KeyboardInterrupt:
            print("Firewall stopped.")

async def main():
    # Run the firewall setup and monitoring system concurrently
    firewall_task = asyncio.to_thread(setup_queue)  # Run the firewall in a thread
    monitor_task = monitor_system()  # Run system monitoring
    
    await asyncio.gather(firewall_task, monitor_task)

if __name__ == "__main__":
    asyncio.run(main())
