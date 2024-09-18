import os
import time
import netfilterqueue
import scapy.all as scapy

# File paths for firewall rules and log files
RULES_FILE = "firewall_rules.txt"
LOG_FILE = "firewall_log.txt"

# Load rules once at the start to avoid repeated file I/O operations
def load_rules():
    rules = []
    with open(RULES_FILE, "r") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):  # Skip empty lines and comments
                rule_parts = [part.split(":") for part in line.strip().split(",")]
                rule_dict = {key.strip(): (None if value.strip() == "-" else (int(value.strip()) if key.strip() == "dst_port" else value.strip())) 
                             for key, value in rule_parts}
                rules.append(rule_dict)
    return rules

# Log only blocked packets
def log_blocked_packet(packet_info_list):
    with open(LOG_FILE, "a") as log_file:
        log_file.write("\n".join(packet_info_list) + "\n")

# Generate log entry for blocked packet
def generate_blocked_log_entry(packet, scapy_pkt, proto):
    try:
        if proto == "TCP":
            info = f"{proto} {scapy_pkt.src}:{scapy_pkt[scapy.TCP].sport} -> {scapy_pkt.dst}:{scapy_pkt[scapy.TCP].dport}"
        elif proto == "UDP":
            info = f"{proto} {scapy_pkt.src}:{scapy_pkt[scapy.UDP].sport} -> {scapy_pkt.dst}:{scapy_pkt[scapy.UDP].dport}"
        elif proto == "ICMP":
            info = f"{proto} {scapy_pkt.src} -> {scapy_pkt.dst} (type: {scapy_pkt[scapy.ICMP].type})"
        else:
            info = f"Unknown protocol {scapy_pkt.proto}"

        return f"{time.ctime()}: Blocked {info}, {len(packet.get_payload())} bytes"
    except Exception as e:
        return f"{time.ctime()}: Error logging packet: {e}"

# Check if the packet matches the rules (optimized for clarity and efficiency)
def packet_matches(scapy_pkt, rules, proto, dport):
    for rule in rules:
        if rule["src_ip"] == scapy_pkt.src and rule["dst_ip"] == scapy_pkt.dst and rule["protocol"] == proto:
            if proto in ["tcp", "udp"] and dport == rule["dst_port"]:
                return True
            if proto == "icmp":  # No port for ICMP
                return True
    return False

# Callback function to process packets (optimized with preloaded rules)
def process_packet(packet, rules):
    try:
        ip_packet = packet.get_payload()  # Extract raw packet
        scapy_pkt = scapy.IP(ip_packet)  # Convert to Scapy format

        proto = None
        dport = None

        # Determine protocol and destination port
        if scapy_pkt.proto == 6:  # TCP
            proto = "tcp"
            dport = scapy_pkt[scapy.TCP].dport
        elif scapy_pkt.proto == 17:  # UDP
            proto = "udp"
            dport = scapy_pkt[scapy.UDP].dport
        elif scapy_pkt.proto == 1:  # ICMP
            proto = "icmp"

        # Process matching and log only blocked packets
        log_entries = []
        if proto and packet_matches(scapy_pkt, rules, proto, dport):
            log_entries.append(generate_blocked_log_entry(packet, scapy_pkt, proto.upper()))
            packet.drop()  # Block packet
            log_blocked_packet(log_entries)  # Log only blocked packets
        else:
            packet.accept()  # Allow packet
    except Exception as e:
        log_blocked_packet([f"{time.ctime()}: Error processing packet: {e}"])
        packet.accept()  # In case of error, allow the packet

# Set up the Netfilter Queue and bind processing function (preloads rules)
def setup_queue():
    rules = load_rules()  # Preload rules once

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, lambda pkt: process_packet(pkt, rules))

    try:
        queue.run()
    except KeyboardInterrupt:
        print("Stopping firewall...")

# Main execution
if __name__ == "__main__":
    setup_queue()
