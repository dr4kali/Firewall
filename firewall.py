import pickle
import os
import time
import dpkt
import socket
import netfilterqueue
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import psutil
from scapy.all import sniff  # Importing sniff function from scapy

RULES_FILE = "var/firewall/rules"
LOG_FILE = "var/firewall/log"

def sniff_on_interface(interface):
    """ Sniff packets on the given interface. """
    sniff(iface=interface, prn=lambda x: handle_packet(x, interface), store=0)

def load_rules():
    """ Load firewall rules from a specified file. """
    rules = []
    with open(RULES_FILE, "r") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):  # Skip empty lines and comments
                rule_parts = [part.split(":") for part in line.strip().split(",")]
                rule_dict = {key.strip(): (None if value.strip() == "-" else (int(value.strip()) if key.strip() == "dst_port" else value.strip())) 
                             for key, value in rule_parts}
                rules.append(rule_dict)
    return rules

def log_packet(packet_info_list):
    """ Log packet information to the log file. """
    with open(LOG_FILE, "a") as log_file:
        log_file.write("\n".join(packet_info_list) + "\n")

def generate_log_entry(src_ip, dst_ip, proto, sport, dport, action):
    """ Generate a log entry for a packet. """
    try:
        if proto == "TCP":
            info = f"{proto} {src_ip}:{sport} -> {dst_ip}:{dport}"
        elif proto == "UDP":
            info = f"{proto} {src_ip}:{sport} -> {dst_ip}:{dport}"
        elif proto == "ICMP":
            info = f"{proto} {src_ip} -> {dst_ip} (ICMP)"
        else:
            info = f"Unknown protocol {proto}"

        return f"{time.ctime()}: {action} {info}"
    except Exception as e:
        return f"{time.ctime()}: Error logging packet: {e}"

def packet_matches(src_ip, dst_ip, proto, dport, rules):
    """ Check if the packet matches any defined firewall rules. """
    src_ip_obj = ipaddress.ip_address(src_ip)
    dst_ip_obj = ipaddress.ip_address(dst_ip)

    for rule in rules:
        rule_src_ip = rule["src_ip"]
        rule_dst_ip = rule["dst_ip"]

        rule_src_ip_obj = ipaddress.ip_network(rule_src_ip, strict=False)
        rule_dst_ip_obj = ipaddress.ip_network(rule_dst_ip, strict=False)

        if src_ip_obj in rule_src_ip_obj and dst_ip_obj in rule_dst_ip_obj and rule["protocol"] == proto:
            if proto in ["tcp", "udp"] and dport == rule["dst_port"]:
                return True
            if proto == "icmp":
                return True
    return False

def extract_packet_details(packet_data):
    """ Extract details from the packet. """
    ip_packet = dpkt.ip.IP(packet_data)  # Convert raw packet to dpkt IP object
    src_ip = socket.inet_ntoa(ip_packet.src)
    dst_ip = socket.inet_ntoa(ip_packet.dst)
    proto = None
    sport = None
    dport = None

    # Determine protocol and destination port
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

def process_packet_logic(packet, packet_data, rules):
    """ Logic for processing the packet. """
    try:
        # Extract packet details using dpkt
        src_ip, dst_ip, proto, sport, dport = extract_packet_details(packet_data)

        log_entries = []
        if proto and packet_matches(src_ip, dst_ip, proto, dport, rules):
            log_entries.append(generate_log_entry(src_ip, dst_ip, proto.upper(), sport, dport, "Blocked"))
            log_packet(log_entries)
            packet.drop()  # Block packet
        else:
            packet.accept()  # Allow packet

        # Log only blocked packets
        if log_entries:
            log_packet(log_entries)
    except Exception as e:
        log_packet([f"{time.ctime()}: Error processing packet: {e}"])
        packet.accept()  # In case of error, allow the packet

def process_packet(packet, rules, executor):
    """ Submit packet processing to the thread pool. """
    packet_data = packet.get_payload()
    # Submit packet processing to the thread pool for parallel execution
    executor.submit(process_packet_logic, packet, packet_data, rules)

def setup_queue():
    """ Set up the packet queue for processing. """
    rules = load_rules()  # Preload rules once

    queue = netfilterqueue.NetfilterQueue()
    
    # Create a thread pool to process packets in parallel
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        queue.bind(0, lambda pkt: process_packet(pkt, rules, executor))
        
        try:
            queue.run()
        except KeyboardInterrupt:
            print("Stopping firewall...")

# Main execution
if __name__ == "__main__":
    interfaces = psutil.net_if_addrs()  # Get network interfaces
    for interface in interfaces:
        sniff_on_interface(interface)
    setup_queue()
