import os

import time

import netfilterqueue

import scapy.all as scapy



# File that contains firewall rules

RULES_FILE = "firewall_rules.txt"

LOG_FILE = "firewall_log.txt"



# Load rules from the file

def load_rules():

    rules = []

    with open("firewall_rules.txt", "r") as f:

        for line in f:

            if line.strip() and not line.startswith("#"):  # Skip empty lines and comments

                rule_parts = line.strip().split(",")

                rule_dict = {}

                for part in rule_parts:

                    key, value = part.split(":")

                    key = key.strip()

                    value = value.strip()

                    if key == "dst_port" and value == "-":

                        rule_dict[key] = None  # Handle missing port

                    else:

                        rule_dict[key] = value if key != "dst_port" else int(value)

                rules.append(rule_dict)

    return rules



# Log network activity with detailed packet information

def log_packet(packet, action):

    try:

        ip_packet = packet.get_payload()  # Extract raw packet

        scapy_pkt = scapy.IP(ip_packet)  # Convert to Scapy format

        proto = None

        packet_info = ""



        if scapy_pkt.proto == 6:  # TCP

            proto = "TCP"

            packet_info = f"{proto} {scapy_pkt.src}:{scapy_pkt[scapy.TCP].sport} -> {scapy_pkt.dst}:{scapy_pkt[scapy.TCP].dport}"

        elif scapy_pkt.proto == 17:  # UDP

            proto = "UDP"

            packet_info = f"{proto} {scapy_pkt.src}:{scapy_pkt[scapy.UDP].sport} -> {scapy_pkt.dst}:{scapy_pkt[scapy.UDP].dport}"

        elif scapy_pkt.proto == 1:  # ICMP

            proto = "ICMP"

            packet_info = f"{proto} {scapy_pkt.src} -> {scapy_pkt.dst} (type: {scapy_pkt[scapy.ICMP].type})"

        else:

            packet_info = f"Unknown protocol {scapy_pkt.proto}"



        log_entry = f"{time.ctime()}: {action} {packet_info}, {len(ip_packet)} bytes"



        with open(LOG_FILE, "a") as log_file:

            log_file.write(log_entry + "\n")

    except Exception as e:

        with open(LOG_FILE, "a") as log_file:

            log_file.write(f"{time.ctime()}: Error logging packet: {e}\n")



# Check if the packet matches the rules

def packet_matches(packet, rules):

    try:

        ip_packet = packet.get_payload()  # Extract raw packet

        scapy_pkt = scapy.IP(ip_packet)  # Convert to Scapy format

        proto = None

        

        if scapy_pkt.proto == 6:  # TCP

            proto = "tcp"

            sport = scapy_pkt[scapy.TCP].sport

            dport = scapy_pkt[scapy.TCP].dport

        elif scapy_pkt.proto == 17:  # UDP

            proto = "udp"

            sport = scapy_pkt[scapy.UDP].sport

            dport = scapy_pkt[scapy.UDP].dport

        elif scapy_pkt.proto == 1:  # ICMP

            proto = "icmp"

            dport = None  # ICMP doesn't use ports

        else:

            return False

        for rule in rules:

            if rule["src_ip"] == scapy_pkt.src and rule["dst_ip"] == scapy_pkt.dst:

                if rule["protocol"] == proto:

                    if proto in ["tcp", "udp"] and dport == rule["dst_port"]:

                        return True

                    if proto == "icmp":  # No port for ICMP

                        return True

    except Exception as e:

        log_packet(packet, f"Error processing packet: {e}")

        return False

    return False



# Callback function to process the packets

def process_packet(packet):

    rules = load_rules()

    if packet_matches(packet, rules):

        log_packet(packet, "Blocked")

        packet.drop()

    else:

        log_packet(packet, "Allowed")

        packet.accept()



# Set up the Netfilter Queue

def setup_queue():

    queue = netfilterqueue.NetfilterQueue()

    queue.bind(0, process_packet)

    try:

        queue.run()

    except KeyboardInterrupt:

        print("Stopping firewall...")



# Main execution

if __name__ == "__main__":

    setup_queue()

