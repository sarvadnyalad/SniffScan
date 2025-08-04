import argparse
import logging
from scapy.all import rdpcap, Raw, IP
from colorama import Fore, Style
import os

# Predefined list of sensitive keywords to search for in packet payloads
SENSITIVE_KEYWORDS = ["password", "admin", "login", "secret"]
SUSPICIOUS_IPS = []  # This will be populated from a file

# Load suspicious IP addresses from a file
def load_suspicious_ips(file_path="suspicious_ips.txt"):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return [line.strip() for line in f.readlines()]
    return []

# Append suspicious packet summary to the log file
def log_packet(packet, log_file):
    with open(log_file, "a") as f:
        f.write(packet.summary() + "\n")

# Analyze a single packet for suspicious patterns
def process_packet(packet, args):
    if packet.haslayer(IP):  # Ensure the packet has an IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Flag communication with suspicious IPs
        if src_ip in SUSPICIOUS_IPS or dst_ip in SUSPICIOUS_IPS:
            print(Fore.RED + f"[!] Communication with suspicious IP: {src_ip} -> {dst_ip}" + Style.RESET_ALL)
            log_packet(packet, args.log)

        # Check if the packet has a payload and search for sensitive keywords
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                for keyword in args.keywords:
                    if keyword.lower() in payload.lower():
                        print(Fore.YELLOW + f"[!] Keyword match '{keyword}' in packet from {src_ip}" + Style.RESET_ALL)
                        log_packet(packet, args.log)
                        break  # Stop after first keyword match
            except Exception:
                pass  # Ignore decoding errors gracefully

# Entry point for the script
def main():
    # Set up command-line arguments
    parser = argparse.ArgumentParser(description="Analyze PCAP file for suspicious traffic.")
    parser.add_argument("--pcap", required=True, help="Path to the PCAP file to analyze")
    parser.add_argument("--log", default="output/suspicious.log", help="Log file to save suspicious packets")
    parser.add_argument("--keywords", default="password,admin", help="Comma-separated keywords to scan in payloads")

    args = parser.parse_args()
    args.keywords = [k.strip().lower() for k in args.keywords.split(",")]

    # Make sure the output directory exists
    os.makedirs(os.path.dirname(args.log), exist_ok=True)

    # Load the list of suspicious IPs from file
    global SUSPICIOUS_IPS
    SUSPICIOUS_IPS = load_suspicious_ips()

    print(Fore.CYAN + "[*] Reading packets from: " + args.pcap + Style.RESET_ALL)

    # Load packets from the given PCAP file
    packets = rdpcap(args.pcap)

    # Process each packet one by one
    for pkt in packets:
        process_packet(pkt, args)

# Run the program
if __name__ == "__main__":
    main()

