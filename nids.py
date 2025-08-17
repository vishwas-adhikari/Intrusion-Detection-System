# nids.py
import argparse
import json
from scapy.all import sniff, IP, TCP, ICMP

# Import our modular components
from detectors.icmp_detector import analyze_icmp
from detectors.tcp_detector import analyze_tcp

# --- Global Configuration ---
CONFIG = {}

def packet_processor(packet):
    """
    Main callback function to process each packet.
    It acts as a dispatcher, sending the packet to the relevant analyzer.
    """
    if packet.haslayer(ICMP):
        analyze_icmp(packet, CONFIG)
    
    if packet.haslayer(TCP):
        analyze_tcp(packet, CONFIG)

def main():
    """
    Main function to parse arguments and start the NIDS.
    """
    global CONFIG
    try:
        with open('config.json', 'r') as f:
            CONFIG = json.load(f)
    except FileNotFoundError:
        print("[ERROR] config.json not found! Please create it.")
        return
    except json.JSONDecodeError:
        print("[ERROR] Could not decode config.json. Please check its format.")
        return

    parser = argparse.ArgumentParser(description="A modular Network Intrusion Detection System.")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on.")
    parser.add_argument("-r", "--read", type=str, help="PCAP file to read from.")
    args = parser.parse_args()

    print("NIDS starting...")

    if args.read:
        print(f"Reading packets from: {args.read}")
        try:
            sniff(offline=args.read, prn=packet_processor, store=False)
        except FileNotFoundError:
            print(f"[ERROR] PCAP file not found: {args.read}")
    else:
        interface = args.interface or CONFIG.get("network_interface")
        if not interface:
            print("Starting live capture on default interface...")
        else:
            print(f"Starting live capture on interface: {interface}")
        
        try:
            sniff(iface=interface, prn=packet_processor, store=False)
        except Exception as e:
            print(f"[ERROR] Could not start sniffing. Run with sudo and check interface name.")
            print(f"Details: {e}")

    print("NIDS stopped.")

if __name__ == "__main__":
    main()