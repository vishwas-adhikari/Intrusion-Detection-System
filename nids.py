# nids.py
import argparse
import json
from scapy.all import sniff, IP, TCP, ICMP

from detectors.icmp_detector import analyze_icmp
from detectors.tcp_detector import analyze_tcp
from core.state import detection_state

CONFIG = {}

def packet_processor(packet):
    detection_state["total_packets_processed"] += 1
    if packet.haslayer(ICMP):
        analyze_icmp(packet, CONFIG)
    if packet.haslayer(TCP):
        analyze_tcp(packet, CONFIG)

def print_summary():
    print("\n" + "="*50)
    print("      NIDS Session Summary")
    print("="*50)
    print(f"Total Packets Analyzed: {detection_state['total_packets_processed']}")
    total_alerts = sum(detection_state['alert_summary'].values())
    print(f"Total Alerts Generated: {total_alerts}")
    if total_alerts > 0:
        print("\nAlerts by Type:")
        for alert_type, count in detection_state['alert_summary'].items():
            print(f"  - {alert_type}: {count}")
    else:
        print("\nNo suspicious activities detected.")
    print("="*50)

def main():
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

    try:
        if args.read:
            print(f"Analyzing packets from: {args.read}")
            sniff(offline=args.read, prn=packet_processor, store=False)
        else:
            interface = args.interface or CONFIG.get("network_interface")
            print(f"NIDS starting on interface: {interface or 'default'} (Press Ctrl+C to stop)")
            sniff(iface=interface, prn=packet_processor, store=False)
    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user.")
    except FileNotFoundError:
        print(f"[ERROR] PCAP file not found: {args.read}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
    finally:
        print_summary()
    print("NIDS stopped.")

if __name__ == "__main__":
    main()