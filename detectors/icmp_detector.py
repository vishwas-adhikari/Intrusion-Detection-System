# detectors/icmp_detector.py
import time
from scapy.all import ICMP, IP

# Import our shared components
from core.alerting import log_alert
from core.state import detection_state

def analyze_icmp(packet, config):
    """
    Analyzes an ICMP packet for suspicious activity (Pings and Floods).
    """
    if not packet.haslayer(ICMP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    current_time = time.time()
    threshold = config['detection_thresholds']['icmp_flood_threshold']

    # Rule 1: ICMP Echo Request (Ping) Detection
    if packet[ICMP].type == 8:
        log_alert(config, "ICMP Ping Detected", src_ip, dst_ip, "ICMP Echo Request")

    # Rule 2: ICMP Flood Detection
    tracker = detection_state["icmp_packet_tracker"]
    tracker[src_ip].append(current_time)
    
    # Remove timestamps older than 1 second
    tracker[src_ip] = [t for t in tracker[src_ip] if current_time - t <= 1]
    
    if len(tracker[src_ip]) > threshold:
        log_alert(config, "ICMP Flood Detected", src_ip, "N/A", f"Rate: {len(tracker[src_ip])} packets/sec")
        # Reset tracker for this IP to prevent continuous alerts
        tracker[src_ip] = []