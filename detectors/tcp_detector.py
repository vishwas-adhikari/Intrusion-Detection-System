# detectors/tcp_detector.py
import time
from collections import defaultdict # <-- THIS LINE WAS MISSING
from scapy.all import TCP, IP

from core.alerting import log_alert
from core.state import detection_state

def analyze_tcp(packet, config):
    """
    Analyzes a TCP packet for suspicious activity with corrected state management logic.
    """
    try:
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        current_time = time.time()

        # Rule 1 & 2: Stateless scans (NULL, FIN)
        if flags == 0:
            log_alert(config, "NULL Scan Detected", src_ip, dst_ip, f"NULL scan packet to port {dst_port}")
            return
        if flags == 'F':
            log_alert(config, "FIN Scan Detected", src_ip, dst_ip, f"FIN scan packet to port {dst_port}")
            return

        # Rule 3: Stateful SYN Scan Detection
        if flags == 'S':
            tracker = detection_state["port_scan_tracker"]
            threshold = config['detection_thresholds']['syn_scan_port_threshold']
            window = config['detection_thresholds']['port_scan_window']

            # Initialize the tracker for a new source IP
            if src_ip not in tracker:
                tracker[src_ip] = {
                    'timestamp': current_time,
                    'alerted': False,
                    'ports': defaultdict(set)
                }

            # If the time window has expired, reset the state for a new window
            if current_time - tracker[src_ip]['timestamp'] > window:
                tracker[src_ip]['timestamp'] = current_time
                tracker[src_ip]['alerted'] = False
                tracker[src_ip]['ports'].clear()

            # Record the port scan attempt for the current window
            tracker[src_ip]['ports'][dst_ip].add(dst_port)

            # Check if the threshold has been crossed for this destination
            scanned_ports_count = len(tracker[src_ip]['ports'][dst_ip])
            
            if scanned_ports_count > threshold and not tracker[src_ip]['alerted']:
                port_list = sorted(list(tracker[src_ip]['ports'][dst_ip]))
                details = (
                    f"Detected scan on {scanned_ports_count} ports within a {window}-second window. "
                    f"(e.g., ports {port_list[:5]})"
                )
                log_alert(config, "SYN Scan Detected", src_ip, dst_ip, details)
                
                tracker[src_ip]['alerted'] = True

    except Exception as e:
        print(f"[ERROR in TCP Detector] An exception occurred: {e}")