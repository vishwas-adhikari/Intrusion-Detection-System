# core/state.py
from collections import defaultdict

# Centralized detection state with all keys initialized to prevent errors.
detection_state = {
    "icmp_packet_tracker": defaultdict(list),
    "port_scan_tracker": defaultdict(lambda: defaultdict(set)),
    "alert_summary": defaultdict(int),
    "total_packets_processed": 0
}