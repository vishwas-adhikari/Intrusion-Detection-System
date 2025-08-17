# detectors/tcp_detector.py
from scapy.all import TCP, IP

from core.alerting import log_alert
from core.state import detection_state

def analyze_tcp(packet, config):
    """
    Analyzes a TCP packet for suspicious activity (Port Scans, etc.).
    This is where we will add our TCP detection logic next.
    """
    # Placeholder for now
    pass