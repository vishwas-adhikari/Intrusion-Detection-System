# core/alerting.py
import csv
import json
from datetime import datetime

"""
This module handles alerting and logging for the IDS.
It prints alerts to the console and optionally writes them to CSV and JSON logs.
"""

def log_alert(config, alert_type, src_ip, dst_ip, details):
    """
    Logs an intrusion detection alert.

    Args:
        config (dict): IDS configuration dictionary containing log file settings.
        alert_type (str): Type of alert (e.g., "ICMP Flood", "SYN Scan").
        src_ip (str): Source IP address of the suspicious traffic.
        dst_ip (str): Destination IP address of the suspicious traffic.
        details (str): Additional details about the alert.

    Behavior:
        - Prints the alert to the console.
        - Appends the alert to a CSV log file (if configured).
        - Appends the alert to a JSON log file (if configured).
    """
    timestamp = datetime.now()

    # Format the alert message
    alert_message = (
        f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
        f"ALERT: {alert_type} from {src_ip} to {dst_ip} - {details}"
    )

    # Print alert to console
    print(alert_message)

    # --- Log to CSV ---
    try:
        with open(config['log_settings']['log_file_csv'], 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, alert_type, src_ip, dst_ip, details])
    except IOError as e:
        print(f"[ERROR] Could not write to CSV log file: {e}")

    # --- Log to JSON ---
    alert_data = {
        'timestamp': str(timestamp),
        'type': alert_type,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'details': details
    }
    try:
        with open(config['log_settings']['log_file_json'], 'a') as f:
            json.dump(alert_data, f)
            f.write('\n')  # Ensure each alert is on a new line
    except IOError as e:
        print(f"[ERROR] Could not write to JSON log file: {e}")
