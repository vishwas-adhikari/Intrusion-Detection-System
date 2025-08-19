# core/alerting.py
import csv
import json
import os
from datetime import datetime
from core.state import detection_state

def log_alert(config, alert_type, src_ip, dst_ip, details):
    """
    Formats an alert, prints it, updates the summary, and logs it to files.
    """
    timestamp = datetime.now()
    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    # Pretty console alert
    alert_message = (
        f"\n[ALERT] {alert_type}\n"
        f"  Time       : {timestamp_str}\n"
        f"  Source IP  : {src_ip}\n"
        f"  Dest IP    : {dst_ip}\n"
        f"  Details    : {details}\n"
    )
    print(alert_message)

    # This is a critical step for the summary report.
    detection_state["alert_summary"][alert_type] += 1

    # --- CSV Logging ---
    try:
        csv_file_path = config['log_settings']['log_file_csv']
        csv_header = ['Timestamp', 'Alert Type', 'Source IP', 'Destination IP', 'Details']
        file_exists = os.path.exists(csv_file_path)
        is_empty = not file_exists or os.path.getsize(csv_file_path) == 0

        with open(csv_file_path, 'a', newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            if is_empty:
                writer.writerow(csv_header)
            writer.writerow([timestamp_str, alert_type, src_ip, dst_ip, details])
    except IOError as e:
        print(f"[ERROR] Could not write to CSV log file: {e}")

    # --- JSON Logging ---
    try:
        json_file_path = config['log_settings']['log_file_json']
        alert_data = {'timestamp': timestamp_str, 'type': alert_type, 'src_ip': src_ip, 'dst_ip': dst_ip, 'details': details}
        with open(json_file_path, 'a', encoding="utf-8") as f:
            json.dump(alert_data, f)
            f.write('\n')
    except IOError as e:
        print(f"[ERROR] Could not write to JSON log file: {e}")