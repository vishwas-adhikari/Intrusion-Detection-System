# Lightweight Network Intrusion Detection System (NIDS)

A modular, console-based **Network Intrusion Detection System (NIDS)** built in Python using **Scapy**.  
This tool serves as a proof-of-concept for monitoring network traffic (live or from PCAP files) and detecting basic suspicious activities like **port scans** and **ICMP floods**.

---

## ✨ Features

- **Modular Architecture**  
  Detection logic is cleanly separated into modules (`icmp_detector`, `tcp_detector`) for easy maintenance and scalability.

- **Dual-Mode Operation**  
  - **Live Capture**: Monitors network traffic on a specified interface in real-time.  
  - **Offline Analysis**: Reads and analyzes pre-recorded `.pcap` or `.pcapng` files.  

- **Detection Capabilities**  
  - **ICMP Monitoring**  
    - Detects individual ICMP pings (Echo Requests).  
    - Identifies high-rate ICMP Floods.  
  - **TCP Port Scan Detection**  
    - **SYN Scans**: Detects classic "half-open" stealth scans.  
    - **FIN Scans**: Detects stealth scans using only the FIN flag.  
    - **NULL Scans**: Detects stealth scans using packets with no flags set.  

- **Rich Alerting and Logging**  
  - **Console Output**: Displays formatted, easy-to-read alerts in the terminal as they happen.  
  - **File Logging**: Automatically logs alerts to both `alerts.csv` (for spreadsheets) and `alerts.json` (for programmatic access) inside the `logs/` directory.  

- **Session Summary**  
  Provides a comprehensive summary report at the end of a session, showing total packets analyzed and a breakdown of alerts by type.  

---

## 📸 Screenshots

<p align="center">
  <img src="screenshot/nids1.png" alt="NIDS Screenshot 1" width="45%"/>
  <img src="screenshot/nids2.png" alt="NIDS Screenshot 2" width="45%"/>
</p>

<p align="center">
  <img src="screenshot/nids3.png" alt="NIDS Screenshot 3" width="45%"/>
  <img src="screenshot/nids4.png" alt="NIDS Screenshot 4" width="45%"/>
</p>

---

## 🚀 Usage

### 1️⃣ Install dependencies
```bash
pip install -r requirements.txt
