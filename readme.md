# Lightweight Network Intrusion Detection System (NIDS)

A lightweight, modular, console-based **Network Intrusion Detection System (NIDS)** built in Python using [Scapy](https://scapy.net/).  
This project serves as a **proof-of-concept** for monitoring network traffic (live or from PCAP files) and detecting basic suspicious activities such as **port scans** and **ICMP floods**.

---

## ✨ Features

- **🧩 Modular Architecture**  
  Detection logic is separated into modules (`icmp_detector`, `tcp_detector`) for easy maintenance and scalability.  

- **🔀 Dual-Mode Operation**  
  - **Live Capture**: Monitor network traffic on a given interface in real-time.  
  - **Offline Analysis**: Analyze pre-recorded `.pcap` or `.pcapng` files.  

- **🚨 Detection Capabilities**  
  - **ICMP Monitoring**  
    - Detects individual ICMP pings (Echo Requests).  
    - Identifies high-rate ICMP Floods.  
  - **TCP Port Scan Detection**  
    - **SYN Scans**: Detects classic "half-open" stealth scans.  
    - **FIN Scans**: Detects stealth scans using only the FIN flag.  
    - **NULL Scans**: Detects stealth scans using packets with no flags set.  

- **📊 Rich Alerting & Logging**  
  - **Console Output**: Alerts are displayed in real-time in the terminal.  
  - **File Logging**: Alerts are logged automatically in:  
    - `logs/alerts.csv` → Human-readable, spreadsheet-friendly format.  
    - `logs/alerts.json` → Structured format for programmatic use.  

- **📋 Session Summary**  
  At the end of each run, a comprehensive report is generated, showing:  
  - Total packets analyzed.  
  - Breakdown of alerts by type.  

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/nids.git
cd nids
