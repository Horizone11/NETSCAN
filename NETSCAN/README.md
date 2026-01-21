# NETSCAN: Network Visibility Prototype

## Overview
NETSCAN is a passive network monitoring tool designed to demonstrate metadata exposure. It captures DNS queries, HTTP traffic, and service broadcasts (mDNS/SSDP) to build a real-time risk profile of devices on the network.

## Features
- **Passive Sniffing**: Uses Scapy to capture traffic without interference.
- **Real-time Map**: Visualizes destination IP geolocation.
- **Device Intelligence**: Profiles devices based on their meta-data leakage.
- **Interactive Console**: Click logs to see specific device details.
- **Professional UI**: Built with CustomTkinter for a premium dark-themed experience.

## Installation & Requirements
1. **Npcap**: You must install [Npcap](https://npcap.com/) (select "Install Npcap in WinPcap API-compatible Mode").
2. **Python 3.10+**
3. **Dependencies**:
   ```bash
   pip install scapy customtkinter tkintermapview requests
   ```

## Running the App
Run the application with administrative privileges (required for packet sniffing):
```bash
python app.py
```

## Security & Ethics
This tool is for **demonstration purposes only**.
- It is strictly **passive** (listen-only).
- No data is stored; all session data is cleared on exit.
- It does not intercept encrypted content (HTTPS/TLS).
