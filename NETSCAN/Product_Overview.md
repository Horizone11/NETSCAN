# NETSCAN: Real-Time Network Visibility & Metadata Intelligence
**Product Overview & Technical Brief**

---

## 1. Executive Overview
**NETSCAN** is a high-impact, real-time network visibility demonstrator designed for executive and client-facing presentations. The platform provides immediate, visual evidence of "metadata leakage"—the private information that modern devices (smartphones, laptops, IoT) broadcast over local networks without user knowledge. 

By capturing and visualizing passive network traffic, NETSCAN helps clients understand the gap between perceived digital security and the reality of network-layer exposure.

## 2. The Core Problem: The "Silent Leak"
Most users believe that modern encryption (HTTPS/padlock icons) makes them invisible on public or office Wi-Fi. However, devices regularly "shout" private information across the network to function:
*   **Discovery Signals:** Devices announce their names (e.g., "Sarah's iPhone") to find printers or speakers.
*   **DNS Resolution:** Before a secure connection is made, the device must ask for the website's address in plain text.
*   **Unsecured Services:** Legacy apps and background services often transmit data without any encryption.

## 3. Product Solution & Key Features
NETSCAN captures this "noise" and translates technical packet data into a high-stakes visual narrative through three core interfaces:

### A. Real-Time Data Flow (The Console)
A live, interactive feed of network events. It translates raw traffic into human-readable alerts:
*   **DNS Monitoring:** Shows which websites devices are attempting to visit.
*   **Identity Extraction:** Identifies device names and types via mDNS/SSDP broadcasts.
*   **Unsecured Activity Alerts:** Flags unencrypted HTTP traffic with high-severity visual markers.

### B. Device Intelligence (Risk Profiling)
A sophisticated sidebar inventory that builds a "digital dossier" for every device on the network:
*   **Dynamic Risk Scoring:** Devices change color (Green -> Yellow -> Red) as they leak more sensitive metadata.
*   **Behavioral History:** Selecting a device reveals its full chronological activity log and assessed risk level.

### C. Global Traffic Map (The "Escape" Path)
Visualizes the physical path of data. When a device communicates with a server, NETSCAN geolocates that server in real-time, placing markers on a 3D global map. This demonstrates that "local" activity often has a global footprint.

## 4. Technical Workflow (Safe & Passive)
To ensure the product is safe for use in any corporate environment, it follows a strict **"Listen-Only"** protocol:
1.  **Passive Sniffing:** The tool never interacts with or "hacks" other devices. It merely listens to traffic already present in the air.
2.  **Metadata Focus:** NETSCAN ignores the content of encrypted packets (passwords, emails), focusing entirely on the "metadata" (who, where, and when).
3.  **In-Memory Architecture:** No captured data is ever written to disk. All intelligence is stored temporarily in RAM and is permanently wiped when the application is closed.

## 5. Sales & Demo Impact
NETSCAN is built to be "Retail Ready." It features a premium, midnight-blue aesthetic with "Glass-morphism" UI elements designed to wow audiences. The 5-minute demo flow allows a salesperson to:
1.  Initialize the "NETSCAN Protocol" via a high-impact splash screen.
2.  Show an "Idle" network becoming "Alive" with discovered devices.
3.  Reveal exactly where a client is browsing in real-time.
4.  Demonstrate the "Scare Factor" by showing data traveling across a global map.

---
**Prepared for:** Client Presentation & Product Documentation  
**Version:** 1.0 (PROTOTYPE)
