# Feasibility Report: Windows-Native Network Visibility Prototype

**Project:** Network Insecurity Demo Tool  
**Platform:** Windows (Python/Scapy)  
**Status:** Functional Prototype Delivered

---

## 1. Executive Summary
The goal was to build a "Sales Demonstrator" to visualize unencrypted network traffic. After evaluating multiple platforms, a **Windows Desktop** approach was selected for the prototype. This choice provided the best balance between rapid development (7-day window) and direct access to the network interface for promiscuous sniffing.

The resulting prototype successfully demonstrates real-time DNS queries, local device discovery (mDNS/SSDP), and unsecured HTTP transactions, including a global geolocation map to visualize data escape points.

## 2. Platform Choice & Rationale
### Selected Platform: Windows 10/11
*   **Why:** Unlike iOS and Android, which heavily sandbox network access (requiring complex VPN-tunneling workarounds), Windows allows direct "Promiscuous Mode" sniffing via the **Npcap** driver.
*   **Performance:** Using Python with the **Scapy** library allowed for sub-second packet dissection and real-time UI updates.
*   **Demo Impact:** A laptop can act as a Wi-Fi hotspot during a demo, making it the "hub" that sees all traffic from a client’s phone, providing 100% visibility of the targets.

## 3. Data Capture Successes
We successfully confirmed metadata visibility in the following areas:

| Feature | Technical Method | Sales Narrative "Scare Factor" |
| :--- | :--- | :--- |
| **DNS Queries** | Captured UDP Port 53 | "We can see exactly which websites you are looking up." |
| **Device Naming** | Parsed mDNS (5353) & SSDP (1900) | "Your device is shouting its name (e.g., 'John-iPhone') to everyone." |
| **Unsecured Web** | Captured TCP Port 80 (GET requests) | "You are browsing an unencrypted site; your activity is fully visible." |
| **Geolocation** | Real-time IP-to-Location mapping | "Your private metadata is traveling to servers in [City, Country]." |

## 4. Technical Constraints & Encryption Limits
While the tool is high-impact, it respects modern encryption boundaries:
*   **HTTPS (TLS/SSL):** We cannot see the *content* of encrypted packets (emails, passwords). However, the "Metadata" (which IP you are talking to and when) remains visible, which is often enough to build a behavioral profile.
*   **VPNs:** If a client uses a third-party VPN, most traffic becomes invisible to this tool. This actually serves as a strong sales point for our own security products.
*   **Administrative Access:** Windows requires the tool to run with "Administrative Privileges" to access the network card.

## 5. Security & Safety Compliance
To ensure the tool is safe for sales meetings:
*   **Passive Only:** It only listens. It does not exploit or hack any device.
*   **In-Memory:** No data is stored on the hard drive. All captured packets are wiped from RAM when the app is closed.
*   **No PII:** Private body content (credentials) is intentionally unparsed and ignored by the code.

---
**Prepared by:** Work Experience AI Partner  
**Date:** January 21, 2026
