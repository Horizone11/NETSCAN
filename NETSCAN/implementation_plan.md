# Implementation Plan - Network Insecurity Demo Tool: Phase 2 (The Brain)

This plan outlines the transition from raw packet sniffing to meaningful protocol dissection, focusing on DNS and local discovery as per the project requirements.

## Current Progress
- Verified Scapy connectivity on Windows using `conf.L3socket()`.
- Successfully captured IP/TCP/UDP traffic.
- Established basic packet callback structure.

## Proposed Next Steps

### 1. DNS Dissection (Immediate Priority)
The goal is to extract the "Human Readable" website names from DNS queries.
- **Action**: Update `packet_callback` to detect the `DNS` layer.
- **Data Point**: Extract `pkt[DNSQR].qname`.
- **Sales Narrative**: Map this to "Privacy Leak: Website Identity Exposed".

### 2. Local Service Discovery (SSDP/mDNS)
To show "Device Inventory" as requested.
- **Action**: Add filters for UDP 1900 (SSDP) and UDP 5353 (mDNS).
- **Data Point**: Parse headers for device names (e.g., "Samsung Smart TV", "HP Printer").

### 3. Background Threading & Data Storage
Preparing for the UI phase.
- **Action**: Move `sniff()` to a background thread.
- **Action**: Create a simple data structure (e.g., a dictionary/list) to store "Unique Devices" and "Recent Hits" so the UI can later consume them.

## Implementation Tasks (for today)

1. [ ] **Refine Sniffer**: Update `test.py` to specifically target and decode DNS traffic.
2. [ ] **IP-to-Hostname Resolution**: Implement a mechanism to resolve destination IPs to hostnames for non-DNS traffic where possible.
3. [ ] **Mock Data / Test Source**: Prepare a test case (e.g., visiting a website) to verify the sniffer picks it up.

---
**Next Action**: I will now update `test.py` to implement **Task 1: DNS Dissection**.
