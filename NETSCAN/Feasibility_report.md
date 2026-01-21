# NETSCAN: Prototype Summary & Visibility Report

### 1. Platform Choice: Windows (Python + Npcap)
*   **Why:** iOS and Android "sandbox" apps, making it impossible to see other devices' traffic.
*   **The Choice:** We used Windows with the **Npcap** driver to enable **Promiscuous Mode**. This allows the tool to "hear" all traffic from any device on the network.

### 2. What We Captured
The tool successfully extracts the following plain-text data:
*   **Browsing History (DNS):** We see the specific website names devices are looking up (e.g., `facebook.com`), even if the final connection is encrypted.
*   **Device Names (mDNS/SSDP):** We extract human-readable names like "John’s iPhone" or "Office-Printer" from background broadcasts.
*   **Unsecured Web (HTTP):** We capture full URLs for any traffic sent over unencrypted Port 80.
*   **Geographies:** We geolocate the destination of every packet to show a real-time global map of data flow.

### 3. Encryption Boundaries (TLS/SSL)
*   **Protected:** We cannot see the *inside* of encrypted packets (passwords, private messages, email text). 
*   **Exposed:** We still see the **Metadata** (who is talking, what website they are visiting, and where that server is physically located). For a sales demo, this metadata is usually enough to build a full behavioral profile of the target.

### 4. Security & Privacy
*   **Passive:** The tool only listens; it does not hack or intercept traffic.
*   **Wiped on Exit:** All data is held in RAM and is permanently deleted the moment the app is closed. No logs are kept.
