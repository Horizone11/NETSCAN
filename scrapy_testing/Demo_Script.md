# 5-Minute Demo Script: The Network Visibility Prototype

## Goal
Prove to a non-technical client that their "private" device is constantly leaking metadata.

---

### Minute 1: The Setup
*   **Action:** Launch `app.py`. Ensure the status is "IDLE".
*   **Narrative:** *"Imagine we're in a crowded coffee shop. You're using the free Wi-Fi, and your phone says it's connected to 'Free_WiFi_Secure'. You see the padlock icon in your browser, so you feel safe. But let's look at what's happening 'in the air' around us."*

### Minute 2: "The Big Red Button" (Start Scan)
*   **Action:** Click the **START SCAN** button.
*   **Narrative:** *"I've just started our Visibility Monitor. Within seconds, we're seeing devices appearing in our inventory. These are total strangers on this network. Notice the colors—Green means they are relatively quiet, but that's about to change."*

### Minute 3: The Privacy Leak (DNS)
*   **Action:** Open a browser on the laptop/target device and visit any major site (e.g., `google.com`).
*   **Narrative:** *"Look at the 'Data Flow' feed. Device 10.10.100.86 just resolved 'google.com'. Even though the website content will be encrypted, your phone had to 'shout' the name of the site across the room just to find it. I now know exactly where you are browsing."*

### Minute 4: The Critical Alert (HTTP)
*   **Action:** Visit an unencrypted site (e.g., `http://neverssl.com`).
*   **Narrative:** *"Now watch this. The device button just turned RED. We've detected a 'Browsing Website: Unsecured' event. On this unencrypted connection, I'm not just seeing WHERE you are going—I can theoretically see every image and word on that page. Notice the 'Global Traffic Map' just added a marker? Your data just traveled to a server in London."*

### Minute 5: The "Scare" Close
*   **Action:** Click the Red/Orange device button in the sidebar to show the **Device Intelligence** panel.
*   **Narrative:** *"When we look at the 'Intelligence' for this device, we see a full behavioral profile. We know their phone name, the legacy services they use, and every server they've touched. This is why 'Free Wi-Fi' is never really free. Without our security suite, your identity is public property."*

---
**END DEMO**
