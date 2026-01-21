from scapy.all import sniff, conf

def packet_callback(pkt):
    # 1. DNS Logic: Capturing website requests
    if pkt.haslayer('DNS') and pkt.getlayer('DNS').qr == 0:  # qr=0 is a query
        query_name = pkt.getlayer('DNSQR').qname.decode('utf-8')
        # Clean up the trailing dot often found in DNS names
        clean_name = query_name.strip('.')
        print(f"[!] PRIVACY LEAK: Device {pkt['IP'].src} is looking up: {clean_name}")

    # 2. SSDP/mDNS Logic: Local device discovery
    elif pkt.haslayer('UDP') and (pkt['UDP'].dport == 1900 or pkt['UDP'].dport == 5353):
        print(f"[*] DEVICE DISCOVERY: New service broadcast detected from {pkt['IP'].src}")

# Filter for DNS (UDP 53) and common discovery ports to keep noise low
sniff(opened_socket=conf.L3socket(), filter="udp port 53 or port 1900 or port 5353", prn=packet_callback)
