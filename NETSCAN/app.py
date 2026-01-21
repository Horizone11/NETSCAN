import threading
import tkinter as tk
import customtkinter as ctk
import tkintermapview
import requests
import socket
from scapy.all import sniff, conf
import datetime

# Set the appearance and theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class NetworkInsecurityApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NETSCAN")
        self.geometry("800x600") # Smaller initial size
        self.center_window(800, 600)
        self.running = True
        self.is_sniffing = False
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Data structures
        self.discovered_devices = {}  # IP -> { 'activities': [], 'risk': 0.0, 'name': None }
        self.device_buttons = {}      # IP -> Button Object
        self.ip_to_location = {}       # IP -> (lat, lon, city)
        self.selected_device = None
        self.ip_to_hostname = {}      # Cache for reverse DNS
        self.city_markers = {}        # city -> { 'marker': marker_obj, 'count': N }
        self.self_marker = None
        self.new_markers_count = 0
        self.lookup_lock = threading.Lock()
        self.pending_lookups = set()
        self.last_activity_seen = {} # (ip, activity) -> timestamp

        # Create Landing Screen Container (Deep Midnight Blue)
        self.landing_frame = ctk.CTkFrame(self, fg_color="#0F172A")
        self.landing_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        # Hero Section
        self.landing_content = ctk.CTkFrame(self.landing_frame, fg_color="transparent")
        self.landing_content.place(relx=0.5, rely=0.5, anchor="center")
        
        self.welcome_label = ctk.CTkLabel(self.landing_content, text="NETSCAN", 
                                        font=ctk.CTkFont(family="Inter", size=64, weight="bold"), text_color="white")
        self.welcome_label.pack(pady=(0, 40))
        
        # Pill-shaped Start Button (Reference Image Style)
        self.btn_container = ctk.CTkFrame(self.landing_content, fg_color="transparent")
        self.btn_container.pack(pady=20)
        
        self.landing_start_btn = ctk.CTkButton(self.btn_container, text="⚡", 
                                              fg_color="#1E293B", 
                                              hover_color="#334155",
                                              border_color="#22C55E", 
                                              border_width=4,
                                              text_color="#22C55E",
                                              font=ctk.CTkFont(size=50),
                                              height=120, width=200, # Pill shape
                                              corner_radius=60,
                                              command=self.enter_app)
        self.landing_start_btn.pack()

        self.start_text = ctk.CTkLabel(self.btn_container, text="START SCAN", 
                                       font=ctk.CTkFont(size=14, weight="bold"), text_color="white")
        self.start_text.pack(pady=(15, 0))
        
        description = (
            "Passive network monitoring to expose unencrypted metadata, identify\n"
            "broadcasting devices, and visualize global data flow in real-time."
        )
        self.desc_label = ctk.CTkLabel(self.landing_content, text=description, 
                                      font=ctk.CTkFont(size=14), 
                                      text_color="#94A3B8", justify="center")
        self.desc_label.pack(pady=40)

        # --- Dashboard (Initially Hidden) ---
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        
        self.main_container.grid_columnconfigure(1, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        # --- Sidebar ---
        self.sidebar_frame = ctk.CTkFrame(self.main_container, width=300, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)
        
        self.sidebar_label = ctk.CTkLabel(self.sidebar_frame, text="NETWORK MONITOR", font=ctk.CTkFont(size=20, weight="bold"))
        self.sidebar_label.grid(row=0, column=0, padx=20, pady=(25, 10))
        
        # Circular Dashboard Button
        self.scan_btn_container = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.scan_btn_container.grid(row=1, column=0, padx=20, pady=15)
        
        self.scan_button = ctk.CTkButton(self.scan_btn_container, text="⚡", 
                                        fg_color="#1E293B", 
                                        hover_color="#334155",
                                        border_width=4,
                                        font=ctk.CTkFont(size=25),
                                        height=100, width=100,
                                        corner_radius=50,
                                        command=self.toggle_scan)
        self.scan_button.pack()
        
        self.scan_status_label = ctk.CTkLabel(self.scan_btn_container, text="STOP SCAN", 
                                             font=ctk.CTkFont(size=12, weight="bold"))
        self.scan_status_label.pack(pady=(5, 0))

        # Initial Active Styling (Since we start active)
        self.scan_button.configure(border_color="#EF4444", text_color="#EF4444")

        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="STATUS: ACTIVE SCAN", text_color="#00FF00", font=ctk.CTkFont(size=11, weight="bold"))
        self.status_label.grid(row=2, column=0, padx=20, pady=5)

        self.risk_gauge = ctk.CTkProgressBar(self.sidebar_frame, height=12)
        self.risk_gauge.grid(row=3, column=0, padx=20, pady=(20, 5))
        self.risk_gauge.set(0)
        
        self.risk_label = ctk.CTkLabel(self.sidebar_frame, text="THREAT LEVEL: MONITORING", font=ctk.CTkFont(size=13, weight="bold"))
        self.risk_label.grid(row=4, column=0, padx=20, pady=5)

        self.inventory_title = ctk.CTkLabel(self.sidebar_frame, text="DISCOVERED DEVICES", font=ctk.CTkFont(size=14, weight="bold"), text_color="gray")
        self.inventory_title.grid(row=5, column=0, padx=20, pady=(20, 5), sticky="w")

        self.inventory_frame = ctk.CTkScrollableFrame(self.sidebar_frame, label_text="", width=270)
        self.inventory_frame.grid(row=6, column=0, padx=10, pady=10, sticky="nsew")

        # --- Main Tabview ---
        self.tabview = ctk.CTkTabview(self.main_container, corner_radius=10, command=self.tab_clicked)
        self.tabview.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        self.tab_map = self.tabview.add("Global Traffic Map")
        self.tab_feed = self.tabview.add("Data Flow")
        self.tabview.set("Data Flow") # Default as per request
        
        # Tab: Global Traffic Map
        self.tab_map.grid_columnconfigure(0, weight=1)
        self.tab_map.grid_rowconfigure(0, weight=1)
        self.map_widget = tkintermapview.TkinterMapView(self.tab_map, corner_radius=0)
        self.map_widget.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.map_widget.set_zoom(2)

        # Map Controls Overlay
        self.map_controls = ctk.CTkFrame(self.tab_map, fg_color="#1a1a1a", corner_radius=15, border_width=1, border_color="gray")
        self.map_controls.place(relx=0.97, rely=0.03, anchor="ne")
        
        self.controls_label = ctk.CTkLabel(self.map_controls, text="MAP OVERLAYS", font=ctk.CTkFont(size=12, weight="bold"), text_color="#555555")
        self.controls_label.pack(side="top", padx=15, pady=(5, 0), anchor="w")

        self.show_names_var = ctk.BooleanVar(value=True)
        self.names_toggle = ctk.CTkSwitch(self.map_controls, text="Node Names", variable=self.show_names_var, 
                                        command=self.toggle_marker_names, font=ctk.CTkFont(size=11))
        self.names_toggle.pack(side="top", padx=15, pady=(10, 15), anchor="w")

        # Tab: Data Flow
        self.flow_container = ctk.CTkFrame(self.tab_feed, fg_color="transparent")
        self.flow_container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.flow_container.grid_rowconfigure(0, weight=6)
        self.flow_container.grid_rowconfigure(1, weight=4)
        self.flow_container.grid_columnconfigure(0, weight=1)
        self.tab_feed.grid_rowconfigure(0, weight=1)
        self.tab_feed.grid_columnconfigure(0, weight=1)

        self.feed_frame = ctk.CTkFrame(self.flow_container)
        self.feed_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        self.feed_frame.grid_rowconfigure(1, weight=1)
        self.feed_frame.grid_columnconfigure(0, weight=1)
        self.log_textbox = ctk.CTkTextbox(self.feed_frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_textbox.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.log_textbox.configure(state="disabled")

        self.detail_frame = ctk.CTkFrame(self.flow_container)
        self.detail_frame.grid_rowconfigure(1, weight=1)
        self.detail_frame.grid_columnconfigure(0, weight=1)
        self.detail_label = ctk.CTkLabel(self.detail_frame, text="DEVICE INTELLIGENCE", font=ctk.CTkFont(size=15, weight="bold"))
        self.detail_label.grid(row=0, column=0, padx=15, pady=5, sticky="w")
        self.detail_textbox = ctk.CTkTextbox(self.detail_frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.detail_textbox.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.detail_textbox.configure(state="disabled")
        self.detail_frame.grid_forget() # Hide detail frame initially

        for box in [self.log_textbox, self.detail_textbox]:
            box.tag_config("safe", foreground="#2ecc71")
            box.tag_config("warning", foreground="#f1c40f")
            box.tag_config("danger", foreground="#e74c3c")
            box.tag_config("normal", foreground="white")

        # Start self marker detection
        threading.Thread(target=self.add_self_marker, daemon=True).start()

    def center_window(self, width, height):
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def enter_app(self):
        # Scale the existing window from its current position
        curr_width = self.winfo_width()
        curr_height = self.winfo_height()
        curr_x = self.winfo_x()
        curr_y = self.winfo_y()
        
        new_width = 1050
        new_height = 675

        
        # Calculate new position to keep the center point the same
        new_x = curr_x - (new_width - curr_width) // 2
        new_y = curr_y - (new_height - curr_height) // 2
        
        # Apply new size and position in one go
        self.geometry(f"{new_width}x{new_height}+{max(0, new_x)}+{max(0, new_y)}")
        
        # Swap the content frames
        self.landing_frame.place_forget()
        self.main_container.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        # Start scanning
        self.is_sniffing = True
        threading.Thread(target=self.start_sniffing, daemon=True).start()

    def add_self_marker(self):
        try:
            response = requests.get("https://api64.ipify.org?format=json", timeout=1.5).json()
            my_ip = response["ip"]
            geo_response = requests.get(f"http://ip-api.com/json/{my_ip}", timeout=1.5).json()
            if geo_response.get("status") == "success":
                lat, lon = geo_response["lat"], geo_response["lon"]
                self.after(0, lambda: self.create_self_marker(lat, lon))
        except: pass

    def create_self_marker(self, lat, lon):
        self.self_marker = self.map_widget.set_marker(lat, lon, text="You", marker_color_circle="blue", marker_color_outside="blue")

    def toggle_marker_names(self):
        show = self.show_names_var.get()
        for city_data in self.city_markers.values():
            marker = city_data['marker']
            if not show:
                # Store text if not already stored, then clear it
                if not hasattr(marker, 'original_text') or marker.original_text == "":
                    marker.original_text = marker.text
                marker.set_text("")
            else:
                # Restore text from storage
                if hasattr(marker, 'original_text'):
                    marker.set_text(marker.original_text)
        
        # The labels will update automatically via set_text

    def geolocate_ip(self, ip):
        with self.lookup_lock:
            if ip in self.ip_to_location or ip in self.pending_lookups:
                return
            self.pending_lookups.add(ip)
        
        try:
            # Check local IP ranges again
            if ip.startswith(("10.", "192.168.", "172.16.", "127.")):
                return

            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,city,lat,lon", timeout=2).json()
            if response.get("status") == "success":
                lat, lon, city = response["lat"], response["lon"], response["city"]
                self.ip_to_location[ip] = (lat, lon, city)
                
                # Update Map UI safely
                self.after(10, lambda: self.update_map_marker(lat, lon, city, ip))
        except: pass
        finally:
            with self.lookup_lock:
                if ip in self.pending_lookups:
                    self.pending_lookups.remove(ip)

    def update_map_marker(self, lat, lon, city, ip):
        if city in self.city_markers:
            self.city_markers[city]['count'] += 1
            count = self.city_markers[city]['count']
            new_text = f"{city} ({count} Nodes)"
            marker = self.city_markers[city]['marker']
            marker.original_text = new_text
            if self.show_names_var.get(): marker.set_text(new_text)
        else:
            text = f"{city} ({ip})"
            marker = self.map_widget.set_marker(lat, lon, text=text if self.show_names_var.get() else "", command=self.marker_callback)
            marker.original_text = text
            self.city_markers[city] = {'marker': marker, 'count': 1}
        
        if self.tabview.get() != "Global Traffic Map":
            self.new_markers_count += 1
            self.update_tab_badge()

    def should_process(self, ip, activity, interval=2.0):
        now = datetime.datetime.now().timestamp()
        key = (ip, activity)
        if key in self.last_activity_seen and (now - self.last_activity_seen[key] < interval):
            return False
        self.last_activity_seen[key] = now
        return True

    def tab_clicked(self):
        if self.tabview.get() == "Global Traffic Map":
            self.new_markers_count = 0
            self.update_tab_badge()

    def update_tab_badge(self):
        badge_text = f"Global Traffic Map ({self.new_markers_count})" if self.new_markers_count > 0 else "Global Traffic Map"
        try: self.tabview._segmented_button._buttons_dict["Global Traffic Map"].configure(text=badge_text)
        except: pass

    def toggle_scan(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.scan_status_label.configure(text="STOP SCAN")
            self.scan_button.configure(border_color="#EF4444", text_color="#EF4444")
            self.status_label.configure(text="STATUS: ACTIVE SCAN", text_color="#00FF00")
            threading.Thread(target=self.start_sniffing, daemon=True).start()
        else:
            self.is_sniffing = False
            self.scan_status_label.configure(text="START SCAN")
            self.scan_button.configure(border_color="#22C55E", text_color="#22C55E")
            self.status_label.configure(text="STATUS: IDLE", text_color="gray")

    def on_closing(self):
        self.running = False
        self.is_sniffing = False
        self.destroy()

    def get_hostname(self, ip):
        if ip in self.ip_to_hostname: return self.ip_to_hostname[ip]
        try:
            name = socket.gethostbyaddr(ip)[0]
            self.ip_to_hostname[ip] = name
            return name
        except:
            self.ip_to_hostname[ip] = ip
            return ip

    def get_color_params(self, risk):
        if risk < 0.25: r, g, b = 46, 204, 113
        elif risk < 0.5: r, g, b = 241, 196, 15
        elif risk < 0.75: r, g, b = 230, 126, 34
        else: r, g, b = 231, 76, 60
        fg_color = f"#{r:02x}{g:02x}{b:02x}"
        hr, hg, hb = int(r * 0.7), int(g * 0.7), int(b * 0.7)
        hover_color = f"#{hr:02x}{hg:02x}{hb:02x}"
        brightness = (r * 0.299 + g * 0.587 + b * 0.114)
        text_color = "black" if brightness > 150 else "white"
        return fg_color, hover_color, text_color

    def add_log(self, message, ip=None):
        if not self.running: return
        self.log_textbox.configure(state="normal")
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Determine base severity tag
        tag = "normal"
        if "UNSECURED" in message or "CRITICAL" in message or "ERROR" in message: tag = "danger"
        elif "DNS" in message or "RESOLVED" in message: tag = "warning"
        elif "IDENTITY" in message or "BROADCAST" in message: tag = "safe"
        
        tags = [tag]
        if ip:
            # Create a unique clickable tag for this specific log entry
            click_tag = f"click_{timestamp}_{ip.replace('.', '_')}"
            tags.append(click_tag)
            
            # Configure clickable appearance (Underline on hover)
            self.log_textbox.tag_config(click_tag, foreground=self.log_textbox.tag_cget(tag, "foreground"))
            
            # Bind click event
            self.log_textbox.tag_bind(click_tag, "<Button-1>", lambda e, addr=ip: self.select_device(addr))
            
            # Bind hover events to change cursor and underline
            self.log_textbox.tag_bind(click_tag, "<Enter>", lambda e, t=click_tag: (
                self.log_textbox.tag_config(t, underline=True),
                self.log_textbox.configure(cursor="hand2")
            ))
            self.log_textbox.tag_bind(click_tag, "<Leave>", lambda e, t=click_tag: (
                self.log_textbox.tag_config(t, underline=False),
                self.log_textbox.configure(cursor="")
            ))

        self.log_textbox.insert("end", f"[{timestamp}] {message}\n", tuple(tags))
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def update_global_risk(self):
        if not self.discovered_devices: return
        max_risk = max(dev['risk'] for dev in self.discovered_devices.values())
        self.risk_gauge.set(max_risk)
        
        if max_risk == 0:
            text, color = "THREAT LEVEL: MONITORING", "gray"
        elif max_risk < 0.25:
            text, color = "THREAT LEVEL: SAFE", "#2ecc71"
        elif max_risk < 0.5:
            text, color = "THREAT LEVEL: CAUTION", "#f1c40f"
        elif max_risk < 0.75:
            text, color = "THREAT LEVEL: ELEVATED", "#e67e22"
        else:
            text, color = "THREAT LEVEL: CRITICAL", "#e74c3c"
            
        self.risk_label.configure(text=text, text_color=color)
        self.risk_gauge.configure(progress_color=color)

    def update_devices(self, ip, activity, risk_weight=0.0, potential_name=None):
        if not self.running: return
        if ip not in self.discovered_devices:
            self.discovered_devices[ip] = {'activities': [], 'risk': 0.0, 'name': potential_name}
            fg, hvr, txt = self.get_color_params(0.0)
            btn = ctk.CTkButton(self.inventory_frame, text=f"{potential_name if potential_name else 'Scanning...'}\n{ip}", 
                               command=lambda i=ip: self.select_device(i), fg_color=fg, hover_color=hvr, text_color=txt,
                               font=ctk.CTkFont(size=12, weight="bold"), anchor="w", height=55)
            btn.pack(fill="x", padx=5, pady=5)
            self.device_buttons[ip] = btn
        dev = self.discovered_devices[ip]
        if potential_name and not dev['name']:
            dev['name'] = potential_name
            self.device_buttons[ip].configure(text=f"{potential_name}\n{ip}")
        if activity not in dev['activities']:
            dev['activities'].append(activity)
            dev['risk'] = min(1.0, dev['risk'] + risk_weight)
            fg, hvr, txt = self.get_color_params(dev['risk'])
            self.device_buttons[ip].configure(fg_color=fg, hover_color=hvr, text_color=txt)
            self.after(0, self.update_global_risk)

    def select_device(self, ip):
        self.selected_device = ip
        dev_data = self.discovered_devices[ip]
        self.detail_label.configure(text=f"DEVICE INTELLIGENCE: {dev_data['name'] if dev_data['name'] else ip}")
        self.detail_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self.refresh_detail_view()
        # Automatically switch to the Data Flow tab to show intelligence
        self.tabview.set("Data Flow")

    def refresh_detail_view(self):
        if not self.selected_device: return
        dev_data = self.discovered_devices[self.selected_device]
        self.detail_textbox.configure(state="normal")
        self.detail_textbox.delete("1.0", "end")
        risk_int = int(dev_data['risk'] * 100)
        risk_tag = "safe" if risk_int < 25 else "warning" if risk_int < 75 else "danger"
        self.detail_textbox.insert("end", f"Assessed Risk: ", "normal")
        self.detail_textbox.insert("end", f"{risk_int}%\n", risk_tag)
        self.detail_textbox.insert("end", "-"*40 + "\n", "normal")
        for act in reversed(dev_data['activities']):
            a_tag = "normal"
            if "Unsecured" in act or "CRITICAL" in act: a_tag = "danger"
            elif "Browsing" in act or "Domain" in act: a_tag = "warning"
            elif "Identity" in act or "Broadcasting" in act or "Initiated" in act: a_tag = "safe"
            self.detail_textbox.insert("end", f" > {act}\n", a_tag)
        self.detail_textbox.configure(state="disabled")

    def marker_callback(self, marker):
        self.map_widget.set_position(marker.position[0], marker.position[1])
        self.map_widget.set_zoom(10)

    def packet_callback(self, pkt):
        if not self.is_sniffing: return
        if not pkt.haslayer('IP'): return
        src, dst = pkt['IP'].src, pkt['IP'].dst

        # --- OPTIMIZATION: Early Exit/Filtering ---
        is_external_dst = not (dst.startswith(("10.", "192.168.", "172.16.", "127.")))
        
        # 1. DNS logic (Privacy Leak)
        if pkt.haslayer('DNS') and pkt.getlayer('DNS').qr == 0:
            try:
                qname = pkt.getlayer('DNSQR').qname.decode('utf-8').strip('.')
                activity = f"Browsing {qname}"
                if self.should_process(src, activity):
                    msg = f"RESOLVED: {src} -> {qname}"
                    self.after(10, lambda m=msg, s=src, q=qname: (self.add_log(m, ip=s), self.update_devices(s, activity, risk_weight=0.05, potential_name=q.split('.')[-2].capitalize())))
                
                if is_external_dst:
                    threading.Thread(target=self.geolocate_ip, args=(dst,), daemon=True).start()
            except: pass

        # 2. HTTP logic
        elif pkt.haslayer('TCP') and pkt['TCP'].dport == 80:
            try:
                payload = bytes(pkt['TCP'].payload).decode('utf-8', errors='ignore')
                if payload.startswith("GET"):
                    first_line = payload.split('\r\n')[0] 
                    name = self.get_hostname(dst)
                    activity = f"Browsing Website: Unsecured ({name})"
                    if self.should_process(src, activity):
                        msg = f"UNSECURED ACTIVITY: {src} -> {first_line}"
                        self.after(10, lambda m=msg, s=src, a=activity: (self.add_log(m, ip=s), self.update_devices(s, a, risk_weight=0.2)))
                    
                    if is_external_dst:
                        threading.Thread(target=self.geolocate_ip, args=(dst,), daemon=True).start()
                else:
                    name = self.get_hostname(dst)
                    activity = f"Unsecured Traffic: {name}"
                    if self.should_process(src, activity):
                        msg = f"UNSECURED DATA: {src} -> {name}"
                        self.after(10, lambda m=msg, s=src, a=activity: (self.add_log(m, ip=s), self.update_devices(s, a, risk_weight=0.1)))
                    
                    if is_external_dst:
                        threading.Thread(target=self.geolocate_ip, args=(dst,), daemon=True).start()
            except: pass

        # 3. Discovery logic
        elif pkt.haslayer('UDP') and (pkt['UDP'].dport in [1900, 5353]):
            protocol = "SSDP" if pkt['UDP'].dport == 1900 else "mDNS"
            activity = f"{protocol} Identity Leak"
            if self.should_process(src, activity, interval=10.0): # Long interval for broadcasts
                name = None
                try:
                    raw_payload = bytes(pkt['UDP'].payload).decode('utf-8', errors='ignore')
                    if "SERVER:" in raw_payload:
                        server_info = raw_payload.split("SERVER:")[1].split("\r\n")[0].strip()
                        name = f"Node: {server_info.split('/')[0]}" 
                    elif "LOCATION:" in raw_payload: name = "UPnP Service"
                    if protocol == "mDNS":
                        if pkt.haslayer('DNSRR'):
                            rrname = pkt.getlayer('DNSRR').rrname.decode('utf-8', errors='ignore').strip('.')
                            if ".local" in rrname and not rrname.startswith('_'): name = rrname.replace(".local", "")
                        elif pkt.haslayer('DNSQR'):
                            qname = pkt.getlayer('DNSQR').qname.decode('utf-8', errors='ignore').strip('.')
                            if ".local" in qname and not qname.startswith('_'): name = qname.replace(".local", "")
                    if not name and protocol == "mDNS": name = "Apple/Linux Device"
                except: pass
                
                msg = f"{protocol} IDENTITY SHOUT: {src}"
                display_name = f"{name} ({protocol})" if name else f"Private {protocol} Device"
                self.after(10, lambda m=msg, s=src, p=protocol, n=display_name, a=activity: (self.add_log(m, ip=s), self.update_devices(s, a, risk_weight=0.03, potential_name=n)))

        # 4. General Traffic (Map Only)
        elif (pkt.haslayer('TCP') or pkt.haslayer('UDP')) and is_external_dst:
            threading.Thread(target=self.geolocate_ip, args=(dst,), daemon=True).start()

    def start_sniffing(self):
        try: sniff(opened_socket=conf.L3socket(), filter="udp port 53 or port 1900 or port 5353 or tcp port 80", prn=self.packet_callback, store=0, stop_filter=lambda x: not self.is_sniffing)
        except Exception as e:
            if self.running: self.after(0, lambda: self.add_log(f"ERROR: {str(e)}"))

if __name__ == "__main__":
    app = NetworkInsecurityApp()
    app.mainloop()
