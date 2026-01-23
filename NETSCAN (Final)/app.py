import threading
import tkinter as tk
import customtkinter as ctk
import tkintermapview
import requests
import socket
from scapy.all import sniff, conf
import datetime

# --- DESIGN SYSTEM ---
COLORS = {
    "bg_dark": "#0B0F19",      # Deep Obsidian
    "bg_card": "#161B22",      # Slate Gray
    "accent": "#F43F5E",       # Rose / Soft Red
    "accent_hover": "#E11D48", 
    "success": "#10B981",      # Emerald
    "warning": "#F59E0B",      # Amber
    "danger": "#EF4444",       # Red
    "text_primary": "#F8FAFC", # White
    "text_secondary": "#94A3B8",# Slate
    "border": "#1E293B"        # Slate Dark
}

FONTS = {
    "h1": ("Inter", 72, "bold"),
    "h2": ("Inter", 24, "bold"),
    "body": ("Inter", 13),
    "body_bold": ("Inter", 13, "bold"),
    "mono": ("JetBrains Mono", 12)
}

UI_STYLE = {
    "radius": 12,
    "btn_radius": 10,
    "pill_radius": 40,
    "border_width": 2
}

# Set the appearance and theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class NetworkInsecurityApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NETSCAN // NETWORK VISIBILITY PROTOTYPE")
        self.geometry("1100x700")
        self.center_window(1100, 700)
        self.running = True
        self.is_sniffing = False
        self.sidebar_visible = True
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Data structures
        self.discovered_devices = {}  # IP -> { 'activities': [], 'risk': 0.0, 'name': None }
        self.device_buttons = {}      # IP -> Button Object
        self.ip_to_location = {}       # IP -> (lat, lon, city)
        self.selected_device = None
        self.ip_to_hostname = {}      # Cache for reverse DNS
        self.city_markers = {}        # city -> { 'marker': marker_obj, 'count': N }
        self.new_markers_count = 0
        self.lookup_lock = threading.Lock()
        self.pending_lookups = set()
        self.last_activity_seen = {} # (ip, activity) -> timestamp

        # --- Landing Screen ---
        self.landing_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_dark"], corner_radius=0)
        self.landing_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        # Decorative Elements
        self.bg_decor = ctk.CTkLabel(self.landing_frame, text="010101" * 100, 
                                     font=ctk.CTkFont(family="Inter", size=10),
                                     text_color="#1E293B", justify="center", wraplength=1200)
        self.bg_decor.place(relx=0.5, rely=0.5, anchor="center")

        self.landing_content = ctk.CTkFrame(self.landing_frame, fg_color="transparent")
        self.landing_content.place(relx=0.5, rely=0.5, anchor="center")
        
        self.welcome_label = ctk.CTkLabel(self.landing_content, text="NETSCAN", 
                                        font=FONTS["h1"], text_color=COLORS["text_primary"])
        self.welcome_label.pack(pady=(0, 5))
        
        self.tagline = ctk.CTkLabel(self.landing_content, text="OPERATIONAL NETWORK INTELLIGENCE", 
                                    font=ctk.CTkFont(size=14, weight="bold", slant="italic"), 
                                    text_color=COLORS["accent"])
        self.tagline.pack(pady=(0, 40))

        # Big Red Start Button
        self.btn_container = ctk.CTkFrame(self.landing_content, fg_color="transparent")
        self.btn_container.pack(pady=20)
        
        self.landing_start_btn = ctk.CTkButton(self.btn_container, text="⏻  INITIATE SCAN", 
                                              fg_color=COLORS["accent"], 
                                              hover_color=COLORS["accent_hover"],
                                              text_color="white",
                                              font=ctk.CTkFont(size=20, weight="bold"),
                                              height=70, width=300,
                                              corner_radius=UI_STYLE["pill_radius"],
                                              border_width=UI_STYLE["border_width"],
                                              border_color=COLORS["text_primary"],
                                              command=self.enter_app)
        self.landing_start_btn.pack()
        
        description = (
            "Monitor unencrypted metadata | Identify broadcasting devices | Visualize Global Data Flow\n"
            "This prototype demonstrates the inherent insecurity of local network protocols."
        )
        self.desc_label = ctk.CTkLabel(self.landing_content, text=description, 
                                      font=FONTS["body"], 
                                      text_color=COLORS["text_secondary"], justify="center")
        self.desc_label.pack(pady=40)

        # --- Dashboard (Initially Hidden) ---
        self.main_container = ctk.CTkFrame(self, fg_color=COLORS["bg_dark"], corner_radius=0)
        
        self.main_container.grid_columnconfigure(2, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        # --- Nav Rail (Far Left) ---
        self.nav_rail = ctk.CTkFrame(self.main_container, width=90, fg_color="#0A0D14", corner_radius=0)
        self.nav_rail.grid(row=0, column=0, sticky="nsew")
        self.nav_rail.grid_rowconfigure(7, weight=1) # Spacer at bottom

        # Rail Toggle Button (Top)
        self.btn_toggle_sidebar = ctk.CTkButton(self.nav_rail, text="«", 
                                               width=60, height=35, corner_radius=UI_STYLE["btn_radius"],
                                               fg_color="transparent", text_color=COLORS["text_secondary"],
                                               hover_color=COLORS["border"],
                                               font=ctk.CTkFont(size=22, weight="bold"),
                                               anchor="center",
                                               command=self.toggle_sidebar)
        self.btn_toggle_sidebar.grid(row=0, column=0, padx=15, pady=(20, 10))

        # Rail Separators
        self.rail_sep1 = ctk.CTkFrame(self.nav_rail, width=50, height=2, fg_color=COLORS["border"])
        self.rail_sep2 = ctk.CTkFrame(self.nav_rail, width=50, height=2, fg_color=COLORS["border"])
        self.rail_sep3 = ctk.CTkFrame(self.nav_rail, width=50, height=2, fg_color=COLORS["border"])
        
        # Initial placement of separators
        self.rail_sep3.grid(row=5, column=0, pady=10)

        # Mini Power Button (Joins rail when sidebar is hidden)
        self.btn_rail_power = ctk.CTkButton(self.nav_rail, text="⏻", 
                                           width=55, height=55, corner_radius=28,
                                           fg_color="transparent", text_color=COLORS["success"],
                                           border_width=UI_STYLE["border_width"], border_color=COLORS["success"],
                                           font=ctk.CTkFont(size=20, weight="bold"),
                                           command=self.toggle_scan)
        # Initially hidden

        # Rail Navigation Buttons
        self.btn_rail_flow = ctk.CTkButton(self.nav_rail, text="🖥️", 
                                          width=60, height=60, corner_radius=UI_STYLE["btn_radius"],
                                          fg_color=COLORS["accent"], text_color="white",
                                          font=("Segoe UI Emoji", 22), anchor="center",
                                          command=lambda: self.show_view("flow"))
        self.btn_rail_flow.grid(row=4, column=0, padx=15, pady=10)

        self.btn_rail_map = ctk.CTkButton(self.nav_rail, text="🌐", 
                                         width=60, height=60, corner_radius=UI_STYLE["btn_radius"],
                                         fg_color="transparent", text_color=COLORS["text_secondary"],
                                         hover_color=COLORS["border"], anchor="center",
                                         font=("Segoe UI Emoji", 22),
                                         command=lambda: self.show_view("map"))
        self.btn_rail_map.grid(row=6, column=0, padx=15, pady=10)

        # Notification Dot for Map (Small circular frame for better rendering)
        self.map_dot = ctk.CTkFrame(self.nav_rail, width=10, height=10, 
                                   corner_radius=5, fg_color=COLORS["accent"], 
                                   border_width=0)
        # Hidden by default
        self.map_dot_visible = False

        # --- Sidebar ---
        self.sidebar_frame = ctk.CTkFrame(self.main_container, width=280, fg_color=COLORS["bg_card"], corner_radius=0)
        self.sidebar_frame.grid(row=0, column=1, sticky="nsew")
        self.sidebar_frame.grid_columnconfigure(0, weight=1)
        self.sidebar_frame.grid_rowconfigure(6, weight=1) # Allow inventory frame to expand
        
        self.sidebar_label = ctk.CTkLabel(self.sidebar_frame, text="NETSCAN // MONITOR", 
                                         font=ctk.CTkFont(size=16, weight="bold"), text_color=COLORS["accent"])
        self.sidebar_label.grid(row=0, column=0, padx=20, pady=(25, 20))
        
        # 1. Threat Level Widget
        self.threat_container = ctk.CTkFrame(self.sidebar_frame, fg_color=COLORS["bg_dark"], corner_radius=UI_STYLE["radius"])
        self.threat_container.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        self.risk_label = ctk.CTkLabel(self.threat_container, text="THREAT LEVEL: NOMINAL", 
                                       font=ctk.CTkFont(size=11, weight="bold"), text_color=COLORS["success"])
        self.risk_label.pack(pady=(10, 5))
        
        self.risk_gauge = ctk.CTkProgressBar(self.threat_container, height=8, progress_color=COLORS["success"])
        self.risk_gauge.pack(padx=15, pady=(0, 15), fill="x")
        self.risk_gauge.set(0)

        # 2. Power Button (Styled with Border)
        self.scan_button = ctk.CTkButton(self.sidebar_frame, text="⏻", 
                                        fg_color="transparent",
                                        text_color=COLORS["success"], 
                                        hover_color=COLORS["bg_dark"],
                                        border_color=COLORS["success"],
                                        border_width=UI_STYLE["border_width"],
                                        font=ctk.CTkFont(size=44, weight="bold"),
                                        width=110, height=75,
                                        corner_radius=UI_STYLE["pill_radius"],
                                        command=self.toggle_scan)
        self.scan_button.grid(row=2, column=0, padx=40, pady=(20, 5))
        
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="STATUS: ACTIVE", 
                                         text_color=COLORS["success"], font=FONTS["body_bold"])
        self.status_label.grid(row=3, column=0, pady=(0, 10))

        # Separator Line
        self.sep1 = ctk.CTkFrame(self.sidebar_frame, height=1, fg_color=COLORS["border"])
        self.sep1.grid(row=4, column=0, padx=20, pady=20, sticky="ew")

        self.inventory_title = ctk.CTkLabel(self.sidebar_frame, text="DISCOVERED NODES", 
                                            font=FONTS["body_bold"], text_color=COLORS["text_secondary"])
        self.inventory_title.grid(row=5, column=0, padx=20, pady=(0, 5), sticky="w")

        self.inventory_frame = ctk.CTkScrollableFrame(self.sidebar_frame, label_text="", 
                                                      fg_color="transparent")
        self.inventory_frame.grid(row=6, column=0, padx=10, pady=(5, 10), sticky="nsew")

        # --- Main View Container (Switching mechanism) ---
        self.view_container = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.view_container.grid(row=0, column=2, sticky="nsew") # Removed padx/pady for true "fill"
        self.view_container.grid_rowconfigure(0, weight=1)
        self.view_container.grid_columnconfigure(0, weight=1)

        self.current_view = "flow"

        # View: Global Traffic Map
        self.map_view = ctk.CTkFrame(self.view_container, fg_color=COLORS["bg_card"], corner_radius=UI_STYLE["radius"])
        self.map_view.grid_columnconfigure(0, weight=1)
        self.map_view.grid_rowconfigure(0, weight=1)
        self.map_view.grid(row=0, column=0, sticky="nsew") # Stack on same grid

        self.map_widget = tkintermapview.TkinterMapView(self.map_view, corner_radius=UI_STYLE["radius"])
        self.map_widget.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.map_widget.set_zoom(2)

        # Map Controls Overlay
        self.map_controls = ctk.CTkFrame(self.map_view, fg_color=COLORS["bg_dark"], corner_radius=UI_STYLE["radius"], border_width=1, border_color=COLORS["border"])
        self.map_controls.place(relx=0.97, rely=0.03, anchor="ne")
        
        self.controls_label = ctk.CTkLabel(self.map_controls, text="MAP OVERLAYS", font=ctk.CTkFont(size=10, weight="bold"), text_color=COLORS["text_secondary"])
        self.controls_label.pack(side="top", padx=15, pady=(8, 0), anchor="w")

        self.show_names_var = ctk.BooleanVar(value=True)
        self.names_toggle = ctk.CTkSwitch(self.map_controls, text="Node Names", variable=self.show_names_var, 
                                         command=self.toggle_marker_names, font=ctk.CTkFont(size=11),
                                         progress_color=COLORS["accent"])
        self.names_toggle.pack(side="top", padx=15, pady=(10, 15), anchor="w")

        # View: Data Flow
        self.flow_view = ctk.CTkFrame(self.view_container, fg_color=COLORS["bg_card"], corner_radius=UI_STYLE["radius"])
        self.flow_view.grid_columnconfigure(0, weight=1)
        self.flow_view.grid_rowconfigure(0, weight=1)
        self.flow_view.grid(row=0, column=0, sticky="nsew") # Stack on same grid
        self.flow_view.lift() # Default view on top

        self.flow_container = ctk.CTkFrame(self.flow_view, fg_color="transparent")
        self.flow_container.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 0)) # Sticky top, inner padding
        self.flow_container.grid_rowconfigure(0, weight=1) # Log takes priority
        self.flow_container.grid_rowconfigure(1, weight=1) # Detail view sharing
        self.flow_container.grid_columnconfigure(0, weight=1)

        self.feed_frame = ctk.CTkFrame(self.flow_container, fg_color=COLORS["bg_dark"], corner_radius=UI_STYLE["radius"])
        self.feed_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        self.feed_frame.grid_rowconfigure(1, weight=1)
        self.feed_frame.grid_columnconfigure(0, weight=1)
        self.log_textbox = ctk.CTkTextbox(self.feed_frame, font=FONTS["mono"], fg_color="transparent")
        self.log_textbox.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.log_textbox.configure(state="disabled")

        self.detail_frame = ctk.CTkFrame(self.flow_container, fg_color=COLORS["bg_dark"], corner_radius=UI_STYLE["radius"])
        self.detail_frame.grid_rowconfigure(1, weight=1)
        self.detail_frame.grid_columnconfigure(0, weight=1)
        self.detail_label = ctk.CTkLabel(self.detail_frame, text="DEVICE INTELLIGENCE", font=FONTS["body_bold"], text_color=COLORS["accent"])
        self.detail_label.grid(row=0, column=0, padx=15, pady=5, sticky="w")
        self.detail_textbox = ctk.CTkTextbox(self.detail_frame, font=FONTS["mono"], fg_color="transparent")
        self.detail_textbox.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.detail_textbox.configure(state="disabled")
        self.detail_frame.grid_forget() # Hide detail frame initially

        for box in [self.log_textbox, self.detail_textbox]:
            box.tag_config("safe", foreground=COLORS["success"])
            box.tag_config("warning", foreground=COLORS["warning"])
            box.tag_config("danger", foreground=COLORS["danger"])
            box.tag_config("info", foreground="#60A5FA") # Blueish
            box.tag_config("normal", foreground=COLORS["text_primary"])

        # Start auto-clear timer (5 mins)
        self.after(300000, self.perform_auto_clear)

    def center_window(self, width, height):
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def enter_app(self):
        # Swap the content frames
        self.landing_frame.place_forget()
        self.main_container.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        # Start scanning
        self.is_sniffing = True
        threading.Thread(target=self.start_sniffing, daemon=True).start()

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
        
        if self.current_view != "map":
            self.new_markers_count += 1
            self.update_nav_badges()

    def should_process(self, ip, activity, interval=2.0):
        now = datetime.datetime.now().timestamp()
        key = (ip, activity)
        if key in self.last_activity_seen and (now - self.last_activity_seen[key] < interval):
            return False
        self.last_activity_seen[key] = now
        return True

    def show_view(self, view_name):
        self.current_view = view_name
        if view_name == "map":
            self.map_view.lift()
            self.btn_rail_map.configure(fg_color=COLORS["accent"], text_color="white")
            self.btn_rail_flow.configure(fg_color="transparent", text_color=COLORS["text_secondary"])
            self.new_markers_count = 0
            self.update_nav_badges()
        else:
            self.flow_view.lift()
            self.btn_rail_flow.configure(fg_color=COLORS["accent"], text_color="white")
            self.btn_rail_map.configure(fg_color="transparent", text_color=COLORS["text_secondary"])
            self.update_nav_badges()

    def update_sidebar_inventory(self, active_ip=None):
        for ip, btn in self.device_buttons.items():
            if ip == active_ip:
                btn.configure(fg_color=COLORS["accent"], text_color="white", border_width=0)
            else:
                btn.configure(fg_color="transparent", text_color=COLORS["text_primary"], border_width=1)

    def update_nav_badges(self):
        if self.current_view != "map" and self.new_markers_count > 0:
            if not self.map_dot_visible:
                # Place the dot in a corner of the button grid area
                self.map_dot.place(in_=self.btn_rail_map, relx=0.75, rely=0.2, anchor="center")
                self.map_dot_visible = True
        else:
            self.map_dot.place_forget()
            self.map_dot_visible = False

    def toggle_sidebar(self):
        self.sidebar_visible = not self.sidebar_visible
        if self.sidebar_visible:
            self.sidebar_frame.grid(row=0, column=1, sticky="nsew")
            self.btn_rail_power.grid_forget()
            self.rail_sep1.grid_forget()
            self.rail_sep2.grid_forget()
            self.btn_toggle_sidebar.configure(text="«")
        else:
            self.sidebar_frame.grid_forget()
            self.rail_sep1.grid(row=1, column=0, pady=10)
            self.btn_rail_power.grid(row=2, column=0, padx=15, pady=5)
            self.rail_sep2.grid(row=3, column=0, pady=10)
            self.btn_toggle_sidebar.configure(text="»")

    def toggle_scan(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            color = COLORS["success"]
            self.scan_button.configure(text_color=color, border_color=color)
            self.btn_rail_power.configure(text_color=color, border_color=color)
            self.status_label.configure(text="STATUS: ACTIVE", text_color=color)
            threading.Thread(target=self.start_sniffing, daemon=True).start()
        else:
            self.is_sniffing = False
            color = COLORS["danger"]
            self.scan_button.configure(text_color=color, border_color=color)
            self.btn_rail_power.configure(text_color=color, border_color=color)
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
        if risk < 0.25: r, g, b = 16, 185, 129 # success
        elif risk < 0.5: r, g, b = 245, 158, 11 # warning
        elif risk < 0.75: r, g, b = 249, 115, 22# orange
        else: r, g, b = 239, 68, 68 # danger
        fg_color = f"#{r:02x}{g:02x}{b:02x}"
        hr, hg, hb = int(r * 0.7), int(g * 0.7), int(b * 0.7)
        hover_color = f"#{hr:02x}{hg:02x}{hb:02x}"
        text_color = "white"
        return fg_color, hover_color, text_color

    def add_log(self, message, ip=None):
        if not self.running: return
        self.log_textbox.configure(state="normal")
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Determine base severity tag
        tag = "info"
        if "UNSECURED" in message or "CRITICAL" in message or "ERROR" in message: tag = "danger"
        elif "DNS" in message or "RESOLVED" in message: tag = "warning"
        elif "IDENTITY" in message or "BROADCAST" in message or "mDNS" in message: tag = "safe"
        
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

    def perform_auto_clear(self):
        if not self.running: return
        self.log_textbox.configure(state="normal")
        self.log_textbox.delete("1.0", "end")
        self.log_textbox.configure(state="disabled")
        self.add_log("SYSTEM: LOGS CLEARED (5 MIN CYCLE)")
        self.after(300000, self.perform_auto_clear)

    def update_global_risk(self):
        if not self.discovered_devices: return
        max_risk = max(dev['risk'] for dev in self.discovered_devices.values())
        self.risk_gauge.set(max_risk)
        
        if max_risk < 0.1:
            text, color = "THREAT LEVEL: NOMINAL", COLORS["success"]
        elif max_risk < 0.4:
            text, color = "THREAT LEVEL: LOW", COLORS["success"]
        elif max_risk < 0.7:
            text, color = "THREAT LEVEL: CAUTION", COLORS["warning"]
        elif max_risk < 0.9:
            text, color = "THREAT LEVEL: ELEVATED", "#F97316"
        else:
            text, color = "THREAT LEVEL: CRITICAL", COLORS["danger"]
            
        self.risk_label.configure(text=text, text_color=color)
        self.risk_gauge.configure(progress_color=color)

    def update_devices(self, ip, activity, risk_weight=0.0, potential_name=None):
        if not self.running: return
        if ip not in self.discovered_devices:
            self.discovered_devices[ip] = {'activities': [], 'risk': 0.0, 'name': potential_name}
            btn = ctk.CTkButton(self.inventory_frame, text=f"⊕ {potential_name if potential_name else 'RECON...'} \n  {ip}", 
                               command=lambda i=ip: self.select_device(i), fg_color="transparent", 
                               hover_color=COLORS["border"], text_color=COLORS["text_primary"],
                               border_width=1, border_color=COLORS["border"],
                               font=ctk.CTkFont(size=12, weight="bold"), anchor="w", height=60, 
                               corner_radius=UI_STYLE["btn_radius"])
            btn.pack(fill="x", padx=5, pady=5)
            self.device_buttons[ip] = btn
            
            # Auto-select the first device that appears
            if self.selected_device is None:
                self.after(100, lambda: self.select_device(ip))
        dev = self.discovered_devices[ip]
        if potential_name and not dev['name']:
            dev['name'] = potential_name
            self.device_buttons[ip].configure(text=f"{potential_name}\n{ip}")
        if activity not in dev['activities']:
            dev['activities'].append(activity)
            dev['risk'] = min(1.0, dev['risk'] + risk_weight)
            fg, hvr, txt = self.get_color_params(dev['risk'])
            self.device_buttons[ip].configure(border_color=fg)
            self.after(0, self.update_global_risk)

    def select_device(self, ip):
        self.selected_device = ip
        dev_data = self.discovered_devices[ip]
        self.detail_label.configure(text=f"DEVICE INTELLIGENCE: {dev_data['name'] if dev_data['name'] else ip}")
        self.detail_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self.refresh_detail_view()
        self.update_sidebar_inventory(ip)
        # Automatically switch to the Data Flow view to show intelligence
        self.show_view("flow")

    def refresh_detail_view(self):
        if not self.selected_device: return
        dev_data = self.discovered_devices[self.selected_device]
        self.detail_textbox.configure(state="normal")
        self.detail_textbox.delete("1.0", "end")
        
        risk_int = int(dev_data['risk'] * 100)
        risk_tag = "safe" if risk_int < 25 else "warning" if risk_int < 75 else "danger"
        
        self.detail_textbox.insert("end", "Device: ", "normal")
        self.detail_textbox.insert("end", f"{dev_data['name']}\n", "body_bold")
        self.detail_textbox.insert("end", "IP Address: ", "normal")
        self.detail_textbox.insert("end", f"{self.selected_device}\n", "mono")
        self.detail_textbox.insert("end", "Risk Factor: ", "normal")
        self.detail_textbox.insert("end", f"[{risk_int}%]\n", risk_tag)
        self.detail_textbox.insert("end", "─" * 40 + "\n\n", "normal")
        
        self.detail_textbox.insert("end", "DETECTION LOG:\n", "body_bold")
        for act in reversed(dev_data['activities']):
            a_tag = "normal"
            if "Unsecured" in act or "CRITICAL" in act: a_tag = "danger"
            elif "Browsing" in act or "Domain" in act: a_tag = "warning"
            elif "Identity" in act or "Broadcasting" in act or "Initiated" in act: a_tag = "safe"
            self.detail_textbox.insert("end", f" ➜ {act}\n", a_tag)
            
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
                    self.after(10, lambda m=msg, s=src, q=qname: (self.add_log(m, ip=s), self.update_devices(s, activity, risk_weight=0.01, potential_name=q.split('.')[-2].capitalize())))
                
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
                        self.after(10, lambda m=msg, s=src, a=activity: (self.add_log(m, ip=s), self.update_devices(s, a, risk_weight=0.08)))
                    
                    if is_external_dst:
                        threading.Thread(target=self.geolocate_ip, args=(dst,), daemon=True).start()
                else:
                    name = self.get_hostname(dst)
                    activity = f"Unsecured Traffic: {name}"
                    if self.should_process(src, activity):
                        msg = f"UNSECURED DATA: {src} -> {name}"
                        self.after(10, lambda m=msg, s=src, a=activity: (self.add_log(m, ip=s), self.update_devices(s, a, risk_weight=0.04)))
                    
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
                self.after(10, lambda m=msg, s=src, p=protocol, n=display_name, a=activity: (self.add_log(m, ip=s), self.update_devices(s, a, risk_weight=0.005, potential_name=n)))

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
