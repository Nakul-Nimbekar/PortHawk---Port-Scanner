import socket
import threading
import datetime
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk
import csv
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import random
import time
from tkinter import font as tkfont

import sys
if sys.executable.endswith(".exe"):  # Running as compiled EXE
    sys.stdout = open("output.log", "a")  # Redirect output
    sys.stderr = sys.stdout


# Global variables
log_file = "scan_results.txt"
scan_results = []
stop_scan = False
dark_mode = False
current_theme = {}

# Service databases
nmap_services = {}
extended_services = {
    80: "HTTP", 443: "HTTPS", 
    21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 110: "POP3",
    143: "IMAP", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    5900: "VNC", 1723: "PPTP", 500: "ISAKMP",
    161: "SNMP", 445: "SMB", 587: "SMTP-SSL",
    465: "SMTPS", 993: "IMAPS", 995: "POP3S"
}

def identify_unknown_port(ip, port):
    """Enhanced identification for unknown ports"""
    results = []
    
    # Ephemeral port ranges
    if 32768 <= port <= 60999:
        results.append("Likely ephemeral port (Linux default range)")
    elif 49152 <= port <= 65535:
        results.append("Likely ephemeral port (Windows/IANA range)")
    
    # Banner grabbing
    banner = grab_banner(ip, port)
    if banner != "No Banner":
        results.append(f"Banner: {banner[:200]}{'...' if len(banner) > 200 else ''}")
    
    # Protocol detection
    protocol = detect_protocol(ip, port)
    if protocol:
        results.append(f"Protocol hints: {protocol}")
    
    # Security checks
    malware_check = check_malware_ports(port)
    if malware_check:
        results.append(f"Security note: {malware_check}")
    
    return " | ".join(results) if results else "No additional info"

def detect_protocol(ip, port):
    """Attempt to identify protocol through behavior"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            
            # HTTP test
            s.send(b"GET / HTTP/1.0\r\n\r\n")
            if b"HTTP/" in s.recv(1024):
                return "HTTP"
            
            # Redis test
            s.send(b"INFO\r\n")
            if b"redis_version" in s.recv(1024):
                return "Redis"
            
            return None
    except:
        return None

def check_malware_ports(port):
    """Check against known malware ports"""
    malware_ports = {
        31337: "Back Orifice",
        4444: "Metasploit",
        6660: "IRC (often malware)",
        12345: "NetBus"
    }
    return malware_ports.get(port)

def load_services_from_nmap(file_path="nmap-services"):
    """Load service mappings from nmap-services file"""
    services_dict = {}
    try:
        with open(file_path, "r") as file:
            for line in file:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    service_name = parts[0]
                    port_proto = parts[1]
                    if "/tcp" in port_proto:
                        port = int(port_proto.split("/")[0])
                        services_dict[port] = service_name.upper()
        print(f"[+] Loaded {len(services_dict)} services from nmap-services")
    except Exception as e:
        print(f"[-] Error loading nmap-services: {e}")
    return services_dict



def get_service_name(port):
    """Get service name from multiple sources with priority"""
    # Try system first
    try:
        return f"{socket.getservbyport(port, 'tcp').upper()} (System)"
    except:
        pass
    
    # Then try nmap services
    if port in nmap_services:
        return f"{nmap_services[port]} (Nmap)"
    
    # Finally extended fallback
    return extended_services.get(port, f"Unknown (Port {port})")

def grab_banner(ip, port):
    """Enhanced banner grabbing with protocol-specific probes"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect((ip, port))
            
            # Protocol-specific probes
            if port == 21:  # FTP
                s.send(b"USER anonymous\r\n")
                banner = s.recv(1024).decode(errors='ignore').strip()
                s.send(b"PASS anonymous\r\n")
                banner += "\n" + s.recv(1024).decode(errors='ignore').strip()
                return banner
            elif port == 22:  # SSH
                return s.recv(1024).decode(errors='ignore').strip()
            elif port in [25, 587, 465]:  # SMTP
                banner = s.recv(1024).decode(errors='ignore').strip()
                s.send(b"EHLO example.com\r\n")
                banner += "\n" + s.recv(1024).decode(errors='ignore').strip()
                return banner
            elif port in [110, 995]:  # POP3
                banner = s.recv(1024).decode(errors='ignore').strip()
                s.send(b"CAPA\r\n")
                banner += "\n" + s.recv(1024).decode(errors='ignore').strip()
                return banner
            elif port in [143, 993]:  # IMAP
                banner = s.recv(1024).decode(errors='ignore').strip()
                s.send(b"A01 CAPABILITY\r\n")
                banner += "\n" + s.recv(1024).decode(errors='ignore').strip()
                return banner
            
            # Generic probe for other ports
            s.send(b"\r\n")
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner if banner else "No Banner"
    except Exception:
        return "No Banner"

def check_http_info(ip, port):
    """Enhanced HTTP information gathering"""
    if port not in [80, 443, 8080, 8443]:
        return {"server": "N/A", "title": "N/A", "redirect": "N/A"}
    
    try:
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{ip}:{port}"
        
        # First try HEAD request for server info
        response = requests.head(url, timeout=2, allow_redirects=True)
        server = response.headers.get("Server", "No Server Info")
        
        # Then try GET for page title
        response = requests.get(url, timeout=3, allow_redirects=True)
        title = "No Title"
        if "<title>" in response.text.lower():
            title_start = response.text.lower().find("<title>") + 7
            title_end = response.text.lower().find("</title>")
            title = response.text[title_start:title_end].strip()
        
        redirect = response.url if response.url != url else "No Redirect"
        
        return {
            "server": server,
            "title": title[:100] + "..." if len(title) > 100 else title,
            "redirect": redirect
        }
    except requests.exceptions.RequestException:
        return {"server": "No Server Info", "title": "N/A", "redirect": "N/A"}

def scan_port(ip, port): #speed_delay
    global stop_scan
    if stop_scan:
        return None
    
    # if speed_delay > 0:
    #     time.sleep(speed_delay/1000)
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                service_name = get_service_name(port)
                banner = grab_banner(ip, port)
                http_info = check_http_info(ip, port)
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Enhanced identification for unknown ports
                additional_info = ""
                if "Unknown" in service_name:
                    additional_info = identify_unknown_port(ip, port)
                
                result_data = {
                    "timestamp": timestamp,
                    "port": port,
                    "service": service_name,
                    "banner": banner,
                    "http_server": http_info["server"],
                    "http_title": http_info["title"],
                    "http_redirect": http_info["redirect"],
                    "additional_info": additional_info
                }
                
                return result_data
    except Exception as e:
        return {"error": f"Port {port}: {str(e)[:100]}"}
    return None

def scan_ports(ip, start_port, end_port, text_widget, progress_label, progress_bar): #speed_var, randomize_var
    """Main scanning function with chunked processing and enhanced output"""
    global stop_scan, scan_results
    stop_scan = False
    scan_results = []
    
    total_ports = end_port - start_port + 1
    progress_bar["maximum"] = total_ports
    scanned_ports = 0
    # speed_delay = (100 - speed_var.get()) / 10  # Convert #speed to delay
    
    # Prepare port list (randomized if requested)
    ports = list(range(start_port, end_port + 1))
    # if randomize_var.get():
    #     random.shuffle(ports)
    
    chunk_size = min(200, max(50, len(ports) // 10))  # Dynamic chunk size
    chunked_ports = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]
    
    with ThreadPoolExecutor(max_workers=200) as executor:
        for chunk in chunked_ports:
            if stop_scan:
                break
            
            futures = {executor.submit(scan_port, ip, port): port for port in chunk} #speed_delay
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        if "error" in result:
                            text_widget.after(0, lambda r=result: text_widget.insert(tk.END, f"{r['error']}\n"))
                        else:
                            scan_results.append(result)
                            
                            # Build enhanced output
                            output = [
                                f"[{result['timestamp']}] Port {result['port']}: {result['service']}"
                            ]
                            
                            # Add additional info for unknown ports
                            if "additional_info" in result and result["additional_info"]:
                                output.append(f"  Additional: {result['additional_info']}")
                            
                            # Add banner information if available
                            if result['banner'] != "No Banner":
                                banner = result['banner']
                                if len(banner) > 200:
                                    banner = banner[:200] + "..."
                                output.append(f"  Banner: {banner}")
                            
                            # Add HTTP info if available
                            if result['http_server'] != "N/A":
                                output.extend([
                                    f"  HTTP Server: {result['http_server']}",
                                    f"  Page Title: {result['http_title']}",
                                    f"  Redirect: {result['http_redirect']}"
                                ])
                            
                            # Add security warnings if found
                            if "security_warning" in result:
                                output.append(f"  SECURITY WARNING: {result['security_warning']}")
                                time.sleep(2)
                            
                            # Insert the formatted output
                            text_widget.after(0, lambda o="\n".join(output): text_widget.insert(tk.END, o + "\n\n"))
                            
                except Exception as e:
                    text_widget.after(0, lambda e=e: text_widget.insert(tk.END, f"[Error] {e}\n"))
                finally:
                    scanned_ports += 1
                    progress_bar.after(0, lambda: progress_bar.step(1))
                    progress_label.after(0, lambda: progress_label.config(
                        text=f"Scanned {scanned_ports}/{total_ports} ports | "
                             f"Open: {len([r for r in scan_results if 'port' in r])} | "
                             f"Security Warnings: {len([r for r in scan_results if 'security_warning' in r])}"
                    ))
    
    if not stop_scan:
        text_widget.after(0, lambda: text_widget.insert(tk.END, "\nScan complete!\n"))
        progress_label.after(0, lambda: progress_label.config(text="Scan complete!"))
    start_button.after(0, lambda: start_button.config(state=tk.NORMAL))
    stop_button.after(0, lambda: stop_button.config(state=tk.DISABLED))

def start_scan():
    """Validate inputs and start scanning thread"""
    global stop_scan
    stop_scan = False
    
    target_ip = ip_entry.get()
    try:
        socket.inet_aton(target_ip)
        start_port = int(port_start_entry.get())
        end_port = int(port_end_entry.get())
        
        if start_port > end_port:
            messagebox.showerror("Invalid Range", "Start port must be <= end port")
            return
        if end_port > 65535:
            messagebox.showerror("Invalid Port", "Port cannot exceed 65535")
            return
        
        output_text.delete(1.0, tk.END)
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)
        progress_bar["value"] = 0
        progress_label.config(text="Starting scan...")
        
        threading.Thread(
            target=scan_ports,
            args=(
                target_ip, 
                start_port, 
                end_port, 
                output_text, 
                progress_label, 
                progress_bar,
                # speed_slider,
                # randomize_var
            ),
            daemon=True
        ).start()
        
    except socket.error:
        messagebox.showerror("Invalid IP", "Please enter a valid IP address")
    except ValueError:
        messagebox.showerror("Invalid Port", "Please enter valid port numbers")

def stop_scanning():
    """Stop the current scan"""
    global stop_scan
    stop_scan = True
    progress_label.config(text="Stopping scan...")

def save_results():
    file_types = [
        ("CSV files", "*.csv"),
        ("JSON files", "*.json"),
        ("Text files", "*.txt")
    ]
    
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=file_types)
    
    if not file_path:
        return
    
    try:
        if file_path.endswith('.csv'):
            with open(file_path, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([
                    "Timestamp", "Port", "Service", "Banner",
                    "HTTP Server", "Page Title", "Redirect", "Additional Info"
                ])
                for result in scan_results:
                    if "port" in result:
                        writer.writerow([
                            result["timestamp"],
                            result["port"],
                            result["service"],
                            result["banner"],
                            result["http_server"],
                            result["http_title"],
                            result["http_redirect"],
                            result.get("additional_info", "")
                        ])
        
        elif file_path.endswith('.json'):
            with open(file_path, "w") as jsonfile:
                json.dump(scan_results, jsonfile, indent=2)
        
        elif file_path.endswith('.txt'):
            with open(file_path, "w") as txtfile:
                for result in scan_results:
                    if "port" in result:
                        txtfile.write(
                            f"[{result['timestamp']}] Port {result['port']}: "
                            f"{result['service']}\n"
                        )
                        if result.get("additional_info"):
                            txtfile.write(f"  Additional: {result['additional_info']}\n")
                        if result['banner'] != "No Banner":
                            txtfile.write(f"  Banner: {result['banner']}\n")
                        if result['http_server'] != "N/A":
                            txtfile.write(
                                f"  HTTP Server: {result['http_server']}\n"
                                f"  Page Title: {result['http_title']}\n"
                                f"  Redirect: {result['http_redirect']}\n"
                            )
                        txtfile.write("\n")
        
        messagebox.showinfo("Success", f"Results saved to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save file: {e}")

def toggle_dark_mode():
    """Toggle between dark and light themes using proper ttk styling"""
    global dark_mode
    
    dark_mode = not dark_mode
    style = ttk.Style()
    
    if dark_mode:
        # Dark theme configuration
        style.theme_use('alt')
        
        # Configure colors for dark theme
        bg_color = '#2d2d2d'
        text_color = '#ffffff'
        entry_bg = '#3a3a3a'
        button_bg = '#3a3a3a'
        text_widget_bg = '#1e1e1e'
        text_widget_fg = '#e0e0e0'
        
        # Configure ttk styles
        style.configure('.', 
                      background=bg_color,
                      foreground=text_color,
                      fieldbackground=entry_bg)
        
        style.configure('TLabel', background=bg_color, foreground=text_color)
        style.configure('TButton', 
                       background=button_bg, 
                       foreground=text_color,
                       relief='raised')
        style.configure('TEntry', 
                       fieldbackground=entry_bg, 
                       foreground=text_color,
                       insertcolor=text_color)
        style.configure('TFrame', background=bg_color)
        style.configure('TLabelframe', 
                       background=bg_color, 
                       foreground=text_color)
        style.configure('TLabelframe.Label', 
                       background=bg_color, 
                       foreground=text_color)
        style.configure('Vertical.TScrollbar', 
                       background=button_bg,
                       troughcolor=bg_color)
        
        # Configure standard tkinter widgets
        output_text.config(
            bg=text_widget_bg,
            fg=text_widget_fg,
            insertbackground=text_color
        )
        
    else:
        # Light theme configuration
        style.theme_use('clam')
        
        # Configure colors for light theme
        bg_color = '#f0f0f0'
        text_color = '#000000'
        entry_bg = '#ffffff'
        button_bg = '#e0e0e0'
        text_widget_bg = '#ffffff'
        text_widget_fg = '#000000'
        
        # Configure ttk styles
        style.configure('.', 
                      background=bg_color,
                      foreground=text_color,
                      fieldbackground=entry_bg)
        
        style.configure('TLabel', background=bg_color, foreground=text_color)
        style.configure('TButton', 
                       background=button_bg, 
                       foreground=text_color,
                       relief='raised')
        style.configure('TEntry', 
                       fieldbackground=entry_bg, 
                       foreground=text_color,
                       insertcolor=text_color)
        style.configure('TFrame', background=bg_color)
        style.configure('TLabelframe', 
                       background=bg_color, 
                       foreground=text_color)
        style.configure('TLabelframe.Label', 
                       background=bg_color, 
                       foreground=text_color)
        style.configure('Vertical.TScrollbar', 
                       background=button_bg,
                       troughcolor=bg_color)
        
        # Configure standard tkinter widgets
        output_text.config(
            bg=text_widget_bg,
            fg=text_widget_fg,
            insertbackground=text_color
        )
    
    # Update all child widgets
    for widget in root.winfo_children():
        widget_class = widget.winfo_class()
        if widget_class == 'Text':
            # Skip as we've already configured the text widget
            continue
        try:
            # Force widget update
            widget['style'] = widget['style']
        except:
            pass

def apply_theme():
    """Apply the current theme to all widgets"""
    root.config(bg=current_theme["bg"])
    
    for widget in root.winfo_children():
        widget_type = widget.winfo_class()
        
        if widget_type == "TLabel":
            widget.config(
                bg=current_theme["bg"],
                fg=current_theme["fg"]
            )
        elif widget_type == "TButton":
            widget.config(
                bg=current_theme["button_bg"],
                fg=current_theme["button_fg"],
                highlightbackground=current_theme["highlight"]
            )
        elif widget_type == "TEntry":
            widget.config(
                bg=current_theme["entry_bg"],
                fg=current_theme["entry_fg"],
                insertbackground=current_theme["fg"]
            )
        elif widget_type == "Text" or widget_type == "ScrolledText":
            widget.config(
                bg=current_theme["text_bg"],
                fg=current_theme["text_fg"],
                insertbackground=current_theme["fg"]
            )
        elif widget_type == "TCheckbutton":
            widget.config(
                bg=current_theme["bg"],
                fg=current_theme["fg"],
                selectcolor=current_theme["bg"]
            )
        elif widget_type == "TFrame":
            widget.config(bg=current_theme["bg"])

def validate_ports(action, value_if_allowed):
    """Validate port number entries"""
    if action == '1':  # Insert
        if value_if_allowed.isdigit():
            num = int(value_if_allowed)
            return 0 <= num <= 65535
        return False
    return True

def show_warning():
    """Show scanning disclaimer"""
    disclaimer = (
        "WARNING: Port scanning without permission is illegal in many jurisdictions.\n\n"
        "This tool is for educational and authorized security testing only.\n"
        "By using this tool, you agree that you have permission to scan the target system."
    )
    messagebox.showwarning("Disclaimer", disclaimer)

# Initialize nmap services
# nmap_services = load_services_from_nmap()

# Create main window
root = tk.Tk()
root.title("PortHawk - Advanced Port Scanner")
root.geometry("800x700")


# Register port validation
vcmd = root.register(validate_ports)

# Create menu bar
menubar = tk.Menu(root)
filemenu = tk.Menu(menubar, tearoff=0)
filemenu.add_command(label="Save Results", command=save_results)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="File", menu=filemenu)

helpmenu = tk.Menu(menubar, tearoff=0)
helpmenu.add_command(label="About", command=show_warning)
menubar.add_cascade(label="Help", menu=helpmenu)
root.config(menu=menubar)

# Create main container
main_frame = ttk.Frame(root, padding="10")
main_frame.pack(fill=tk.BOTH, expand=True)

# Target IP Section
ip_frame = ttk.LabelFrame(main_frame, text="Target Information", padding="10")
ip_frame.pack(fill=tk.X, pady=5)

ttk.Label(ip_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=tk.W)
ip_entry = ttk.Entry(ip_frame, width=30)
ip_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
ip_entry.insert(0, "127.0.0.1")

# Port Range Section
port_frame = ttk.LabelFrame(main_frame, text="Port Range", padding="10")
port_frame.pack(fill=tk.X, pady=5)

ttk.Label(port_frame, text="Start Port:").grid(row=0, column=0, sticky=tk.W)
port_start_entry = ttk.Entry(port_frame, width=10, validate="key", validatecommand=(vcmd, '%d', '%P'))
port_start_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
port_start_entry.insert(0, "1")

ttk.Label(port_frame, text="End Port:").grid(row=0, column=2, sticky=tk.W, padx=(10, 0))
port_end_entry = ttk.Entry(port_frame, width=10, validate="key", validatecommand=(vcmd, '%d', '%P'))
port_end_entry.grid(row=0, column=3, sticky=tk.W, padx=5)
port_end_entry.insert(0, "1024")

# Quick Port Presets
quick_ports_frame = ttk.Frame(port_frame)
quick_ports_frame.grid(row=1, column=0, columnspan=4, pady=(20, 0))

quick_ports = {
    "Common (1-1024)": (1, 1024),
    "Web (80,443,8080)": (80, 8080),
    "Database (3306,5432)": (3306, 5432),
    "Full (1-65535)": (1, 65535)
}

for i, (text, ports) in enumerate(quick_ports.items()):
    btn = ttk.Button(
        quick_ports_frame, 
        text=text, 
        width=20,
        command=lambda p=ports: (port_start_entry.delete(0, tk.END), port_start_entry.insert(0, str(p[0])),
                              port_end_entry.delete(0, tk.END), port_end_entry.insert(0, str(p[1])))
    )
    btn.grid(row=0, column=i, padx=2)

# Scan Options
options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="10")
options_frame.pack(fill=tk.X, pady=5)

# ttk.Label(options_frame, text="Scan Speed:").grid(row=0, column=0, sticky=tk.W)
# speed_slider = ttk.Scale(options_frame, from_=1, to=100, orient=tk.HORIZONTAL)
# speed_slider.set(50)
# speed_slider.grid(row=0, column=1, sticky=tk.W, padx=5)

# randomize_var = tk.BooleanVar()
# randomize_check = ttk.Checkbutton(
#     options_frame, 
#     text="Randomize Port Order", 
#     variable=randomize_var
# )
# randomize_check.grid(row=0, column=2, padx=10)

dark_mode_var = tk.BooleanVar()
dark_mode_check = ttk.Checkbutton(
    options_frame, 
    text="Dark Mode", 
    variable=dark_mode_var,
    command=toggle_dark_mode
)
dark_mode_check.grid(row=0, column=3, padx=10)

# Control Buttons
button_frame = ttk.Frame(main_frame)
button_frame.pack(fill=tk.X, pady=10)

start_button = ttk.Button(
    button_frame, 
    text="Start Scan", 
    command=start_scan,
    style="Accent.TButton"
)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = ttk.Button(
    button_frame, 
    text="Stop Scan", 
    command=stop_scanning,
    state=tk.DISABLED
)
stop_button.pack(side=tk.LEFT, padx=5)

save_button = ttk.Button(
    button_frame, 
    text="Save Results", 
    command=save_results
)
save_button.pack(side=tk.RIGHT, padx=5)

# Progress Display
progress_frame = ttk.Frame(main_frame)
progress_frame.pack(fill=tk.X, pady=5)

progress_label = ttk.Label(progress_frame, text="Ready to scan")
progress_label.pack(anchor=tk.W)

progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=400, mode="determinate")
progress_bar.pack(fill=tk.X)

# Output Display
output_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
output_frame.pack(fill=tk.BOTH, expand=True)

output_text = scrolledtext.ScrolledText(
    output_frame, 
    width=80, 
    height=20,
    font=tkfont.Font(family="Consolas", size=10)
)
output_text.pack(fill=tk.BOTH, expand=True)

# Status Bar
status_bar = ttk.Label(root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

# Apply default theme
toggle_dark_mode()  # Starts with dark mode off (light theme)

# Initialize style
style = ttk.Style()
style.theme_use('clam')  # Start with light theme
dark_mode = False

#Show warning on first run
root.after(500, show_warning)

# Start the application
root.mainloop()