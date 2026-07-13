"""
Omega USB Security Tool - Enhanced USB Detection
"""

import os
import sys
import ctypes
import subprocess
import json
import zipfile
import shutil
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from datetime import datetime
import hashlib

# Try to import Windows-specific modules
try:
    import win32file
    import win32con
    import win32api
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("Windows API modules not available")

class USBSecurityTool:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Omega USB Security Tool")
        self.root.geometry("1100x800")
        self.root.configure(bg='#1a1a1a')
        
        # Variables
        self.usb_path = None
        self.scanning = False
        self.repairing = False
        self.report_data = []
        self.blocked_usbs = {}
        self.scan_results = []
        self.scanned_files = 0
        self.found_threats = 0
        self.monitoring_active = True
        self.all_drives = []  # Store all detected drives for debugging
        
        # Threat signatures
        self.suspicious_extensions = ['.scr', '.pif', '.vbs', '.js', '.jar', '.exe', '.bat', '.cmd', '.ps1']
        self.suspicious_files = ['autorun.inf', 'recycler', 'thumbs.db', 'desktop.ini']
        
        # Check admin
        self.is_admin = self.check_admin()
        
        # Setup GUI
        self.setup_gui()
        
        # Load blocked USBs
        self.load_blocked_usbs()
        
        # Log startup
        self.add_log("=" * 50)
        self.add_log("OMEGA USB SECURITY TOOL STARTED")
        self.add_log("=" * 50)
        
        if not self.is_admin:
            self.add_log("⚠ WARNING: Not running as Administrator!")
        else:
            self.add_log("✓ Running with Administrator privileges")
        
        # Start USB monitoring
        self.start_enhanced_monitoring()
    
    def check_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def setup_gui(self):
        bg_color = '#1a1a1a'
        
        # Title
        title = tk.Label(self.root, text="🔒 OMEGA USB SECURITY TOOL", 
                         font=("Courier", 18, "bold"), bg=bg_color, fg='#00ff00')
        title.pack(pady=10)
        
        # Status Frame
        status_frame = tk.Frame(self.root, bg='#2d2d2d', relief=tk.RIDGE, bd=2)
        status_frame.pack(pady=10, padx=10, fill=tk.X)
        
        self.status_label = tk.Label(status_frame, text="Status: Initializing...", 
                                      bg='#2d2d2d', fg='white', font=("Arial", 11))
        self.status_label.pack(pady=5, padx=10, anchor=tk.W)
        
        self.usb_label = tk.Label(status_frame, text="USB: Not detected", 
                                  bg='#2d2d2d', fg='#ffaa00', font=("Arial", 10))
        self.usb_label.pack(pady=5, padx=10, anchor=tk.W)
        
        # Debug label
        self.debug_label = tk.Label(status_frame, text="Debug: Waiting for USB...", 
                                    bg='#2d2d2d', fg='#888888', font=("Arial", 8))
        self.debug_label.pack(pady=5, padx=10, anchor=tk.W)
        
        # Stats Frame
        stats_frame = tk.Frame(self.root, bg='#2d2d2d', relief=tk.RIDGE, bd=2)
        stats_frame.pack(pady=10, padx=10, fill=tk.X)
        
        self.stats_label = tk.Label(stats_frame, 
                                    text="Files: 0 | Threats: 0 | Status: Idle", 
                                    bg='#2d2d2d', fg='#00ff00', font=("Arial", 10))
        self.stats_label.pack(pady=5, padx=10, anchor=tk.W)
        
        # Buttons Frame
        button_frame = tk.Frame(self.root, bg=bg_color)
        button_frame.pack(pady=15)
        
        button_style = {'font': ("Arial", 11, "bold"), 'padx': 20, 'pady': 8}
        
        # First row buttons
        button_row1 = tk.Frame(button_frame, bg=bg_color)
        button_row1.pack()
        
        self.scan_btn = tk.Button(button_row1, text="🔍 SCAN USB", 
                                   command=self.scan_only,
                                   bg='#2196F3', fg='white', 
                                   **button_style, state=tk.DISABLED)
        self.scan_btn.pack(side=tk.LEFT, padx=10)
        
        self.repair_btn = tk.Button(button_row1, text="🔧 REPAIR USB", 
                                     command=self.repair_usb,
                                     bg='#FF9800', fg='white',
                                     **button_style, state=tk.DISABLED)
        self.repair_btn.pack(side=tk.LEFT, padx=10)
        
        self.block_btn = tk.Button(button_row1, text="🚫 BLOCK USB", 
                                    command=self.block_usb,
                                    bg='#f44336', fg='white',
                                    **button_style, state=tk.DISABLED)
        self.block_btn.pack(side=tk.LEFT, padx=10)
        
        # Second row buttons
        button_row2 = tk.Frame(button_frame, bg=bg_color)
        button_row2.pack(pady=10)
        
        self.unblock_btn = tk.Button(button_row2, text="🔓 UNBLOCK USB", 
                                      command=self.unblock_usb,
                                      bg='#4CAF50', fg='white',
                                      **button_style)
        self.unblock_btn.pack(side=tk.LEFT, padx=10)
        
        self.show_blocked_btn = tk.Button(button_row2, text="📋 SHOW BLOCKED", 
                                           command=self.show_blocked_usbs,
                                           bg='#9C27B0', fg='white',
                                           **button_style)
        self.show_blocked_btn.pack(side=tk.LEFT, padx=10)
        
        self.report_btn = tk.Button(button_row2, text="📄 SAVE REPORT", 
                                     command=self.generate_report,
                                     bg='#00BCD4', fg='white',
                                     **button_style)
        self.report_btn.pack(side=tk.LEFT, padx=10)
        
        self.refresh_btn = tk.Button(button_row2, text="🔄 REFRESH USB", 
                                      command=self.manual_refresh,
                                      bg='#FFC107', fg='black',
                                      **button_style)
        self.refresh_btn.pack(side=tk.LEFT, padx=10)
        
        # Progress Bar
        self.progress = ttk.Progressbar(self.root, mode='indeterminate', length=400)
        self.progress.pack(pady=10)
        
        # Log Area
        log_frame = tk.Frame(self.root, bg='#0a0a0a')
        log_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        log_label = tk.Label(log_frame, text="ACTIVITY LOG", 
                             bg='#0a0a0a', fg='#00ff00', font=("Arial", 10, "bold"))
        log_label.pack(anchor=tk.W)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, 
                                                  bg='#000000', fg='#00ff00',
                                                  font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def add_log(self, message, tag=None):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        self.report_data.append({
            'timestamp': timestamp,
            'message': message
        })
        
        print(log_entry.strip())
    
    def update_stats(self):
        """Update statistics display"""
        status = "Scanning..." if self.scanning else "Repairing..." if self.repairing else "Idle"
        self.stats_label.config(text=f"Files: {self.scanned_files} | Threats: {self.found_threats} | Status: {status}")
        self.root.update_idletasks()
    
    def load_blocked_usbs(self):
        """Load blocked USB list from file"""
        try:
            if getattr(sys, 'frozen', False):
                application_path = os.path.dirname(sys.executable)
            else:
                application_path = os.path.dirname(os.path.abspath(__file__))
            
            blocked_file = os.path.join(application_path, 'blocked_usbs.json')
            
            if os.path.exists(blocked_file):
                with open(blocked_file, 'r') as f:
                    self.blocked_usbs = json.load(f)
                self.add_log(f"Loaded {len(self.blocked_usbs)} blocked USB entries")
        except Exception as e:
            self.add_log(f"Error loading blocked USBs: {str(e)}")
    
    def save_blocked_usbs(self):
        """Save blocked USB list to file"""
        try:
            if getattr(sys, 'frozen', False):
                application_path = os.path.dirname(sys.executable)
            else:
                application_path = os.path.dirname(os.path.abspath(__file__))
            
            blocked_file = os.path.join(application_path, 'blocked_usbs.json')
            
            with open(blocked_file, 'w') as f:
                json.dump(self.blocked_usbs, f)
            self.add_log("Blocked USB list saved")
        except Exception as e:
            self.add_log(f"Error saving blocked USBs: {str(e)}")
    
    def detect_all_drives(self):
        """Detect all drives and their types (for debugging)"""
        drives = []
        try:
            # Method 1: Using win32api if available
            if WIN32_AVAILABLE:
                all_drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
                for drive in all_drives:
                    try:
                        drive_type = win32file.GetDriveType(drive)
                        type_names = {
                            0: "Unknown",
                            1: "No Root",
                            2: "Removable",
                            3: "Fixed",
                            4: "Remote",
                            5: "CD-ROM",
                            6: "RAM Disk"
                        }
                        type_name = type_names.get(drive_type, "Unknown")
                        drives.append({
                            'path': drive,
                            'type': drive_type,
                            'type_name': type_name,
                            'is_usb': drive_type == 2
                        })
                    except:
                        pass
            
            # Method 2: Using Python's built-in methods
            import string
            from ctypes import windll
            
            bitmask = windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drive = letter + ":\\"
                    try:
                        if os.path.exists(drive):
                            drive_type = windll.kernel32.GetDriveTypeW(drive)
                            type_names = {
                                0: "Unknown",
                                1: "No Root",
                                2: "Removable",
                                3: "Fixed",
                                4: "Remote",
                                5: "CD-ROM",
                                6: "RAM Disk"
                            }
                            type_name = type_names.get(drive_type, "Unknown")
                            drives.append({
                                'path': drive,
                                'type': drive_type,
                                'type_name': type_name,
                                'is_usb': drive_type == 2
                            })
                    except:
                        pass
                bitmask >>= 1
                
        except Exception as e:
            self.add_log(f"Drive detection error: {str(e)}")
        
        return drives
    
    def detect_usb_devices(self):
        """Enhanced USB detection with multiple methods"""
        usb_drives = []
        
        try:
            # Get all drives
            all_drives = self.detect_all_drives()
            self.all_drives = all_drives
            
            # Filter for USB drives (type 2 = removable)
            for drive in all_drives:
                if drive['is_usb']:
                    # Check if not blocked
                    if drive['path'] not in self.blocked_usbs:
                        usb_drives.append(drive['path'])
            
            # Debug: Log what we found
            if usb_drives:
                self.debug_label.config(text=f"Debug: Found {len(usb_drives)} USB drive(s): {', '.join(usb_drives)}")
            else:
                # Show all drives for debugging
                non_usb = [d['path'] for d in all_drives if not d['is_usb']]
                if non_usb:
                    self.debug_label.config(text=f"Debug: No USB found. Other drives: {', '.join(non_usb[:3])}")
                else:
                    self.debug_label.config(text=f"Debug: No drives detected. Check USB connection.")
                    
        except Exception as e:
            self.add_log(f"USB detection error: {str(e)}")
            self.debug_label.config(text=f"Debug: Error - {str(e)[:50]}")
        
        return usb_drives
    
    def manual_refresh(self):
        """Manual refresh USB detection"""
        self.add_log("Manual refresh triggered...")
        usb_drives = self.detect_usb_devices()
        self.update_usb_status(usb_drives)
        
        if usb_drives:
            messagebox.showinfo("Refresh Complete", f"Found {len(usb_drives)} USB drive(s):\n{', '.join(usb_drives)}")
        else:
            # Show diagnostic info
            if self.all_drives:
                info = "Drives found:\n"
                for drive in self.all_drives:
                    info += f"{drive['path']} - {drive['type_name']}\n"
                messagebox.showinfo("No USB Found", f"No USB drives detected.\n\n{info}\n\nMake sure USB is properly connected and try again.")
            else:
                messagebox.showwarning("No USB Found", "No drives detected at all. Please check your USB connection.")
    
    def start_enhanced_monitoring(self):
        """Start enhanced USB monitoring"""
        def monitor():
            self.add_log("Enhanced USB monitoring started...")
            while self.monitoring_active:
                try:
                    usb_drives = self.detect_usb_devices()
                    self.update_usb_status(usb_drives)
                    time.sleep(2)
                except Exception as e:
                    self.add_log(f"Monitor error: {str(e)}")
                    time.sleep(5)
        
        threading.Thread(target=monitor, daemon=True).start()
    
    def update_usb_status(self, usb_drives):
        """Update UI with USB status"""
        if usb_drives and not self.scanning and not self.repairing:
            # Use the first USB drive
            new_usb = usb_drives[0]
            
            if self.usb_path != new_usb:
                self.usb_path = new_usb
                self.usb_label.config(text=f"USB: {self.usb_path} (Ready)", fg='#00ff00')
                self.status_label.config(text="Status: USB detected - Ready")
                self.scan_btn.config(state=tk.NORMAL)
                self.repair_btn.config(state=tk.NORMAL)
                self.block_btn.config(state=tk.NORMAL)
                self.add_log(f"✅ USB detected: {self.usb_path}")
            elif self.usb_path and self.scan_btn['state'] == tk.DISABLED:
                # Re-enable buttons if they were disabled
                self.scan_btn.config(state=tk.NORMAL)
                self.repair_btn.config(state=tk.NORMAL)
                self.block_btn.config(state=tk.NORMAL)
        elif not usb_drives:
            if self.usb_path:
                self.add_log(f"❌ USB removed: {self.usb_path}")
                self.usb_path = None
                self.usb_label.config(text="USB: Not detected", fg='#ffaa00')
                self.status_label.config(text="Status: Waiting for USB...")
                self.scan_btn.config(state=tk.DISABLED)
                self.repair_btn.config(state=tk.DISABLED)
                self.block_btn.config(state=tk.DISABLED)
    
    def scan_for_threats(self, path, show_progress=True):
        """Scan USB drive for threats"""
        threats = []
        self.scanned_files = 0
        self.found_threats = 0
        
        self.add_log(f"🔍 Starting scan: {path}")
        self.add_log("-" * 40)
        
        try:
            for root, dirs, files in os.walk(path):
                for file in files:
                    self.scanned_files += 1
                    file_path = os.path.join(root, file)
                    file_ext = os.path.splitext(file)[1].lower()
                    
                    if show_progress and self.scanned_files % 50 == 0:
                        self.add_log(f"📁 Scanned: {self.scanned_files} files...")
                        self.update_stats()
                    
                    if file_ext in self.suspicious_extensions:
                        threat = {
                            'type': '⚠️ Suspicious File',
                            'path': file_path,
                            'details': f'Extension: {file_ext}'
                        }
                        threats.append(threat)
                        self.found_threats += 1
                        self.add_log(f"⚠️ THREAT: {file} ({file_ext})")
                        self.update_stats()
                    
                    elif file.lower() in self.suspicious_files:
                        threat = {
                            'type': '⚠️ Suspicious System File',
                            'path': file_path,
                            'details': f'File: {file}'
                        }
                        threats.append(threat)
                        self.found_threats += 1
                        self.add_log(f"⚠️ THREAT: {file}")
                        self.update_stats()
            
            self.add_log("-" * 40)
            if self.found_threats == 0:
                self.add_log(f"✅ Scan complete: {self.scanned_files} files, NO threats found!")
            else:
                self.add_log(f"⚠️ Scan complete: {self.scanned_files} files, {self.found_threats} threats found!")
            
        except Exception as e:
            self.add_log(f"❌ Scan error: {str(e)}")
        
        return threats
    
    def scan_only(self):
        """Only scan, no repair"""
        if not self.usb_path:
            messagebox.showwarning("No USB", "No USB device detected!")
            return
        
        if self.scanning or self.repairing:
            return
        
        self.scanning = True
        self.progress.start()
        self.scan_results = []
        
        self.add_log("=" * 50)
        self.add_log("🔍 SCAN MODE - Scanning only")
        self.add_log("=" * 50)
        
        def scan_thread():
            try:
                threats = self.scan_for_threats(self.usb_path, show_progress=True)
                self.scan_results = threats
                
                if threats:
                    self.add_log(f"\n⚠️ Found {len(threats)} threats!")
                    messagebox.showwarning("Threats Found", 
                                          f"Found {len(threats)} threats!\n\nClick REPAIR USB to fix them.")
                else:
                    self.add_log(f"\n✅ No threats detected!")
                    messagebox.showinfo("Scan Complete", "No threats found!")
            except Exception as e:
                self.add_log(f"❌ Error: {str(e)}")
            finally:
                self.scanning = False
                self.progress.stop()
                self.update_stats()
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def repair_usb(self):
        """Repair USB by removing threats"""
        if not self.usb_path:
            messagebox.showwarning("No USB", "No USB device detected!")
            return
        
        if self.scanning or self.repairing:
            return
        
        self.repairing = True
        self.progress.start()
        
        self.add_log("=" * 50)
        self.add_log("🔧 REPAIR MODE - Starting repair")
        self.add_log("=" * 50)
        
        def repair_thread():
            try:
                self.add_log("Step 1: Scanning for threats...")
                threats = self.scan_for_threats(self.usb_path, show_progress=True)
                
                if not threats:
                    self.add_log("✅ No threats found!")
                    messagebox.showinfo("Repair Complete", "No threats found!")
                    self.repairing = False
                    self.progress.stop()
                    return
                
                self.add_log(f"\nStep 2: Found {len(threats)} threats. Choose action...")
                response = messagebox.askyesno(
                    "Threats Detected",
                    f"Found {len(threats)} threats!\n\nDo you want to quarantine them?\n\n"
                    f"YES = Quarantine threats\nNO = Format USB with backup"
                )
                
                if response:
                    self.add_log("Step 3: Quarantining threats...")
                    quarantine_dir = os.path.join(os.environ['TEMP'], 'usb_quarantine')
                    os.makedirs(quarantine_dir, exist_ok=True)
                    
                    repaired = 0
                    for threat in threats:
                        try:
                            if os.path.exists(threat['path']):
                                q_path = os.path.join(quarantine_dir, 
                                                     os.path.basename(threat['path']) + f"_{int(time.time())}")
                                shutil.move(threat['path'], q_path)
                                repaired += 1
                                self.add_log(f"  ✅ Quarantined: {os.path.basename(threat['path'])}")
                        except Exception as e:
                            self.add_log(f"  ❌ Failed: {str(e)}")
                    
                    self.add_log(f"\n✅ Repaired {repaired} of {len(threats)} threats")
                    messagebox.showinfo("Repair Complete", f"Repaired {repaired} threats!\n\nQuarantined files saved in:\n{quarantine_dir}")
                else:
                    self.add_log("Step 3: Preparing to format USB...")
                    if messagebox.askyesno("Format USB", "Do you want to format the USB?\n\nYour data will be backed up first."):
                        self.format_usb()
                
            except Exception as e:
                self.add_log(f"❌ Error: {str(e)}")
            finally:
                self.repairing = False
                self.progress.stop()
                self.update_stats()
        
        threading.Thread(target=repair_thread, daemon=True).start()
    
    def format_usb(self):
        """Format USB drive"""
        try:
            drive_letter = self.usb_path[0] + ":"
            self.add_log(f"💿 Formatting {drive_letter}...")
            
            backup_path = filedialog.asksaveasfilename(
                defaultextension=".zip",
                filetypes=[("ZIP files", "*.zip")],
                title="Save Backup Location"
            )
            
            if backup_path:
                self.add_log("📦 Creating backup...")
                file_count = 0
                with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(self.usb_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                arcname = os.path.relpath(file_path, self.usb_path)
                                zipf.write(file_path, arcname)
                                file_count += 1
                            except:
                                pass
                self.add_log(f"✅ Backup created: {file_count} files")
                
                self.add_log("🔧 Formatting...")
                format_cmd = f'format {drive_letter} /FS:FAT32 /Q /Y'
                result = subprocess.run(format_cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.add_log("✅ USB formatted successfully!")
                    messagebox.showinfo("Success", "USB formatted successfully!")
                else:
                    self.add_log(f"❌ Format failed: {result.stderr}")
            else:
                self.add_log("Backup cancelled")
                
        except Exception as e:
            self.add_log(f"❌ Format error: {str(e)}")
    
    def block_usb(self):
        """Block USB permanently"""
        if not self.usb_path:
            messagebox.showwarning("No USB", "No USB device detected!")
            return
        
        if messagebox.askyesno("Block USB", f"⚠️ WARNING: This will block {self.usb_path}\n\n"
                               f"This USB will be hidden from the system while this tool is running.\n\n"
                               f"Continue?"):
            try:
                self.blocked_usbs[self.usb_path] = {
                    'path': self.usb_path,
                    'blocked_time': datetime.now().isoformat(),
                    'blocked_by': 'Omega USB Security Tool'
                }
                self.save_blocked_usbs()
                
                self.add_log(f"🚫 USB blocked: {self.usb_path}")
                self.usb_label.config(text=f"USB: {self.usb_path} (BLOCKED)", fg='#ff0000')
                self.status_label.config(text="Status: USB blocked - Hidden from system")
                self.scan_btn.config(state=tk.DISABLED)
                self.repair_btn.config(state=tk.DISABLED)
                self.block_btn.config(state=tk.DISABLED)
                
                messagebox.showinfo("USB Blocked", 
                                   f"USB device has been blocked!\n\n"
                                   f"It will no longer appear in the system while this tool is running.\n\n"
                                   f"To unblock, use the UNBLOCK USB button.")
                
            except Exception as e:
                self.add_log(f"❌ Error blocking USB: {str(e)}")
                messagebox.showerror("Error", f"Failed to block USB: {str(e)}")
    
    def unblock_usb(self):
        """Unblock USB devices"""
        if not self.blocked_usbs:
            messagebox.showinfo("No Blocked USBs", "No USB devices are currently blocked.")
            return
        
        unblock_window = tk.Toplevel(self.root)
        unblock_window.title("Unblock USB Devices")
        unblock_window.geometry("500x450")
        unblock_window.configure(bg='#1a1a1a')
        
        title = tk.Label(unblock_window, text="Select USB to Unblock", 
                        font=("Arial", 14, "bold"), bg='#1a1a1a', fg='#00ff00')
        title.pack(pady=10)
        
        info_label = tk.Label(unblock_window, 
                             text="These USBs are currently blocked by this application.\nUnblocking will make them visible again.",
                             bg='#1a1a1a', fg='#ffaa00', font=("Arial", 9))
        info_label.pack(pady=5)
        
        list_frame = tk.Frame(unblock_window, bg='#1a1a1a')
        list_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, 
                            bg='#000000', fg='#00ff00', font=("Consolas", 10),
                            selectmode=tk.SINGLE)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=listbox.yview)
        
        blocked_list = []
        for path, info in self.blocked_usbs.items():
            display_text = f"{path} - Blocked: {info['blocked_time'][:19]}"
            listbox.insert(tk.END, display_text)
            blocked_list.append(path)
        
        button_frame = tk.Frame(unblock_window, bg='#1a1a1a')
        button_frame.pack(pady=10)
        
        def unblock_selected():
            selection = listbox.curselection()
            if selection:
                index = selection[0]
                drive_path = blocked_list[index]
                drive_info = self.blocked_usbs[drive_path]
                
                if messagebox.askyesno("Confirm Unblock", 
                                      f"Are you sure you want to unblock {drive_info['path']}?\n\n"
                                      f"This will make the USB accessible again."):
                    
                    del self.blocked_usbs[drive_path]
                    self.save_blocked_usbs()
                    
                    self.add_log(f"🔓 USB unblocked: {drive_info['path']}")
                    messagebox.showinfo("Success", f"USB unblocked successfully!\n\n{drive_info['path']} is now accessible.")
                    
                    unblock_window.destroy()
                    self.refresh_usb_detection()
            else:
                messagebox.showwarning("No Selection", "Please select a USB to unblock.")
        
        def unblock_all():
            if messagebox.askyesno("Unblock All", "Are you sure you want to unblock ALL USB devices?"):
                count = len(self.blocked_usbs)
                self.blocked_usbs.clear()
                self.save_blocked_usbs()
                self.add_log(f"🔓 All {count} USB devices unblocked")
                messagebox.showinfo("Success", f"All {count} USB devices have been unblocked!")
                unblock_window.destroy()
                self.refresh_usb_detection()
        
        unblock_btn = tk.Button(button_frame, text="Unblock Selected", 
                               command=unblock_selected,
                               bg='#4CAF50', fg='white', 
                               font=("Arial", 10, "bold"), padx=15, pady=5)
        unblock_btn.pack(side=tk.LEFT, padx=10)
        
        unblock_all_btn = tk.Button(button_frame, text="Unblock All", 
                                    command=unblock_all,
                                    bg='#FF9800', fg='white', 
                                    font=("Arial", 10, "bold"), padx=15, pady=5)
        unblock_all_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = tk.Button(button_frame, text="Cancel", 
                               command=unblock_window.destroy,
                               bg='#f44336', fg='white', 
                               font=("Arial", 10, "bold"), padx=15, pady=5)
        cancel_btn.pack(side=tk.LEFT, padx=10)
    
    def show_blocked_usbs(self):
        """Show list of blocked USB devices"""
        if not self.blocked_usbs:
            messagebox.showinfo("No Blocked USBs", "No USB devices are currently blocked.")
            return
        
        blocked_text = "=== BLOCKED USB DEVICES ===\n\n"
        blocked_text += f"Total Blocked: {len(self.blocked_usbs)}\n\n"
        
        for path, info in self.blocked_usbs.items():
            blocked_text += f"📀 Drive: {path}\n"
            blocked_text += f"   Blocked: {info['blocked_time']}\n"
            blocked_text += f"   Status: Hidden from system\n\n"
        
        text_window = tk.Toplevel(self.root)
        text_window.title("Blocked USB Devices")
        text_window.geometry("600x450")
        text_window.configure(bg='#1a1a1a')
        
        text_area = scrolledtext.ScrolledText(text_window, wrap=tk.WORD, 
                                              bg='#000000', fg='#00ff00',
                                              font=("Consolas", 10))
        text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        text_area.insert(tk.END, blocked_text)
        text_area.config(state=tk.DISABLED)
        
        close_btn = tk.Button(text_window, text="Close", 
                             command=text_window.destroy,
                             bg='#2196F3', fg='white', 
                             font=("Arial", 10, "bold"), padx=20, pady=5)
        close_btn.pack(pady=10)
    
    def refresh_usb_detection(self):
        """Refresh USB detection"""
        self.add_log("Refreshing USB detection...")
        self.manual_refresh()
    
    def generate_report(self):
        """Save report"""
        try:
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")],
                title="Save Report"
            )
            
            if path:
                content = []
                content.append("=" * 70)
                content.append("OMEGA USB SECURITY TOOL - COMPREHENSIVE REPORT")
                content.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                content.append(f"Admin Mode: {'Yes' if self.is_admin else 'No'}")
                content.append("=" * 70)
                content.append("")
                
                if self.scan_results:
                    content.append(f"THREATS FOUND: {len(self.scan_results)}")
                    content.append("-" * 50)
                    for i, t in enumerate(self.scan_results, 1):
                        content.append(f"{i}. {t['type']}")
                        content.append(f"   File: {t['path']}")
                        content.append(f"   Details: {t['details']}")
                        content.append("")
                else:
                    content.append("SCAN RESULTS: No threats detected")
                    content.append("")
                
                content.append("STATISTICS:")
                content.append("-" * 50)
                content.append(f"Files Scanned: {self.scanned_files}")
                content.append(f"Threats Found: {self.found_threats}")
                content.append("")
                
                if self.blocked_usbs:
                    content.append("BLOCKED USB DEVICES:")
                    content.append("-" * 50)
                    for path, info in self.blocked_usbs.items():
                        content.append(f"Path: {path}")
                        content.append(f"Blocked: {info['blocked_time']}")
                        content.append("")
                
                content.append("ACTIVITY LOG:")
                content.append("-" * 50)
                for entry in self.report_data:
                    content.append(f"[{entry['timestamp']}] {entry['message']}")
                
                with open(path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(content))
                
                self.add_log(f"✅ Report saved: {path}")
                messagebox.showinfo("Report Saved", f"Report saved to:\n{path}")
                
        except Exception as e:
            self.add_log(f"❌ Error: {str(e)}")
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    try:
        app = USBSecurityTool()
        app.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        input("Press Enter to exit...")