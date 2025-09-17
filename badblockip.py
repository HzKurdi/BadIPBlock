import requests
import csv
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from io import StringIO
import threading

class FirewallIPBlocker:
    def __init__(self, root):
        self.root = root
        self.root.title("Hz Bad IP Blocker")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")
        
        # Create UI
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        title_label = tk.Label(self.root, text="Hz Bad IP Blocker", 
                              font=("Arial", 16, "bold"), bg="#f0f0f0", fg="#2c3e50")
        title_label.pack(pady=10)
        
        # Description
        desc_text = "This tool downloads malicious IP addresses from Abuse.ch and creates Windows Firewall rules to block them."
        desc_label = tk.Label(self.root, text=desc_text, wraplength=700,
                             font=("Arial", 10), bg="#f0f0f0", fg="#34495e")
        desc_label.pack(pady=5)
        
        # Buttons frame
        button_frame = tk.Frame(self.root, bg="#f0f0f0")
        button_frame.pack(pady=15)
        
        # Fetch and Block button
        self.fetch_button = tk.Button(button_frame, text="Fetch IPs and Create Block Rules", 
                                     command=self.start_fetch_process, bg="#3498db", fg="white",
                                     font=("Arial", 10, "bold"), padx=10, pady=5)
        self.fetch_button.pack(side=tk.LEFT, padx=5)
        
        # Clear Rules button
        self.clear_button = tk.Button(button_frame, text="Clear All Block Rules", 
                                     command=self.clear_rules, bg="#e74c3c", fg="white",
                                     font=("Arial", 10, "bold"), padx=10, pady=5)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, length=700, mode='indeterminate')
        self.progress.pack(pady=10)
        
        # Status label
        self.status_label = tk.Label(self.root, text="Ready to fetch malicious IP addresses", 
                                    font=("Arial", 10), bg="#f0f0f0", fg="#34495e")
        self.status_label.pack(pady=5)
        
        # Results area
        results_frame = tk.LabelFrame(self.root, text="Results", font=("Arial", 11, "bold"),
                                     bg="#f0f0f0", fg="#2c3e50")
        results_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, font=("Consolas", 9))
        self.results_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Footer
        footer_label = tk.Label(self.root, text="Data provided by Abuse.ch | Use responsibly on authorized systems only", 
                               font=("Arial", 8), bg="#f0f0f0", fg="#7f8c8d")
        footer_label.pack(side=tk.BOTTOM, pady=5)
        
    def start_fetch_process(self):
        # Run the fetch process in a separate thread to avoid UI freezing
        thread = threading.Thread(target=self.fetch_and_block_ips)
        thread.daemon = True
        thread.start()
    
    def fetch_and_block_ips(self):
        self.toggle_buttons(False)
        self.progress.start()
        self.status_label.config(text="Fetching malicious IP list from Abuse.ch...")
        self.results_text.delete(1.0, tk.END)
        
        try:
            # Fetch data from Abuse.ch
            response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
            response.raise_for_status()
            
            self.status_label.config(text="Processing IP addresses...")
            self.results_text.insert(tk.END, "Fetched data successfully. Processing...\n\n")
            self.root.update()
            
            # Delete existing rules
            self.results_text.insert(tk.END, "Clearing existing 'BadIP' rules...\n")
            rule = "netsh advfirewall firewall delete rule name='BadIP'"
            result = subprocess.run(['powershell', '-Command', rule], capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results_text.insert(tk.END, "✓ Existing rules cleared successfully\n\n")
            else:
                self.results_text.insert(tk.END, "ℹ No existing rules found or error clearing rules\n\n")
            
            # Process CSV data
            csv_data = response.text
            reader = csv.reader(StringIO(csv_data))
            blocked_count = 0
            
            for row in reader:
                # Skip comment lines and header
                if not row or row[0].startswith('#') or row[1] == "dst_ip":
                    continue
                    
                ip = row[1]
                if ip:  # Make sure IP is not empty
                    # Create firewall rule
                    rule = f"netsh advfirewall firewall add rule name='BadIP' Dir=Out Action=Block RemoteIP={ip}"
                    result = subprocess.run(['powershell', '-Command', rule], capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        self.results_text.insert(tk.END, f"✓ Blocked IP: {ip}\n")
                        blocked_count += 1
                    else:
                        self.results_text.insert(tk.END, f"✗ Failed to block IP: {ip} - {result.stderr}\n")
            
            # Update status
            self.status_label.config(text=f"Completed! Blocked {blocked_count} malicious IP addresses")
            self.results_text.insert(tk.END, f"\n=== Process completed. Total IPs blocked: {blocked_count} ===\n")
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to fetch data from Abuse.ch: {str(e)}"
            self.status_label.config(text=error_msg)
            self.results_text.insert(tk.END, error_msg)
            messagebox.showerror("Network Error", error_msg)
        except Exception as e:
            error_msg = f"An unexpected error occurred: {str(e)}"
            self.status_label.config(text=error_msg)
            self.results_text.insert(tk.END, error_msg)
            messagebox.showerror("Error", error_msg)
        finally:
            self.progress.stop()
            self.toggle_buttons(True)
    
    def clear_rules(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to delete all 'BadIP' firewall rules?"):
            self.toggle_buttons(False)
            self.progress.start()
            self.status_label.config(text="Clearing firewall rules...")
            self.results_text.delete(1.0, tk.END)
            
            try:
                rule = "netsh advfirewall firewall delete rule name='BadIP'"
                result = subprocess.run(['powershell', '-Command', rule], capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.status_label.config(text="All 'BadIP' rules cleared successfully")
                    self.results_text.insert(tk.END, "✓ All 'BadIP' firewall rules have been cleared\n")
                else:
                    self.status_label.config(text="No rules found or error clearing rules")
                    self.results_text.insert(tk.END, "ℹ No 'BadIP' rules found or error clearing rules\n")
                    
            except Exception as e:
                error_msg = f"Error clearing rules: {str(e)}"
                self.status_label.config(text=error_msg)
                self.results_text.insert(tk.END, error_msg)
                messagebox.showerror("Error", error_msg)
            finally:
                self.progress.stop()
                self.toggle_buttons(True)
    
    def toggle_buttons(self, state):
        self.fetch_button.config(state=tk.NORMAL if state else tk.DISABLED)
        self.clear_button.config(state=tk.NORMAL if state else tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallIPBlocker(root)
    root.mainloop()