import os
import requests
import tkinter as tk
from tkinter import messagebox, scrolledtext


print("This program is designed to check if a link is suspicious or not.")
print("Please note that while this tool can be used for legitimate purposes, it can also be misused for malicious intents.")
print("I do not endorse or support the use of this tool for unethical or illegal activities.")

print("This pulls from VirusTotal's API, so you will need to set the VIRUSTOTAL_API_KEY environment variable.")
print("This Project was made for RowdyHacks 2024 by Team Coderunner")

# Print program logo
print("\033[95m" + """
░█████╗░░█████╗░██████╗░███████╗██████╗░██╗░░░██╗███╗░░██╗███╗░░██╗███████╗██████╗░
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██║░░░██║████╗░██║████╗░██║██╔════╝██╔══██╗
██║░░╚═╝██║░░██║██║░░██║█████╗░░██████╔╝██║░░░██║██╔██╗██║██╔██╗██║█████╗░░██████╔╝
██║░░██╗██║░░██║██║░░██║██╔══╝░░██╔══██╗██║░░░██║██║╚████║██║╚████║██╔══╝░░██╔══██╗
╚█████╔╝╚█████╔╝██████╔╝███████╗██║░░██║╚██████╔╝██║░╚███║██║░╚███║███████╗██║░░██║
░╚════╝░░╚════╝░╚═════╝░╚══════╝╚═╝░░╚═╝░╚═════╝░╚═╝░░╚══╝╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝
""" + "\033[0m")

def check_link():
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        messagebox.showerror("Error", "Please set the VIRUSTOTAL_API_KEY environment variable.")
        return
    
    link = link_entry.get()
    if not link:
        messagebox.showwarning("No Link", "Please enter a link.")
        return
    
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': link}
    
    try:
        response = requests.get(url, params=params)
        result = response.json()

        malicious_files = []
        safe_files = []

        if result['response_code'] == 1:
            for scan, info in result['scans'].items():
                if info['detected']:
                    malicious_files.append(f"{scan}: {info['result']}")
                else:
                    safe_files.append(f"{scan}: {info['result']}")

            if malicious_files:
                messagebox.showwarning("Suspicious Link", f"The link {link} is suspicious. Detected {len(malicious_files)} malicious files.")
                for file in malicious_files:
                    report_text.insert(tk.END, file + '\n', 'red')
            else:
                messagebox.showinfo("Safe Link", f"The link {link} is safe. No positive detections.")

            if safe_files:
                report_text.insert(tk.END, '\nSafe Files:\n', 'green')
                for file in safe_files:
                    report_text.insert(tk.END, file + '\n', 'green')
        else:
            messagebox.showerror("Error", result['verbose_msg'])
    except requests.RequestException as e:
        messagebox.showerror("Error", str(e))
        
    if result['response_code'] == 0:
        report_text.configure(bg="yellow")

def clear_search():
    link_entry.delete(0, tk.END)
    report_text.delete(1.0, tk.END)

# Create GUI
root = tk.Tk()
root.title("Scam Checker")

# Link Entry
link_label = tk.Label(root, text="Enter the suspicious link:")
link_label.pack()
link_entry = tk.Entry(root)
link_entry.pack()

# Check Button
check_button = tk.Button(root, text="Check Link", command=check_link)
check_button.pack()

# Clear Button
clear_button = tk.Button(root, text="Clear", command=clear_search)
clear_button.pack()

# Report Text (make it scrollable)
report_text = tk.Text(root, wrap=tk.WORD)
report_text.pack(fill=tk.BOTH, expand=True)  # Make the report_text stretchable

# Configure tags for coloring
report_text.tag_configure("red", foreground="red")
report_text.tag_configure("green", foreground="green")
report_text.tag_configure("yellow", background="yellow")

# Run GUI
root.mainloop()
