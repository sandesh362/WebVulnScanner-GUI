import requests
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from bs4 import BeautifulSoup
import shodan
import subprocess
import os
import socket
from urllib.parse import urljoin
import shutil

# Shodan API Key (Stored Securely)
SHODAN_API_KEY = os.getenv("WedZkV2iwVqxUvtof68XVIuxDPHFzfKh", "YOUR_DEFAULT_KEY")
api = shodan.Shodan(SHODAN_API_KEY)

# Common SQL Injection & XSS payloads
sql_payloads = ["' OR '1'='1", "' OR '1'='1 --"]
xss_payloads = ["<script>alert('XSS')</script>", "\"><img src=x onerror=alert(1)>"]
wordlist = ["admin", "uploads", "config", "backup", "test"]

def get_ip_address(url):
    try:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        ip_address = socket.gethostbyname(domain)
        output.insert(tk.END, f"[+] IP Address: {ip_address}\n", "info")
        return domain, ip_address
    except socket.gaierror:
        output.insert(tk.END, "[!] Unable to resolve IP address\n", "error")
        return domain, None

def get_forms(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except requests.RequestException as e:
        output.insert(tk.END, f"[!] Request Error: {e}\n", "error")
        return []

def test_sql_injection(url, form):
    action = form.get("action")
    post_url = urljoin(url, action) if action else url
    data = {inp.get("name"): sql_payloads[0] for inp in form.find_all("input") if inp.get("name")}
    try:
        response = requests.post(post_url, data=data, timeout=5)
        if "error" in response.text.lower():
            output.insert(tk.END, f"[!] SQL Injection Vulnerability found at {post_url}\n", "vuln")
    except requests.RequestException:
        pass

def test_xss(url, form):
    action = form.get("action")
    post_url = urljoin(url, action) if action else url
    data = {inp.get("name"): xss_payloads[0] for inp in form.find_all("input") if inp.get("name")}
    try:
        response = requests.post(post_url, data=data, timeout=5)
        if xss_payloads[0] in response.text:
            output.insert(tk.END, f"[!] XSS Vulnerability found at {post_url}\n", "vuln")
    except requests.RequestException:
        pass

def check_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        security_headers = {
            "Content-Security-Policy": "Protects against XSS",
            "X-Frame-Options": "Prevents clickjacking",
            "X-XSS-Protection": "Mitigates cross-site scripting",
            "Strict-Transport-Security": "Enforces HTTPS",
            "Referrer-Policy": "Controls referrer info"
        }
        for header, desc in security_headers.items():
            if header not in headers:
                output.insert(tk.END, f"[!] Missing: {header} ({desc})\n", "warning")
    except requests.RequestException:
        pass

def dir_enum(url):
    for dir in wordlist:
        check_url = f"{url}/{dir}/"
        try:
            response = requests.get(check_url, timeout=3)
            if response.status_code == 200:
                output.insert(tk.END, f"[+] Found: {check_url}\n", "success")
        except requests.RequestException:
            pass

def nmap_scan(target):
    try:
        output.insert(tk.END, f"\n[+] Running Nmap scan on {target}...\n", "info")
        nmap_path = shutil.which("nmap") or r"C:\\Program Files\\Nmap\\nmap.exe"
        if not os.path.exists(nmap_path):
            output.insert(tk.END, "[!] Nmap is not installed or not found.\n", "error")
            return
        nmap_result = subprocess.run([nmap_path, "-Pn", "-sV", target], capture_output=True, text=True)
        output.insert(tk.END, nmap_result.stdout + "\n")
    except Exception as e:
        output.insert(tk.END, f"[!] Nmap Error: {e}\n", "error")

def enumerate_subdomains(domain):
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            subdomains = set(entry['name_value'] for entry in response.json())
            output.insert(tk.END, "\n[+] Subdomains Found:\n", "info")
            for subdomain in subdomains:
                output.insert(tk.END, f"  - {subdomain}\n", "success")
        else:
            output.insert(tk.END, "[!] Failed to retrieve subdomains.\n", "error")
    except requests.RequestException as e:
        output.insert(tk.END, f"[!] Error fetching subdomains: {e}\n", "error")

def start_scan():
    url = entry_url.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL")
        return
    output.insert(tk.END, f"Scanning {url}...\n", "info")
    threading.Thread(target=web_vulnerability_scanner, args=(url,)).start()

def web_vulnerability_scanner(url):
    domain, ip_address = get_ip_address(url)
    forms = get_forms(url)
    for form in forms:
        test_sql_injection(url, form)
        test_xss(url, form)
    check_headers(url)
    dir_enum(url)
    enumerate_subdomains(domain)
    if ip_address:
        nmap_scan(ip_address)
    output.insert(tk.END, "\nScan Completed!\n", "success")

# GUI Setup
root = tk.Tk()
root.title("Hacker Terminal - Web Scanner")
root.geometry("900x600")
root.configure(bg="#222")

# Header Label
header = tk.Label(root, text="WEB VULNERABILITY SCANNER", font=("Courier", 16, "bold"), bg="#e74c3c", fg="#fff")
header.pack(pady=10)

# Frame for Input
frame = tk.Frame(root, bg="#222")
frame.pack(pady=10)

# URL Entry
entry_url = tk.Entry(frame, width=50, font=("Courier", 14), bg="#333", fg="#0f0", insertbackground="#0f0", relief="flat")
entry_url.grid(row=0, column=1, padx=10, pady=5)

# Scan Button
scan_btn = tk.Button(frame, text="▶ START SCAN", font=("Courier", 14, "bold"), bg="#0f0", fg="#000", relief="flat", padx=10, pady=5, command=start_scan)
scan_btn.grid(row=0, column=2, padx=10, pady=5)

# Output Box
output = scrolledtext.ScrolledText(root, width=100, height=25, font=("Courier", 12), bg="#333", fg="#0f0", relief="flat")
output.pack(pady=10)

# Custom tags for styled text
output.tag_config("info", foreground="#0ff")
output.tag_config("success", foreground="#0f0")
output.tag_config("warning", foreground="#ff0")
output.tag_config("error", foreground="#f00")

# Status Bar
status_bar = tk.Label(root, text=" Ready... ", font=("Courier", 10), bg="#e74c3c", fg="#fff", anchor="w")
status_bar.pack(fill="x", side="bottom")

root.mainloop()