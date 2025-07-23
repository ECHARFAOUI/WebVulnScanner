import subprocess
import os
import re
import sys
import time
import signal
import shutil
import requests
import socket
import pwd
import grp
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from rich.console import Console
    from rich.prompt import Confirm
    from rich.progress import Progress, BarColumn, TextColumn
    from rich.table import Table
    rich_available = True
except ImportError:
    rich_available = False
    Console = None
    Confirm = None
    Progress = None
    BarColumn = None
    TextColumn = None
    Table = None
try:
    import colorama
    from colorama import Fore
    colorama.init(autoreset=True)
except ImportError:
    Fore = None

# Initialize global variables
console = Console() if rich_available else None
total_findings = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
tools_available = {
    "suricata": False,
    "nikto": False,
    "whatweb": False,
    "gobuster": False,
    "nmap": False,
    "tshark": False
}
stop_execution = False
wireshark_process = None

# Expanded CVE Database
CVE_DATABASE = {
    "Apache": {
        "versions": {
            "2.4.63": ["CVE-2024-38472", "CVE-2024-38473"],
            "2.4.50": ["CVE-2021-42013"],
            "2.4.49": ["CVE-2021-41773"],
            "2.4.46": ["CVE-2020-11985"],
            "2.4.41": ["CVE-2019-10098"],
        },
        "pattern": r"Apache/(\d+\.\d+\.\d+)"
    },
    "PHP": {
        "versions": {
            "7.4.21": ["CVE-2021-21703"],
            "7.3.28": ["CVE-2021-21702"],
            "8.0.8": ["CVE-2021-21705"],
            "5.6.40": ["CVE-2019-11043"],
        },
        "pattern": r"PHP/(\d+\.\d+\.\d+)"
    },
    "MySQL": {
        "versions": {
            "8.0.25": ["CVE-2021-23021"],
            "5.7.34": ["CVE-2021-2144"],
            "5.6.49": ["CVE-2020-14651"],
            "11.8.2": ["CVE-2024-21180"],
        },
        "pattern": r"MySQL (\d+\.\d+\.\d+)|MariaDB (\d+\.\d+\.\d+)"
    }
}

# ASCII Art for Team VENOM
ASCII_ART = r"""
   _____ _          
  / ____| |         
 | |    | |__   ___ 
 | |    | '__ \ / __|
 | |____| | | | (__ 
  \_____|_| |_|____|
  CERTIF CYBER Scanner by Team VENOM
====================================
"""

# Fallback print function
def print_fallback(message, style=None):
    if rich_available and console:
        console.print(message, style=style)
    else:
        print(message)

# Display welcome screen with tools
def display_welcome():
    print_fallback(ASCII_ART, style="bold magenta")
    print_fallback("Welcome, VENOM! Ready to dominate the cyberspace?", style="bold cyan")
    if rich_available:
        table = Table(title="Available Tools", show_lines=True, border_style="cyan", header_style="bold magenta")
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="green", justify="center")
        for tool, available in tools_available.items():
            table.add_row(tool.capitalize(), "Available" if available else "Not Installed", style="bold green" if available else "bold red")
        console.print(table)
    else:
        print_fallback("\nAvailable Tools:")
        for tool, available in tools_available.items():
            print_fallback(f"- {tool.capitalize()}: {'Available' if available else 'Not Installed'}")

# Signal handler for Ctrl+C
def signal_handler(sig, frame):
    global stop_execution, wireshark_process
    print_fallback("\n[!] Scan interrupted. Cleaning up...", style="bold yellow")
    stop_wireshark()
    cleanup_suricata_files()
    stop_execution = True
    sys.exit(0)

# Check if command exists
def check_command(command):
    return shutil.which(command) is not None

# Test tool availability
def test_tool(tool):
    try:
        cmd = {
            "suricata": "suricata -V",
            "nikto": "nikto -h",
            "whatweb": "whatweb --version",
            "gobuster": "gobuster -h",
            "nmap": "nmap --version",
            "tshark": "tshark --version"
        }.get(tool)
        if cmd:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

# Install/upgrade tools
def install_or_update_tools(tools):
    warnings = []
    venv_dir = os.path.join(os.getcwd(), "venv")
    if not os.path.exists(venv_dir):
        print_fallback("[*] Creating virtual environment...", style="cyan")
        try:
            subprocess.run(f"python3 -m venv {venv_dir}", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            print_fallback("[+] Virtual environment created!", style="bold green")
        except Exception as e:
            print_fallback(f"[!] Failed to create virtual environment: {str(e)}", style="bold red")
            warnings.append(f"Failed to create virtual environment: {str(e)}")
            return warnings
    
    activate_cmd = f". {os.path.join(venv_dir, 'bin', 'activate')}" if os.name != "nt" else os.path.join(venv_dir, "Scripts", "activate.bat")
    pip_cmd = os.path.join(venv_dir, "bin", "pip3") if os.name != "nt" else os.path.join(venv_dir, "Scripts", "pip3")
    
    try:
        subprocess.run(f"{activate_cmd} && {pip_cmd} install --upgrade pip", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300, text=True)
        print_fallback("[+] Pip upgraded!", style="bold green")
    except Exception as e:
        print_fallback(f"[!] Failed to upgrade pip: {str(e)}", style="bold red")
        warnings.append(f"Failed to upgrade pip: {str(e)}")
    
    for tool in tools:
        try:
            if tool in ["suricata", "nikto", "whatweb", "gobuster", "nmap", "tshark"]:
                # Ensure suricata group exists
                if tool == "suricata":
                    try:
                        grp.getgrnam("suricata")
                    except KeyError:
                        subprocess.run("sudo groupadd suricata", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                        print_fallback("[+] Suricata group created!", style="bold green")
                subprocess.run(f"sudo apt-get update && sudo apt-get install -y {tool}", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300, text=True)
            elif tool == "python3-rich":
                subprocess.run(f"{activate_cmd} && {pip_cmd} install rich", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300, text=True)
            print_fallback(f"[+] {tool} installed/updated!", style="bold green")
        except Exception as e:
            print_fallback(f"[!] Failed to install/update {tool}: {str(e)}", style="bold red")
            warnings.append(f"Failed to install/update {tool}: {str(e)}")
    return warnings

# Validate target format
def is_valid_target(target):
    url_pattern = r"^(http|https)://[a-zA-Z0-9.-]+(:[0-9]+)?(/[a-zA-Z0-9./-]*)?$"
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(url_pattern, target) or re.match(ip_pattern, target))

# Normalize target URL
def normalize_target_url(target):
    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip("/")
    return f"http://{target.rstrip('/')}"

# Resolve hostname to IP
def resolve_hostname(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        print_fallback(f"[!] Failed to resolve hostname {hostname}", style="bold red")
        return None

# Check if target is reachable
def check_target_reachable(target_url):
    try:
        response = requests.head(target_url, timeout=10, allow_redirects=True)
        return response.status_code < 400
    except requests.RequestException as e:
        print_fallback(f"[!] Target {target_url} not reachable: {str(e)}", style="bold red")
        return False

# Get network interface
def get_network_interfaces(target):
    try:
        result = subprocess.run("tshark -D", shell=True, capture_output=True, text=True, timeout=10)
        interfaces = [line.split()[1] for line in result.stdout.splitlines() if line]
        if "any" in interfaces:
            print_fallback("Selected interface 'any' for packet capture", style="cyan")
            return "any"
        print_fallback("Interface 'any' not found, selecting first available interface", style="bold yellow")
        return interfaces[0] if interfaces else None
    except Exception as e:
        print_fallback(f"Error listing network interfaces: {str(e)}", style="bold red")
        return None

# Check Suricata version
def get_suricata_version():
    try:
        result = subprocess.run("suricata -V", shell=True, capture_output=True, text=True, timeout=10)
        version_match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
        if version_match:
            return version_match.group(1)
        return "unknown"
    except Exception:
        return "unknown"

# Cleanup Suricata files
def cleanup_suricata_files():
    files = ["/etc/suricata/suricata.yaml", "/etc/suricata/rules/local.rules", "/var/log/suricata/fast.log", "/var/log/suricata/eve.json"]
    for file in files:
        if os.path.exists(file):
            try:
                os.remove(file)
            except Exception as e:
                print_fallback(f"[!] Failed to delete {file}: {str(e)}", style="bold red")

# Setup Suricata configuration
def setup_suricata_config(target_ip):
    if target_ip == "localhost":
        target_ip = "127.0.0.1"
    elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip):
        target_ip = resolve_hostname(target_ip)
        if not target_ip:
            print_fallback("[!] Invalid IP address for Suricata", style="bold red")
            return False, None
    
    rules_path = "/etc/suricata/rules/local.rules"
    log_file = "/var/log/suricata/fast.log"
    
    suricata_conf_content = f"""
%YAML 1.1
---
af-packet:
  - interface: any
    threads: 1
    defrag: yes
    cluster-type: cluster_flow
    cluster-id: 99
    checksum-checks: auto
vars:
  address-groups:
    HOME_NET: "[{target_ip}]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,443"
rule-files:
  - local.rules
default-rule-path: /etc/suricata/rules
logging:
  outputs:
    - fast:
        enabled: yes
        filename: fast.log
        append: no
    - eve-json:
        enabled: yes
        filename: eve.json
        append: no
"""
    local_rules_content = r"""
alert tcp any any -> any any (msg:"Potential port scan detected"; flow:stateless; flags:S; threshold: type both, track by_src, count 10, seconds 60; sid:2000001; rev:1;)
alert tcp any any -> any 80 (msg:"SQL Injection attempt"; content:"SELECT"; nocase; http_uri; pcre:"/SELECT\\s+(?:FROM|UNION|WHERE)/i"; sid:2000002; rev:3;)
alert tcp any any -> any 80 (msg:"XSS attempt"; content:"<script"; nocase; http_uri; pcre:"/[<]script[>\s]/i"; sid:2000003; rev:2;)
alert tcp any any -> any 80 (msg:"CSRF attempt"; content:"csrf_token"; nocase; http_uri; sid:2000004; rev:1;)
alert tcp any any -> any 80 (msg:"LFI attempt"; content:"../"; nocase; http_uri; pcre:"/(\.\.\/|\.\.%2[fF]|\.\.%5[cC])/"; sid:2000005; rev:2;)
alert tcp any any -> any 80 (msg:"Command Injection attempt"; content:";"; nocase; http_uri; pcre:"/;[a-zA-Z0-9\s]*(rm|cat|whoami|id|sh|bash|cmd)/i"; sid:2000006; rev:1;)
alert tcp any any -> any 80 (msg:"Suspicious User-Agent"; content:"User-Agent:"; nocase; http_header; pcre:"/User-Agent:.*(sqlmap|burp|nmap|metasploit|hydra)/i"; sid:2000007; rev:1;)
alert tcp any any -> any 80 (msg:"HTTP Method Abuse"; content:"TRACE"; nocase; http_method; sid:2000008; rev:1;)
"""
    try:
        os.makedirs("/etc/suricata/rules", exist_ok=True)
        os.makedirs("/var/log/suricata", exist_ok=True)
        
        with open("/etc/suricata/suricata.yaml", "w", encoding="utf-8") as f:
            f.write(suricata_conf_content)
        
        with open(rules_path, "w", encoding="utf-8") as f:
            f.write(local_rules_content)
        
        try:
            grp.getgrnam("suricata")
            suricata_group = "suricata"
        except KeyError:
            suricata_group = pwd.getpwuid(os.getuid()).pw_name
            print_fallback(f"[!] Suricata group not found, using group: {suricata_group}", style="bold yellow")
        
        subprocess.run(f"sudo chown -R :{suricata_group} /etc/suricata /var/log/suricata", shell=True, check=True)
        subprocess.run(f"sudo chmod -R g+rw /etc/suricata/rules /var/log/suricata", shell=True, check=True)
        
        process = subprocess.Popen(
            ["sudo", "suricata", "-T", "-c", "/etc/suricata/suricata.yaml", "-i", "any"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(timeout=30)
        if process.returncode != 0:
            print_fallback(f"Suricata configuration test failed: {stderr}", style="bold red")
            return False, None
        return True, log_file
    except Exception as e:
        print_fallback(f"Suricata configuration test failed: {str(e)}", style="bold red")
        return False, None

# Start Wireshark capture
def start_wireshark(interface, target_ip, output_file):
    global wireshark_process
    if not tools_available.get("tshark", False):
        print_fallback("[!] tshark not available", style="bold red")
        return False
    try:
        tshark_cmd = f"sudo tshark -i {interface} -f 'host {target_ip} and tcp port 80 or tcp port 443' -w {output_file} -c 100"
        print_fallback(f"[*] Starting Wireshark: {tshark_cmd}", style="cyan")
        wireshark_process = subprocess.Popen(tshark_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(2)
        if wireshark_process.poll() is not None:
            print_fallback(f"[!] Wireshark failed to start", style="bold red")
            return False
        return True
    except Exception as e:
        print_fallback(f"[!] Error starting Wireshark: {str(e)}", style="bold red")
        return False

# Stop Wireshark
def stop_wireshark():
    global wireshark_process
    if wireshark_process:
        try:
            wireshark_process.terminate()
            wireshark_process.wait(timeout=5)
            wireshark_process = None
            print_fallback("[+] Wireshark stopped", style="bold green")
        except Exception as e:
            print_fallback(f"[!] Error stopping Wireshark: {str(e)}", style="bold red")

# Analyze Wireshark output
def analyze_wireshark(output_file, tool_name):
    global total_findings
    findings = []
    if not tools_available.get("tshark", False):
        print_fallback(f"[!] {tool_name}: tshark not available", style="bold red")
        return findings
    try:
        tshark_cmd = f"sudo tshark -r {output_file} -T fields -e ip.src -e ip.dst -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport -e http.request.method -e http.response.code -e http.request.uri -e http.user_agent"
        output = run_command(tshark_cmd, use_sudo=True, tool_name="Wireshark", timeout=120)
        packets = output.splitlines()
        if not packets:
            print_fallback(f"[!] {tool_name}: No packets captured", style="bold yellow")
            findings.append({"finding": "No packets captured by Wireshark", "severity": "Info", "count": 1, "cve": "N/A"})
            total_findings["Info"] += 1
            return findings
        protocols = set(line.split("\t")[2].strip() for line in packets if len(line.split("\t")) > 2 and line.split("\t")[2].strip())
        if protocols:
            findings.append({"finding": f"Detected Protocols: {', '.join(protocols)}", "severity": "Info", "count": 1, "cve": "N/A"})
            total_findings["Info"] += 1
        for line in packets:
            fields = line.split("\t")
            if len(fields) >= 7 and fields[2].strip() == "HTTP":
                status = fields[6].strip() or "N/A"
                uri = fields[7].strip() if len(fields) > 7 else "N/A"
                user_agent = fields[8].strip() if len(fields) > 8 else "N/A"
                if status == "500":
                    findings.append({"finding": f"HTTP Internal Server Error (Status: {status}, URI: {uri})", "severity": "Critical", "count": 1, "cve": "N/A"})
                    total_findings["Critical"] += 1
                elif status in ["403", "401"]:
                    findings.append({"finding": f"HTTP Access Denied (Status: {status}, URI: {uri})", "severity": "High", "count": 1, "cve": "N/A"})
                    total_findings["High"] += 1
                elif status == "404":
                    if not any(keyword in uri.lower() for keyword in [".ht", ".bash", ".config", ".cache", ".mysql", ".cvs", ".rhosts", ".profile", ".sh_history", ".ssh", ".forward", ".subversion"]):
                        findings.append({"finding": f"HTTP Not Found (Status: {status}, URI: {uri})", "severity": "Medium", "count": 1, "cve": "N/A"})
                        total_findings["Medium"] += 1
                if any(keyword in uri.lower() for keyword in ["select", "union", "script", "<script", "alert(", "../", "csrf_token", ";", "rm ", "whoami", "id "]):
                    findings.append({"finding": f"Potential Attack Pattern in URI: {uri}", "severity": "Critical", "count": 1, "cve": "N/A"})
                    total_findings["Critical"] += 1
                for tech, data in CVE_DATABASE.items():
                    match = re.search(data["pattern"], user_agent)
                    if match:
                        version = match.group(1)
                        cves = data["versions"].get(version, [])
                        severity = "High" if cves else "Info"
                        findings.append({"finding": f"{tech} Version: {version} in User-Agent", "severity": severity, "count": 1, "cve": ", ".join(cves) or "N/A"})
                        total_findings[severity] += 1
        print_fallback(f"[+] {tool_name}: Analyzed {len(packets)} packets", style="bold green")
    except Exception as e:
        print_fallback(f"[!] {tool_name}: Error analyzing output: {str(e)}", style="bold red")
        findings.append({"finding": f"Error analyzing output: {str(e)}", "severity": "Info", "count": 1, "cve": "N/A"})
        total_findings["Info"] += 1
    return findings

# Analyze Suricata output
def analyze_suricata_output(log_file, tool_name):
    global total_findings
    findings = []
    if not os.path.exists(log_file):
        print_fallback(f"[!] {tool_name}: Log file {log_file} not found", style="bold yellow")
        findings.append({"finding": "No Suricata alerts captured", "severity": "Info", "count": 1, "cve": "N/A"})
        total_findings["Info"] += 1
        return findings
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            output = f.read()
        alert_pattern = r"\[\d+:\d+:\d+\]\s+(.+?)\s+\["
        for line in output.splitlines():
            match = re.search(alert_pattern, line)
            if not match:
                continue
            alert_msg = match.group(1)
            if "Potential port scan detected" in alert_msg:
                findings.append({"finding": "Potential port scan detected", "severity": "High", "count": 1, "cve": "N/A"})
                total_findings["High"] += 1
            elif "SQL Injection attempt" in alert_msg:
                findings.append({"finding": "SQL Injection attempt (SELECT detected)", "severity": "High", "count": 1, "cve": "N/A"})
                total_findings["High"] += 1
            elif "XSS attempt" in alert_msg:
                findings.append({"finding": "XSS attempt (<script detected)", "severity": "High", "count": 1, "cve": "N/A"})
                total_findings["High"] += 1
            elif "CSRF attempt" in alert_msg:
                findings.append({"finding": "CSRF attempt (csrf_token detected)", "severity": "High", "count": 1, "cve": "N/A"})
                total_findings["High"] += 1
            elif "LFI attempt" in alert_msg:
                findings.append({"finding": "LFI attempt (../ detected)", "severity": "High", "count": 1, "cve": "N/A"})
                total_findings["High"] += 1
            elif "Command Injection attempt" in alert_msg:
                findings.append({"finding": "Command Injection attempt (suspicious command detected)", "severity": "Critical", "count": 1, "cve": "N/A"})
                total_findings["Critical"] += 1
            elif "Suspicious User-Agent" in alert_msg:
                findings.append({"finding": "Suspicious User-Agent detected", "severity": "Medium", "count": 1, "cve": "N/A"})
                total_findings["Medium"] += 1
            elif "HTTP Method Abuse" in alert_msg:
                findings.append({"finding": "HTTP Method Abuse (TRACE method detected)", "severity": "Medium", "count": 1, "cve": "N/A"})
                total_findings["Medium"] += 1
        if not findings:
            findings.append({"finding": "No Suricata alerts captured", "severity": "Info", "count": 1, "cve": "N/A"})
            total_findings["Info"] += 1
        print_fallback(f"[+] {tool_name}: Analyzed log file {log_file}", style="bold green")
    except Exception as e:
        print_fallback(f"[!] {tool_name}: Error analyzing log file: {str(e)}", style="bold red")
        findings.append({"finding": f"Error analyzing log file: {str(e)}", "severity": "Info", "count": 1, "cve": "N/A"})
        total_findings["Info"] += 1
    return findings

# Aggregate duplicate findings
def aggregate_findings(findings):
    aggregated = {}
    for finding in findings:
        key = (finding["finding"].lower(), finding["severity"], finding["cve"])
        if key not in aggregated:
            aggregated[key] = {"finding": finding["finding"], "severity": finding["severity"], "cve": finding["cve"], "count": 0}
        aggregated[key]["count"] += finding.get("count", 1)
    return [value for value in aggregated.values()]

# Analyze tool output (for non-Suricata tools)
def analyze_tool_output(output, tool_name):
    global total_findings
    findings = []
    cve_pattern = r"(CVE-\d{4}-\d+)"
    keywords = ["vulnerable", "exploit", "injection", "critical", "xss", "sql", "rce", "lfi", "rfi", "authentication bypass", "csrf", "directory traversal", "insecure"]
    
    skip_patterns = {
        "nikto": [
            r"Nikto v",
            r"Start Time",
            r"End Time",
            r"Host\(s\) tested",
            r"Target ",
            r"portions of",
            r"submit this information",
        ],
        "whatweb": [
            r"^\s*$",
            r"RedirectLocation",
            r"Title\[301 Moved Permanently\]",
        ],
        "gobuster": [
            r"^\s*$",
            r"Progress:.*",
            r"Started:.*",
            r"Finished:.*",
        ],
        "nmap": [
            r"Nmap \d+\.\d+ scan initiated",
            r"Host is up",
            r"Other addresses",
            r"Not shown",
            r"PORT\s+STATE\s+SERVICE\s+VERSION",
            r"Service detection performed",
            r"Nmap done",
            r"submit\.cgi",
            r"SF-.*mysql_native_password",
            r"Starting Nmap",
        ]
    }
    
    for line in output.splitlines():
        description = line.strip()
        if not description:
            continue
        skip = False
        for pattern in skip_patterns.get(tool_name.lower(), []):
            if re.search(pattern, description, re.IGNORECASE):
                skip = True
                break
        if skip:
            continue
        cve_match = re.search(cve_pattern, description)
        cve_id = cve_match.group(1) if cve_match else "N/A"
        severity = "Critical" if any(k in description.lower() for k in ["critical", "exploit", "injection", "rce"]) else \
                  "High" if cve_match or any(k in description.lower() for k in keywords) else \
                  "Medium" if "warning" in description.lower() or "403" in description or "404" in description else \
                  "Low" if "directory indexing" in description.lower() else "Info"
        findings.append({"finding": description, "severity": severity, "cve": cve_id, "count": 1})
        total_findings[severity] += 1
        
        for tech, data in CVE_DATABASE.items():
            match = re.search(data["pattern"], description)
            if match:
                version = match.group(1)
                cves = data["versions"].get(version, [])
                if cves:
                    findings.append({"finding": f"{tech} Version: {version}", "severity": "High", "cve": ", ".join(cves), "count": 1})
                    total_findings["High"] += 1
    return aggregate_findings(findings)

# Run command
def run_command(command, use_sudo=False, tool_name="Tool", timeout=600):
    try:
        cmd = f"sudo {command}" if use_sudo else command
        print_fallback(f"[*] Running: {cmd}", style="cyan")
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return process.stdout
    except Exception as e:
        print_fallback(f"[!] {tool_name} failed: {str(e)}", style="bold red")
        return f"Error: {str(e)}"

# Generate final report (Markdown only)
def generate_final_report(all_findings, target, output_dir):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_md_file = os.path.join(output_dir, f"venom_report_{target.replace('://', '_').replace('/', '_')}_{timestamp}.md")
    
    report_md = f"""
# Team VENOM Security Scan Report
**Target**: {target}  
**Date**: {timestamp}

## Findings
| Tool | Severity | Finding | Count | CVE |
|------|----------|---------|-------|-----|
"""
    for tool_name, findings in all_findings.items():
        for finding in sorted(findings, key=lambda x: {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'Info': 5}.get(x['severity'], 5)):
            report_md += f"| {tool_name} | {finding['severity']} | {finding['finding'].replace('|', '\\|')} | {finding['count']} | {finding.get('cve', 'N/A')} |\n"
    
    report_md += f"""
## Summary
- **Total Findings**: {sum(total_findings.values())}
- **Critical**: {total_findings['Critical']}
- **High**: {total_findings['High']}
- **Medium**: {total_findings['Medium']}
- **Low**: {total_findings['Low']}
- **Info**: {total_findings['Info']}

**Generated by Team VENOM - Powered by Cyber Warriors**
"""
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(output_md_file, 'w', encoding='utf-8') as f:
            f.write(report_md)
        print_fallback(f"[+] Markdown report saved to {output_md_file}", style="bold green")
    except Exception as e:
        print_fallback(f"[!] Error saving Markdown report: {str(e)}", style="bold red")

# Display detailed vulnerabilities
def display_vulnerabilities(all_findings):
    if rich_available:
        table = Table(title="Detailed Vulnerabilities", show_lines=True, border_style="cyan", header_style="bold magenta")
        table.add_column("Tool", style="cyan", width=15)
        table.add_column("Severity", style="yellow", width=10)
        table.add_column("Finding", style="white", width=50)
        table.add_column("Count", style="green", width=8)
        table.add_column("CVE", style="blue", width=15)
        for tool_name, findings in all_findings.items():
            for finding in sorted(findings, key=lambda x: {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'Info': 5}.get(x['severity'], 5)):
                table.add_row(
                    tool_name,
                    finding['severity'],
                    finding['finding'],
                    str(finding['count']),
                    finding['cve'],
                    style=f"bold {'red' if finding['severity'] == 'Critical' else 'red' if finding['severity'] == 'High' else 'yellow' if finding['severity'] == 'Medium' else 'green' if finding['severity'] == 'Low' else 'blue'}"
                )
        console.print("\n")
        console.print(table)
    else:
        print_fallback("\nDetailed Vulnerabilities:")
        print_fallback("=" * 100)
        print_fallback(f"{'Tool':<15} {'Severity':<10} {'Finding':<50} {'Count':<8} {'CVE':<15}")
        print_fallback("-" * 100)
        for tool_name, findings in all_findings.items():
            for finding in sorted(findings, key=lambda x: {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'Info': 5}.get(x['severity'], 5)):
                color = Fore.RED if finding['severity'] in ["Critical", "High"] else Fore.YELLOW if finding['severity'] == "Medium" else Fore.GREEN if finding['severity'] == "Low" else Fore.BLUE
                print_fallback(f"{color}{tool_name:<15} {finding['severity']:<10} {finding['finding'][:47] + '...' if len(finding['finding']) > 47 else finding['finding']:<50} {finding['count']:<8} {finding['cve']:<15}{Fore.RESET}")
        print_fallback("=" * 100)

# Main function
def main():
    global stop_execution, total_findings, tools_available
    signal.signal(signal.SIGINT, signal_handler)
    
    # Check tools
    for tool in tools_available:
        tools_available[tool] = test_tool(tool)
    
    display_welcome()
    
    # Prompt for tool installation
    install = Confirm.ask("[cyan]Install/update tools?[/cyan]") if rich_available else input("Install/update tools? (y/n): ").lower() == 'y'
    if install:
        warnings = install_or_update_tools(["suricata", "nikto", "whatweb", "gobuster", "nmap", "tshark", "python3-rich"])
        if warnings:
            print_fallback("[!] Some tools failed to install. Check output for details.", style="bold yellow")
        for tool in tools_available:
            tools_available[tool] = test_tool(tool)
    
    # Check Suricata version
    suricata_version = get_suricata_version()
    print_fallback(f"[*] Suricata version: {suricata_version}", style="cyan")
    
    # Get target
    target = input(f"{Fore.CYAN if Fore else ''}Enter target (e.g., http://example.com or 192.168.1.1): {Fore.RESET if Fore else ''}")
    if not is_valid_target(target):
        print_fallback("[!] Invalid target format", style="bold red")
        return
    target = normalize_target_url(target)
    
    if not check_target_reachable(target):
        print_fallback(f"[!] Target {target} not reachable", style="bold red")
        return
    
    interface = get_network_interfaces(target)
    output_dir = f"scan_results_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    target_ip = target.replace("http://", "").replace("https://", "").split("/")[0]
    wireshark_output_file = f"/tmp/wireshark_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    
    all_findings = {}
    tools_to_run = [
        ("suricata", f"suricata -c /etc/suricata/suricata.yaml -i any", True, "Suricata", 600),
        ("nikto", f"nikto -h {target} -Tuning 123456789 -Plugins 'apache_expect_crossattack;report_html;tests'", False, "Nikto", 1800),
        ("whatweb", f"whatweb --no-errors -a 3 -v {target}", False, "WhatWeb", 1200),
        ("gobuster", f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -q -t 20 -x php,txt,html,js,conf,ini", False, "Gobuster", 900),
        ("nmap", f"nmap -sV -p 1-10000 --open --script vuln {target_ip}", False, "Nmap", 900),
    ]
    
    total_findings = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    
    # Start Wireshark once
    if interface and tools_available.get("tshark", False):
        start_wireshark(interface, target_ip, wireshark_output_file)
    
    # Run tools in parallel
    if rich_available:
        with Progress(TextColumn("[cyan]Scanning: {task.percentage:>3.0f}%"), BarColumn(), console=console) as progress:
            task = progress.add_task("Overall Scan", total=len(tools_to_run))
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_to_tool = {}
                for tool_name, command, use_sudo, description, timeout in tools_to_run:
                    if stop_execution or not tools_available.get(tool_name, False):
                        print_fallback(f"[!] {description} not installed", style="bold red")
                        progress.advance(task)
                        continue
                    print_fallback(f"[*] Running {description}...", style="cyan")
                    if tool_name == "suricata":
                        success, log_file = setup_suricata_config(target_ip)
                        if not success:
                            print_fallback(f"[!] {description} failed: Configuration error", style="bold red")
                            all_findings[description] = [{"finding": "Suricata configuration error", "severity": "Info", "count": 1, "cve": "N/A"}]
                            total_findings["Info"] += 1
                            progress.advance(task)
                            continue
                    future = executor.submit(run_command, command, use_sudo, description, timeout)
                    future_to_tool[future] = (tool_name, description, log_file if tool_name == "suricata" else None)
                
                for future in as_completed(future_to_tool):
                    if stop_execution:
                        break
                    tool_name, description, log_file = future_to_tool[future]
                    try:
                        result = future.result()
                        if tool_name == "suricata" and log_file:
                            all_findings[description] = analyze_suricata_output(log_file, tool_name)
                        else:
                            all_findings[description] = analyze_tool_output(result, tool_name)
                        print_fallback(f"[+] {description} completed", style="bold green")
                    except Exception as e:
                        print_fallback(f"[!] {description} failed: {str(e)}", style="bold red")
                        all_findings[description] = [{"finding": f"{description} failed: {str(e)}", "severity": "Info", "count": 1, "cve": "N/A"}]
                        total_findings["Info"] += 1
                    progress.advance(task)
    
    else:
        print_fallback("Scanning: 0%", end="\r")
        total_tools = len(tools_to_run)
        completed_tools = 0
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_tool = {}
            for tool_name, command, use_sudo, description, timeout in tools_to_run:
                if stop_execution or not tools_available.get(tool_name, False):
                    print_fallback(f"\n[!] {description} not installed")
                    completed_tools += 1
                    print_fallback(f"Scanning: {int((completed_tools / total_tools) * 100)}%", end="\r")
                    continue
                print_fallback(f"\n[*] Running {description}...")
                if tool_name == "suricata":
                    success, log_file = setup_suricata_config(target_ip)
                    if not success:
                        print_fallback(f"\n[!] {description} failed: Configuration error")
                        all_findings[description] = [{"finding": "Suricata configuration error", "severity": "Info", "count": 1, "cve": "N/A"}]
                        total_findings["Info"] += 1
                        completed_tools += 1
                        print_fallback(f"Scanning: {int((completed_tools / total_tools) * 100)}%", end="\r")
                        continue
                future = executor.submit(run_command, command, use_sudo, description, timeout)
                future_to_tool[future] = (tool_name, description, log_file if tool_name == "suricata" else None)
            
            for future in as_completed(future_to_tool):
                if stop_execution:
                    break
                tool_name, description, log_file = future_to_tool[future]
                try:
                    result = future.result()
                    if tool_name == "suricata" and log_file:
                        all_findings[description] = analyze_suricata_output(log_file, tool_name)
                    else:
                        all_findings[description] = analyze_tool_output(result, tool_name)
                    print_fallback(f"\n[+] {description} completed")
                except Exception as e:
                    print_fallback(f"\n[!] {description} failed: {str(e)}")
                    all_findings[description] = [{"finding": f"{description} failed: {str(e)}", "severity": "Info", "count": 1, "cve": "N/A"}]
                    total_findings["Info"] += 1
                completed_tools += 1
                print_fallback(f"Scanning: {int((completed_tools / total_tools) * 100)}%", end="\r")
    
    # Stop Wireshark and analyze output
    if interface and tools_available.get("tshark", False):
        stop_wireshark()
        all_findings["Wireshark"] = analyze_wireshark(wireshark_output_file, "Wireshark")
        if os.path.exists(wireshark_output_file):
            os.remove(wireshark_output_file)
    
    # Clean up Suricata files
    cleanup_suricata_files()
    
    # Display detailed vulnerabilities
    display_vulnerabilities(all_findings)
    
    # Display summary
    if rich_available:
        table = Table(title="Vulnerabilities Summary", show_lines=True, border_style="cyan", header_style="bold magenta")
        table.add_column("Severity", style="cyan", justify="left", width=10)
        table.add_column("Count", style="green", justify="center", width=8)
        for severity, count in total_findings.items():
            table.add_row(severity, str(count), style=f"bold {'red' if severity == 'Critical' else 'red' if severity == 'High' else 'yellow' if severity == 'Medium' else 'green' if severity == 'Low' else 'blue'}")
        console.print("\n")
        console.print(table)
    else:
        print_fallback("\nVulnerabilities Summary:")
        print_fallback("=" * 30)
        for severity, count in total_findings.items():
            color = Fore.RED if severity in ["Critical", "High"] else Fore.YELLOW if severity == "Medium" else Fore.GREEN if severity == "Low" else Fore.BLUE
            print_fallback(f"{color}{severity:<10} {count}{Fore.RESET}")
        print_fallback("=" * 30)
    
    # Generate final report
    generate_final_report(all_findings, target, output_dir)

if __name__ == "__main__":
    main()