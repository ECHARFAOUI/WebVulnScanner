# 🛡️ WebVulnScanner

**WebVulnScanner** is an advanced and modular toolkit for scanning and analyzing vulnerabilities in web applications.
It integrates multiple powerful tools such as **Nikto**, **Wireshark**, **Suricata**, **Nmap**, **Legion**, and **CyberScan** to perform deep security assessments.

## 🚀 Features

* 🔎 Web server vulnerability scanning using **Nikto**
* 🌐 Service discovery and enumeration with **Nmap**
* 🔬 Packet capture and network analysis using **Wireshark**
* 🛡️ Intrusion detection and alerting via **Suricata**
* ⚙️ Fast reconnaissance and brute-force with **Legion**
* 🧪 Cyber attack simulation with **CyberScan**
* 📄 Output logs, captures, and reports organized by tool
* 🧰 Modular structure for automation and customization

## 🧰 Tools Used

| Tool      | Purpose                          |
| --------- | -------------------------------- |
| Nikto     | Web vulnerability scanning       |
| Nmap      | Port scanning and service enum   |
| Wireshark | Packet sniffing and PCAP capture |
| Suricata  | IDS/IPS and alerting engine      |
| Legion    | Automated service enumeration    |
| CyberScan | Attack surface and exploit tests |

## 📁 Project Structure

```bash
WebVulnScanner/
├── scans/
│   ├── nikto/
│   ├── nmap/
│   ├── suricata/
│   └── wireshark/
├── logs/
├── scripts/
├── reports/
└── README.md
```

## ⚙️ Installation

```bash
git clone https://github.com/ECHARFAOUI/WebVulnScanner.git
chmod +x WebVulnScanner
cd WebVulnScanner
sudo python3 WebVulnScanner.py
```

If the script prompts you to install or update tools, simply agree to proceed.

Then, enter the target URL or IP address when prompted. After scanning is complete, results will be displayed in a structured table and stored in the corresponding directories.

## 📜 Legal Disclaimer

> This tool is strictly intended for **educational purposes** and **authorized security testing** only. You must obtain **explicit permission** before scanning any system or network. Unauthorized use may **violate applicable laws** and regulations.
