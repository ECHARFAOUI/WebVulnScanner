# 🛡️ WebVulnScanner

**WebVulnScanner** is an advanced and modular toolkit for scanning and analyzing vulnerabilities in web applications.  
It integrates multiple powerful tools such as **Nikto**, **Wireshark**, **Suricata**, **Nmap**, **Legion**, and **CyberScan** to perform deep security assessments.

## 🚀 Features

- 🔎 Web server vulnerability scanning using **Nikto**
- 🌐 Service discovery and enumeration with **Nmap**
- 🔬 Packet capture and network analysis using **Wireshark**
- 🛡️ Intrusion detection and alerting via **Suricata**
- ⚙️ Fast reconnaissance and brute-force with **Legion**
- 🧪 Cyber attack simulation with **CyberScan**
- 📄 Output logs, captures, and reports organized by tool
- 🧰 Modular structure for automation and customization

## 🧰 Tools Used

| Tool        | Purpose                          |
|-------------|----------------------------------|
| Nikto       | Web vulnerability scanning       |
| Nmap        | Port scanning and service enum   |
| Wireshark   | Packet sniffing and PCAP capture |
| Suricata    | IDS/IPS and alerting engine      |
| Legion      | Automated service enumeration    |
| CyberScan   | Attack surface and exploit tests |

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
