# Network Security Auditor – Professional Edition

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A modular, **asynchronous** network security auditing tool for internal infrastructure assessments. It discovers live hosts, performs port scanning with banner grabbing, measures network distance (hops), maps vulnerabilities to CVEs (via local DB or NVD API), includes optional exploitation modules for default credentials, and offers an **interactive post‑scan menu** to test access (SSH, Telnet, FTP, HTTP, SMB, SNMP). **No Nmap required** – all scanning uses Python libraries and system utilities.

> **⚠️ Legal Notice**: This tool is intended for **authorized security assessments only**. Unauthorized scanning or exploitation of networks you do not own or have explicit written permission to test is illegal. The user assumes all responsibility for any misuse.

---

## Features

- **Asynchronous Network Discovery**  
  – ARP scanning (via Scapy) with fallback to ICMP ping sweep.
- **Distance Measurement**  
  – Traceroute (Scapy or system command) to count hops.
- **Asynchronous Service Detection**  
  – TCP connect scan on configurable ports + banner grabbing using `asyncio` streams.
- **Advanced CVE Mapping**  
  – Banner parsing (SSH, HTTP, Telnet).  
  – Local CVE database (JSON) and/or **NVD API** integration with caching and rate limiting.
- **Exploitation Modules**  
  – Default credential checks for SSH, Telnet, HTTP Basic Auth, FTP, SNMP, and SMB share enumeration.
- **Rate Limiting & Safe Mode**  
  – Configurable concurrency limits, delays between ports/hosts to avoid DoS.
- **Interactive Post‑Scan Menu**  
  – After the audit, select a host and choose an action:  
    * SSH – try default creds → get a mini‑shell*  
    * Telnet – try default creds → interactive session  
    * FTP – list files with anonymous/default login  
    * HTTP – detect login page and try default creds  
    * SMB – list shares  
    * SNMP – walk system info  
- **Reporting**  
  – Generates **HTML** and **JSON** reports with host details, vendor, device type, open ports, vulnerabilities, and exploits.
- **Robust Logging**  
  – Logs to console and file (optional dry‑run to disable file writes).
- **Pure Python SNMP**  
  – No external SNMP binaries required (`pysnmp`).

---

## Requirements

- **Python 3.6+**
- **Root/Administrator privileges** (for ARP scanning; fallback ICMP works without)
- **Python packages** (install via pip):
  ```bash
  pip install scapy paramiko requests aiohttp pysnmp

- **For SMB share enumeration, also install:**

  ```bash
  pip install pysmb
 - **System tools (usually pre-installed):**
   
   ping, traceroute (or tracert on Windows)
---
##  Installation
Clone the repository:

bash

git clone https://github.com/NULL200OK/network-security-auditor-plus.git

cd network-security-auditor-plus

**(Optional)**

Create a local CVE database file (cve_db.json) in the same directory (see Configuration).

---

- **Usage**

Run the script with sudo for full capabilities (ARP scanning, raw packets):

```bash
sudo python3 network_security_auditor++.py [arguments]
1- Basic Examples
Scan default network (192.168.1.0/24) with default ports:
sudo python3 network_security_auditor++.py
2- Specify custom networks and ports:
sudo python3 network_security_auditor++.py --networks 192.168.1.0/24 10.0.0.0/24 --ports 22 80 443 445
3- Enable safe mode (adds delays):
sudo python3 network_security_auditor++.py --safe
4- Limit concurrent hosts (default 10):
sudo python3 network_security_auditor++.py --max-concurrent 5
5- Skip exploitation modules (detection only):
sudo python3 network_security_auditor++.py --no-exploit
6- Dry run – no files written:
sudo python3 network_security_auditor++.py --dry-run
---

 ** Command‑line Arguments
  ## Argument	Description :
* networks	CIDR networks to scan (e.g., 192.168.1.0/24 10.0.0.0/24)
* ports	Ports to scan (e.g., 22 80 443 445)
*  html	Output HTML report filename (default: report.html)
*  json	Output JSON report filename (default: report.json)
*  no-exploit	Skip all exploitation attempts
*  safe	Enable safe mode – adds delays between port/host scans
*  dry-run	Do not write any files (logs, reports) – only console output
*  max-concurrent	Maximum number of hosts to audit in parallel (default: 10)
**  Configuration :
All settings are in the CONFIG dictionary at the top of the script. You can modify:

Networks – default subnets to scan.

** Timeouts & delays – timeout, port_delay, host_delay (used in safe mode).

* Max concurrent hosts – rate limiting.

* Ports – list of ports to scan.

* Default credentials – add/remove username/password pairs for each service.

* CVE database file – path to local JSON file.

* NVD API key – optional key to increase rate limits.

**  Local CVE Database
* Create a cve_db.json file with the following structure:
json
{
    "openssh:7.2p2": ["CVE-2016-6210"],
    "apache:2.4.29": ["CVE-2017-9798"]
}
* If present, the script will use this local data first. If a product/version is not found,
 it will query the NVD API (requires internet).
* If you do not provide a local file and do not have an API key,
 the script will still function but with possible rate limits.

** NVD API Key (Optional)
To avoid rate limits, obtain a free API key from NVD and set it in the script:

python
CONFIG["nvd_api_key"] = "your-api-key-here"
Interactive Post‑Scan Menu
After the audit finishes and reports are generated, the script asks:

** text
Do you want to attempt to login to any host? (y/N):
If you answer y, a numbered list of hosts with their open ports appears.
Select a host, then choose an action based on available services:

* SSH – tries default credentials; if successful,
      enters a mini‑shell where you can run commands (ls, cat /etc/passwd, exit).

* Telnet – tries default credentials; opens an interactive telnet session.

* FTP – tries anonymous or default login; lists files in the root directory.

* HTTP – detects a login page (common paths) and tries default credentials;
       displays the first 500 characters of the response if successful.

* SMB – lists SMB shares (requires pysmb).

SNMP – performs a walk for sysDescr, sysName, and ifDescr.

** All actions display success/failure messages.
⚠️ Important: This feature is for authorized testing only.
    Do not attempt to log into systems you do not own or have explicit permission to access.

** Reporting
  After a scan, two reports are generated:

* HTML report – human‑readable, color‑coded for vulnerabilities and exploits.
* Example table columns: Host, MAC, Vendor, Device Type,
* Distance (hops), Open Ports, Vulnerabilities, Exploits.

** JSON report – machine‑readable for further processing.

** License
This project is licensed under the MIT License – see the LICENSE file for details.

** Acknowledgments

Built with Scapy, Paramiko, aiohttp, pysnmp, and Requests.

Inspired by professional network assessment tools.

