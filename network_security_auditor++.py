#!/usr/bin/env python3
"""
Network Security Auditor – with Post‑Scan Interactive Exploitation
Authorized internal use only.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ipaddress import ip_network
from typing import List, Dict, Optional, Tuple, Any

# Third‑party imports
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from pysnmp.hlapi import *
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False

try:
    from smb.SMBConnection import SMBConnection
    PYSMBC_AVAILABLE = True
except ImportError:
    PYSMBC_AVAILABLE = False

print("""

███╗░░██╗██╗░░░██╗██╗░░░░░██╗░░░░░██████╗░░█████╗░░█████╗░  ░█████╗░██╗░░██╗
████╗░██║██║░░░██║██║░░░░░██║░░░░░╚════██╗██╔══██╗██╔══██╗  ██╔══██╗██║░██╔╝
██╔██╗██║██║░░░██║██║░░░░░██║░░░░░░░███╔═╝██║░░██║██║░░██║  ██║░░██║█████═╝░
██║╚████║██║░░░██║██║░░░░░██║░░░░░██╔══╝░░██║░░██║██║░░██║  ██║░░██║██╔═██╗░
██║░╚███║╚██████╔╝███████╗███████╗███████╗╚█████╔╝╚█████╔╝  ╚█████╔╝██║░╚██╗
╚═╝░░╚══╝░╚═════╝░╚══════╝╚══════╝╚══════╝░╚════╝░░╚════╝░  ░╚════╝░╚═╝░░╚═╝
             NULL200OK 💀🔥created by NABEEL 🔥💀
Network Security Auditor – Enhanced Edition
Authorized internal use only.

Features:
- Asynchronous network discovery (ARP, ICMP)
- Asynchronous port scanning + banner grabbing (asyncio streams)
- Distance measurement (traceroute)
- Advanced CVE lookup: local DB + NVD API with caching & rate limiting
- Exploitation modules (default credentials for SSH, Telnet, HTTP, SNMP)
- Rate limiting & safe mode to avoid DoS
- Dry‑run mode (no writes)
- HTML/JSON reporting
- Pure Python SNMP (pysnmp)
- includes optional exploitation modules for default credentials, and offers an **interactive post‑scan menu**
  to test access (SSH, Telnet, FTP, HTTP, SMB, SNMP). **No Nmap required**
""")


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
CONFIG = {
    "networks": ["192.168.1.0/24"],
    "timeout": 3,
    "max_concurrent_hosts": 10,
    "safe_mode": False,
    "port_delay": 0.1,
    "host_delay": 0.5,
    "ports": [21, 22, 23, 25, 80, 443, 445, 161, 3389, 5900, 8080],
    "default_creds": {
        "ssh": [("root", "root"), ("admin", "admin"), ("cisco", "cisco")],
        "telnet": [("root", "root"), ("admin", "admin")],
        "http_basic": [("admin", "admin"), ("admin", "password")],
        "snmp": ["public", "private"],
        "ftp": [("anonymous", ""), ("ftp", "ftp")],
    },
    "cve_db_file": "cve_db.json",
    "nvd_api_key": None,
    "report_file": "audit_report.html",
    "log_file": "audit.log"
}

# ----------------------------------------------------------------------
# Logging setup
# ----------------------------------------------------------------------
logger = logging.getLogger("network_audit")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# ----------------------------------------------------------------------
# MAC OUI Vendor Database
# ----------------------------------------------------------------------
OUI_VENDORS = {
    "000C29": "VMware",
    "005056": "VMware",
    "001C42": "Intel",
    "00E04C": "Realtek",
    "000C41": "Cisco",
    "001A6C": "Juniper",
    "0021A7": "Dell",
    "002590": "HP",
    "001EC2": "Apple",
    "001B63": "Apple",
    "00241D": "Apple",
    "001A73": "Samsung",
    "001F3B": "Huawei",
    "0023CD": "Huawei",
    "0025B0": "MikroTik",
    "0026B0": "Ubiquiti",
    "0001C0": "3Com",
    "0002B3": "Netgear",
    "0003E3": "Linksys",
    "00112F": "D-Link",
    "0014A5": "ZyXEL",
    "0017F2": "TP-Link",
    "001C10": "Cisco Meraki",
}

def get_mac_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    oui = mac[:8].upper().replace(':', '').replace('-', '')
    return OUI_VENDORS.get(oui, "Unknown")

# ----------------------------------------------------------------------
# Device type detection from SNMP sysDescr
# ----------------------------------------------------------------------
def detect_device_type(descr: str) -> str:
    descr_lower = descr.lower()
    if "cisco" in descr_lower and ("router" in descr_lower or "isr" in descr_lower):
        return "Router"
    elif "cisco" in descr_lower and ("switch" in descr_lower or "catalyst" in descr_lower):
        return "Switch"
    elif "juniper" in descr_lower:
        return "Router/Switch"
    elif "mikrotik" in descr_lower:
        return "Router (MikroTik)"
    elif "ubiquiti" in descr_lower:
        return "Wireless AP"
    elif "hp" in descr_lower and "procurve" in descr_lower:
        return "Switch"
    elif "linux" in descr_lower:
        return "Linux Server"
    elif "windows" in descr_lower:
        return "Windows PC/Server"
    elif "printer" in descr_lower:
        return "Printer"
    return "Unknown Device"

# ----------------------------------------------------------------------
# SNMP sysDescr retrieval
# ----------------------------------------------------------------------
async def get_snmp_sysdescr(host: str, port: int = 161, community: str = "public") -> Optional[str]:
    if not PYSNMP_AVAILABLE:
        return None
    loop = asyncio.get_event_loop()
    def _sync_get():
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(community),
                   UdpTransportTarget((host, port), timeout=3, retries=1),
                   ContextData(),
                   ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
        )
        if errorIndication or errorStatus:
            return None
        return str(varBinds[0][1])
    return await loop.run_in_executor(None, _sync_get)

# ----------------------------------------------------------------------
# ARP scan with MAC
# ----------------------------------------------------------------------
def arp_scan_with_mac(network: str) -> List[Tuple[str, str]]:
    if not SCAPY_AVAILABLE:
        return []
    logger.info(f"ARP scanning network {network}...")
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = scapy.srp(packet, timeout=2, verbose=False)[0]
    hosts = [(received.psrc, received.hwsrc) for _, received in answered]
    logger.info(f"Found {len(hosts)} active hosts via ARP.")
    return hosts

def icmp_ping(host: str) -> bool:
    try:
        param = '-n' if os.name == 'nt' else '-c'
        out = subprocess.run(["ping", param, "1", "-W", "1", host],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return out.returncode == 0
    except:
        return False

def traceroute(host: str) -> Optional[int]:
    try:
        if SCAPY_AVAILABLE:
            result = scapy.traceroute(host, maxttl=30, verbose=False)[0]
            if result:
                return len(result.get_trace())
        cmd = ["traceroute", "-n", "-m", "30", "-w", "1", host] if os.name != 'nt' else ["tracert", "-h", "30", host]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10).decode()
        lines = out.strip().split('\n')
        hops = len([l for l in lines if l.strip() and l.strip()[0].isdigit()])
        return hops
    except:
        return None

# ----------------------------------------------------------------------
# Asynchronous banner grabbing
# ----------------------------------------------------------------------
async def grab_banner_async(host: str, port: int, timeout: int = 3) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        if port in [80, 8080]:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 21:
            writer.write(b"HELP\r\n")
        else:
            writer.write(b"\r\n")
        await writer.drain()
        banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return banner.decode('utf-8', errors='ignore').strip()
    except Exception:
        return None

async def port_scan_async(host: str, ports: List[int], safe_mode: bool = False, port_delay: float = 0) -> Dict[int, Optional[str]]:
    results = {}
    for port in ports:
        banner = await grab_banner_async(host, port, timeout=CONFIG["timeout"])
        results[port] = banner
        if safe_mode and port_delay:
            await asyncio.sleep(port_delay)
    return results

# ----------------------------------------------------------------------
# Banner parsing
# ----------------------------------------------------------------------
def parse_ssh_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    match = re.search(r'OpenSSH_([0-9.]+[a-z]*)', banner)
    if match:
        return "openssh", match.group(1)
    return None, None

def parse_http_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    match = re.search(r'Server:\s*([A-Za-z]+)/([0-9.]+)', banner, re.IGNORECASE)
    if match:
        return match.group(1).lower(), match.group(2)
    return None, None

def parse_telnet_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    if "Cisco" in banner:
        return "cisco_ios", None
    return None, None

BANNER_PARSERS = {
    22: parse_ssh_banner,
    80: parse_http_banner,
    443: parse_http_banner,
    8080: parse_http_banner,
    23: parse_telnet_banner,
}

# ----------------------------------------------------------------------
# CVE Database (unchanged)
# ----------------------------------------------------------------------
class CVEDatabase:
    def __init__(self, local_file=None, api_key=None):
        self.local_db = {}
        self.api_key = api_key
        self.cache = {}
        self._last_api_call = 0
        self._rate_limit_seconds = 6
        if local_file and os.path.exists(local_file):
            try:
                with open(local_file) as f:
                    self.local_db = json.load(f)
                logger.info(f"Loaded local CVE database from {local_file}")
            except Exception as e:
                logger.error(f"Failed to load local CVE DB: {e}")

    def _lookup_local(self, product: str, version: str) -> List[str]:
        key = f"{product}:{version}"
        return self.local_db.get(key, [])

    async def _query_nvd(self, product: str, version: str) -> List[str]:
        if not AIOHTTP_AVAILABLE and not REQUESTS_AVAILABLE:
            return []
        now = time.time()
        if now - self._last_api_call < self._rate_limit_seconds:
            wait = self._rate_limit_seconds - (now - self._last_api_call)
            await asyncio.sleep(wait)
        self._last_api_call = time.time()
        cpe = f"cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
        if self.api_key:
            url += f"&apiKey={self.api_key}"
        try:
            if AIOHTTP_AVAILABLE:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10) as resp:
                        data = await resp.json()
            else:
                loop = asyncio.get_event_loop()
                resp = await loop.run_in_executor(None, requests.get, url, {"timeout": 10})
                data = resp.json()
            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln["cve"]["id"]
                cves.append(cve_id)
            return cves
        except Exception as e:
            logger.error(f"NVD query failed for {product} {version}: {e}")
            return []

    async def get_cves(self, product: str, version: str) -> List[str]:
        if not product or not version:
            return []
        cache_key = (product, version)
        if cache_key in self.cache:
            return self.cache[cache_key]
        cves = self._lookup_local(product, version)
        if not cves:
            cves = await self._query_nvd(product, version)
        self.cache[cache_key] = cves
        return cves

# ----------------------------------------------------------------------
# Exploitation modules (reusable)
# ----------------------------------------------------------------------
def ssh_login_and_browse(host: str, port: int = 22):
    """Attempt to login via SSH and if successful, enter a mini-shell."""
    if not PARAMIKO_AVAILABLE:
        print("[-] paramiko not installed, cannot SSH.")
        return
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"[*] Trying default credentials on {host}:{port}...")
    for user, pwd in CONFIG["default_creds"]["ssh"]:
        try:
            client.connect(host, port=port, username=user, password=pwd, timeout=5)
            print(f"[+] Logged in as {user}:{pwd}")
            print("[*] Entering shell. Type 'exit' to quit.")
            while True:
                cmd = input(f"{user}@{host}$ ").strip()
                if cmd.lower() in ('exit', 'quit'):
                    break
                stdin, stdout, stderr = client.exec_command(cmd)
                out = stdout.read().decode()
                err = stderr.read().decode()
                if out:
                    print(out)
                if err:
                    print(err, file=sys.stderr)
            client.close()
            return
        except Exception:
            continue
    print("[-] Failed to login with default credentials.")

def telnet_login_and_browse(host: str, port: int = 23):
    """Attempt to login via Telnet."""
    try:
        import telnetlib
        for user, pwd in CONFIG["default_creds"]["telnet"]:
            tn = telnetlib.Telnet(host, port, timeout=5)
            tn.read_until(b"login: ")
            tn.write(user.encode('ascii') + b"\n")
            tn.read_until(b"Password: ")
            tn.write(pwd.encode('ascii') + b"\n")
            result = tn.read_some()
            if b"incorrect" not in result.lower() and b"failed" not in result.lower():
                print(f"[+] Logged in as {user}:{pwd}")
                print("[*] Telnet session opened. Type 'exit' to close.")
                tn.interact()
                tn.close()
                return
            tn.close()
        print("[-] Failed to login with default credentials.")
    except Exception as e:
        print(f"[-] Telnet error: {e}")

def http_login_attempt(host: str, port: int = 80):
    """Try to guess a login page and attempt default credentials."""
    if not REQUESTS_AVAILABLE:
        print("[-] requests not installed, cannot test HTTP.")
        return
    url = f"http://{host}:{port}/"
    # Simple detection of login page (check for common login paths)
    common_paths = ["/login", "/admin", "/cgi-bin/login", "/user/login"]
    found = None
    for path in common_paths:
        try:
            r = requests.get(url + path, timeout=5)
            if "login" in r.text.lower() or "password" in r.text.lower():
                found = path
                break
        except:
            continue
    if not found:
        print("[-] No obvious login page found.")
        return
    print(f"[*] Trying default credentials on {url}{found}")
    for user, pwd in CONFIG["default_creds"]["http_basic"]:
        try:
            r = requests.get(url + found, auth=(user, pwd), timeout=5)
            if r.status_code == 200 and ("incorrect" not in r.text.lower()):
                print(f"[+] Successful login with {user}:{pwd}")
                # Fetch a simple page to show we're in
                print("[*] First 500 chars of response:")
                print(r.text[:500])
                return
        except:
            continue
    print("[-] Failed to login with default credentials.")

def ftp_login_and_list(host: str, port: int = 21):
    """Attempt anonymous/login and list files."""
    try:
        import ftplib
        for user, pwd in CONFIG["default_creds"]["ftp"]:
            try:
                ftp = ftplib.FTP(host, timeout=5)
                ftp.login(user, pwd)
                print(f"[+] Logged in as {user}:{pwd}")
                files = ftp.nlst()
                print("Files in root:")
                for f in files:
                    print(f"  {f}")
                ftp.quit()
                return
            except ftplib.all_errors:
                continue
        print("[-] Failed to login with default credentials.")
    except Exception as e:
        print(f"[-] FTP error: {e}")

def smb_list_shares(host: str, port: int = 445):
    """List SMB shares (requires pysmb)."""
    if not PYSMBC_AVAILABLE:
        print("[-] pysmb not installed, cannot list SMB shares.")
        return
    try:
        conn = SMBConnection("", "", "", "", use_ntlm_v2=True)
        if conn.connect(host, port):
            shares = conn.listShares()
            print("SMB shares:")
            for share in shares:
                print(f"  {share.name} - {share.comments}")
        else:
            print("[-] Failed to connect to SMB.")
    except Exception as e:
        print(f"[-] SMB error: {e}")

def snmp_walk(host: str, port: int = 161):
    """Perform a simple SNMP walk for sysDescr and interfaces."""
    if not PYSNMP_AVAILABLE:
        print("[-] pysnmp not installed, cannot walk SNMP.")
        return
    community = "public"
    print(f"[*] Trying SNMP walk with community '{community}'...")
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((host, port)),
               ContextData(),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)),
               ObjectType(ObjectIdentity('IF-MIB', 'ifDescr', 0)))
    )
    if errorIndication or errorStatus:
        print("[-] SNMP query failed.")
        return
    for varBind in varBinds:
        print(f"  {varBind[0]} = {varBind[1]}")

# ----------------------------------------------------------------------
# Host audit (core)
# ----------------------------------------------------------------------
async def audit_host(host: str, mac: Optional[str], ports: List[int], cve_db: CVEDatabase,
                     no_exploit: bool = False, safe_mode: bool = False,
                     host_delay: float = 0, port_delay: float = 0) -> Dict[str, Any]:
    logger.info(f"Auditing {host}")
    result = {
        "host": host,
        "mac": mac,
        "vendor": get_mac_vendor(mac) if mac else "Unknown",
        "device_type": "Unknown",
        "distance": traceroute(host),
        "open_ports": {},
        "vulnerabilities": [],
        "exploits": []
    }

    port_banners = await port_scan_async(host, ports, safe_mode, port_delay)
    result["open_ports"] = {p: banner for p, banner in port_banners.items() if banner}

    # CVE matching
    for port, banner in result["open_ports"].items():
        if not banner:
            continue
        parser = BANNER_PARSERS.get(port)
        if parser:
            product, version = parser(banner)
            if product and version:
                cves = await cve_db.get_cves(product, version)
                for cve in cves:
                    result["vulnerabilities"].append({
                        "port": port,
                        "cve": cve,
                        "banner": banner,
                        "product": product,
                        "version": version
                    })

    # SNMP device type
    if 161 in result["open_ports"]:
        sysdescr = await get_snmp_sysdescr(host, 161, "public")
        if sysdescr:
            result["device_type"] = detect_device_type(sysdescr)

    # Fallback vendor guess
    if result["device_type"] == "Unknown" and result["vendor"] != "Unknown":
        vendor = result["vendor"].lower()
        if "cisco" in vendor:
            result["device_type"] = "Cisco Device"
        elif "juniper" in vendor:
            result["device_type"] = "Juniper Device"
        elif "mikrotik" in vendor:
            result["device_type"] = "MikroTik Device"

    # Exploitation (skip if no_exploit)
    if not no_exploit:
        open_port_nums = list(result["open_ports"].keys())
        if 22 in open_port_nums and check_ssh_default_creds(host):
            result["exploits"].append({"type": "SSH default creds", "port": 22})
        if 23 in open_port_nums and check_telnet_default_creds(host):
            result["exploits"].append({"type": "Telnet default creds", "port": 23})
        if any(p in [80, 443, 8080] for p in open_port_nums):
            if check_http_basic_auth(host, port=80):
                result["exploits"].append({"type": "HTTP Basic default creds", "port": 80})
        if 161 in open_port_nums and check_snmp_community(host):
            result["exploits"].append({"type": "SNMP default community", "port": 161})

    if safe_mode and host_delay:
        await asyncio.sleep(host_delay)
    return result

def check_ssh_default_creds(host: str, port: int = 22) -> bool:
    if not PARAMIKO_AVAILABLE:
        return False
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for user, pwd in CONFIG["default_creds"]["ssh"]:
        try:
            client.connect(host, port=port, username=user, password=pwd, timeout=5)
            client.close()
            return True
        except Exception:
            continue
    return False

def check_telnet_default_creds(host: str, port: int = 23) -> bool:
    try:
        import telnetlib
        for user, pwd in CONFIG["default_creds"]["telnet"]:
            tn = telnetlib.Telnet(host, port, timeout=5)
            tn.read_until(b"login: ")
            tn.write(user.encode('ascii') + b"\n")
            tn.read_until(b"Password: ")
            tn.write(pwd.encode('ascii') + b"\n")
            result = tn.read_some()
            tn.close()
            if b"incorrect" not in result.lower() and b"failed" not in result.lower():
                return True
        return False
    except Exception:
        return False

def check_http_basic_auth(host: str, port: int = 80) -> bool:
    if not REQUESTS_AVAILABLE:
        return False
    url = f"http://{host}:{port}/"
    for user, pwd in CONFIG["default_creds"]["http_basic"]:
        try:
            r = requests.get(url, auth=(user, pwd), timeout=5)
            if r.status_code == 200:
                return True
        except:
            continue
    return False

def check_snmp_community(host: str, port: int = 161) -> bool:
    if not PYSNMP_AVAILABLE:
        return False
    for comm in CONFIG["default_creds"]["snmp"]:
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(comm),
                   UdpTransportTarget((host, port)),
                   ContextData(),
                   ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
        )
        if not errorIndication and not errorStatus:
            return True
    return False

# ----------------------------------------------------------------------
# Post‑scan interactive menu
# ----------------------------------------------------------------------
def post_scan_menu(results: List[Dict[str, Any]]):
    print("\n" + "="*60)
    print("POST‑SCAN INTERACTIVE EXPLOITATION")
    print("="*60)
    print("WARNING: This feature may be illegal if you do not have explicit")
    print("         authorization to access these systems. Use only on networks")
    print("         you own or have permission to test.")
    print()
    cont = input("Do you want to attempt to login to any host? (y/N): ").lower()
    if cont != 'y':
        return

    # Display hosts list
    while True:
        print("\nAvailable hosts:")
        for i, r in enumerate(results):
            open_ports = ", ".join(str(p) for p in r["open_ports"].keys())
            print(f"{i+1}. {r['host']} [{r['vendor']}] {r['device_type']} - Open ports: {open_ports or 'None'}")
        print("0. Exit")
        try:
            choice = int(input("\nSelect host number: "))
        except ValueError:
            continue
        if choice == 0:
            break
        if 1 <= choice <= len(results):
            host_info = results[choice-1]
            host = host_info["host"]
            open_ports = list(host_info["open_ports"].keys())
            if not open_ports:
                print("No open ports to exploit.")
                continue
            print(f"\nSelected host: {host}")
            print("Possible actions based on open ports:")
            actions = []
            if 22 in open_ports:
                actions.append(("SSH", "ssh"))
            if 23 in open_ports:
                actions.append(("Telnet", "telnet"))
            if 21 in open_ports:
                actions.append(("FTP", "ftp"))
            if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
                actions.append(("HTTP Login", "http"))
            if 445 in open_ports:
                actions.append(("SMB Share Enumeration", "smb"))
            if 161 in open_ports:
                actions.append(("SNMP Walk", "snmp"))
            if not actions:
                print("No exploitable services found for this host.")
                continue
            for i, (desc, _) in enumerate(actions):
                print(f"{i+1}. {desc}")
            act_choice = int(input("Select action: ")) - 1
            if 0 <= act_choice < len(actions):
                action_key = actions[act_choice][1]
                if action_key == "ssh":
                    ssh_login_and_browse(host)
                elif action_key == "telnet":
                    telnet_login_and_browse(host)
                elif action_key == "ftp":
                    ftp_login_and_list(host)
                elif action_key == "http":
                    http_login_attempt(host)
                elif action_key == "smb":
                    smb_list_shares(host)
                elif action_key == "snmp":
                    snmp_walk(host)
            else:
                print("Invalid selection.")
        else:
            print("Invalid choice.")

# ----------------------------------------------------------------------
# Main audit orchestration
# ----------------------------------------------------------------------
async def run_audit(networks: List[str], ports: List[int], cve_db: CVEDatabase,
                    no_exploit: bool = False, safe_mode: bool = False,
                    host_delay: float = 0, port_delay: float = 0,
                    max_concurrent: int = 10) -> List[Dict[str, Any]]:
    all_hosts = {}  # ip -> mac
    for net in networks:
        if SCAPY_AVAILABLE:
            hosts_with_mac = arp_scan_with_mac(net)
            for ip, mac in hosts_with_mac:
                all_hosts[ip] = mac
        else:
            logger.info("ARP not available, falling back to ICMP ping sweep.")
            net_obj = ip_network(net)
            with ThreadPoolExecutor(max_workers=CONFIG["max_workers"]) as executor:
                futures = {executor.submit(icmp_ping, str(ip)): str(ip) for ip in net_obj.hosts()}
                for future in as_completed(futures):
                    if future.result():
                        ip = futures[future]
                        all_hosts[ip] = None
    logger.info(f"Total hosts to audit: {len(all_hosts)}")

    semaphore = asyncio.Semaphore(max_concurrent)
    async def limited_audit(ip, mac):
        async with semaphore:
            return await audit_host(ip, mac, ports, cve_db, no_exploit, safe_mode, host_delay, port_delay)
    tasks = [limited_audit(ip, mac) for ip, mac in all_hosts.items()]
    results = await asyncio.gather(*tasks)
    return results

# ----------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------
def generate_html_report(results: List[Dict[str, Any]], filename: str, dry_run: bool = False):
    if dry_run:
        logger.info(f"DRY RUN: would generate HTML report at {filename}")
        return
    html = f"""
    <html>
    <head><title>Network Audit Report</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .vuln {{ background-color: #ffcccc; }}
        .exploit {{ background-color: #ffffcc; }}
    </style>
    </head>
    <body>
    <h1>Network Security Audit Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <h2>Host Summary</h2>
    <table border="1">
        <tr><th>Host</th><th>MAC</th><th>Vendor</th><th>Device Type</th><th>Distance (hops)</th><th>Open Ports</th><th>Vulnerabilities</th><th>Exploits</th>去
    """
    for r in results:
        open_ports_str = ", ".join([f"{p}" for p in r["open_ports"].keys()]) or "None"
        vulns_str = "<br>".join([f"{v['port']}: {v['cve']}" for v in r["vulnerabilities"]]) or "None"
        exploits_str = "<br>".join([f"{e['type']} on port {e['port']}" for e in r["exploits"]]) or "None"
        row_class = "vuln" if r["vulnerabilities"] or r["exploits"] else ""
        html += f"""
        <tr class="{row_class}">
            知道{r['host']}知道
            知道{r['mac'] or 'N/A'}知道
            知道{r['vendor']}知道
            知道{r['device_type']}知道
            知道{r['distance'] or 'N/A'}知道
            知道{open_ports_str}知道
            知道{vulns_str}知道
            知道{exploits_str}知道
        </tr>
        """
    html += """
     </table>
    <h2>Detailed Service Info</h2>
    <table border="1">
        <tr><th>Host</th><th>Port</th><th>Banner</th>去
    """
    for r in results:
        for port, banner in r["open_ports"].items():
            html += f"<tr><td>{r['host']}</td><td>{port}</td><td>{banner or 'N/A'}</td></tr>"
    html += """
    </table>
    </body>
    </html>
    """
    with open(filename, 'w') as f:
        f.write(html)
    logger.info(f"HTML report saved to {filename}")

def generate_json_report(results: List[Dict[str, Any]], filename: str, dry_run: bool = False):
    if dry_run:
        logger.info(f"DRY RUN: would generate JSON report at {filename}")
        return
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    logger.info(f"JSON report saved to {filename}")

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
async def main():
    parser = argparse.ArgumentParser(description="Network Security Auditor (Enhanced)")
    parser.add_argument("--networks", nargs="+", help="CIDR networks to scan")
    parser.add_argument("--ports", nargs="+", type=int, help="Ports to scan")
    parser.add_argument("--html", default="report.html", help="HTML report filename")
    parser.add_argument("--json", default="report.json", help="JSON report filename")
    parser.add_argument("--no-exploit", action="store_true", help="Skip exploitation attempts")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (adds delays)")
    parser.add_argument("--dry-run", action="store_true", help="Do not write any files")
    parser.add_argument("--max-concurrent", type=int, default=CONFIG["max_concurrent_hosts"],
                        help="Max concurrent host audits")
    args = parser.parse_args()

    networks = args.networks if args.networks else CONFIG["networks"]
    ports = args.ports if args.ports else CONFIG["ports"]

    if os.geteuid() != 0:
        logger.warning("Not running as root. ARP scanning may fail; ICMP fallback will be used.")

    if not args.dry_run:
        fh = logging.FileHandler(CONFIG["log_file"])
        fh.setLevel(logging.INFO)
        logger.addHandler(fh)

    cve_db = CVEDatabase(CONFIG["cve_db_file"], CONFIG["nvd_api_key"])

    safe_mode = args.safe or CONFIG["safe_mode"]
    host_delay = CONFIG["host_delay"] if safe_mode else 0
    port_delay = CONFIG["port_delay"] if safe_mode else 0

    results = await run_audit(
        networks, ports, cve_db,
        no_exploit=args.no_exploit,
        safe_mode=safe_mode,
        host_delay=host_delay,
        port_delay=port_delay,
        max_concurrent=args.max_concurrent
    )

    generate_html_report(results, args.html, args.dry_run)
    generate_json_report(results, args.json, args.dry_run)

    total_vulns = sum(len(r["vulnerabilities"]) for r in results)
    total_exploits = sum(len(r["exploits"]) for r in results)
    logger.info(f"Audit complete. Total hosts: {len(results)}")
    logger.info(f"Found {total_vulns} potential vulnerabilities and {total_exploits} successful exploits.")

    # Post‑scan interactive menu (only if not dry‑run and if there are hosts)
    if not args.dry_run and results:
        post_scan_menu(results)

if __name__ == "__main__":
    asyncio.run(main())
