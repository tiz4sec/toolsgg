import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
YELLOW = "\033[38;2;255;255;0m"
CYAN = "\033[38;2;0;255;255m"
BOLD = "\033[1m"
RESET = "\033[0m"

def scan(domain):
    try:
        ip = socket.gethostbyname(domain)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        c = s.connect_ex((ip, 22))
        s.close()
        return domain, ip, c == 0
    except:
        return domain, None, False

file = input("File format (ip:port): ")
t = int(input("Thread: ") or 10)

with open(file) as f:
    d = [x.strip() for x in f if x.strip()]

nm = f"hasil_{int(time.time())}.txt"

print(f"\n{CYAN}Scanning {len(d)} domain {nm}){RESET}\n")

open_list = []
with ThreadPoolExecutor(max_workers=t) as ex:
    futures = [ex.submit(scan, domain) for domain in d]
    for future in as_completed(futures):
        domain, ip, ok = future.result()
        if ok:
            print(f"{GREEN}{domain} → {ip}:22 {RESET}")
            open_list.append(f"{ip}:22")
            with open(nm, "a") as f:
                f.write(f"{ip}:22\n")
        elif ip:
            print(f"{RED}{domain} → {ip}:22 {RESET}")
        else:
            print(f"{YELLOW}{domain} → {RESET}")

print(f"\n{BOLD}Total terbuka: {len(open_list)}{RESET}")

if open_list:
    print(f"\n{BOLD}{GREEN}Yang terbuka:{RESET}")
    for x in open_list:
        print(f"  {GREEN}• {x}{RESET}")
    print(f"\n{CYAN}auto sv ke {nm}{RESET}")
else:
    print(f"\n{YELLOW}gak ada yg aktif{RESET}")

print(f"\n{BOLD}{GREEN}Selesai!{RESET}")