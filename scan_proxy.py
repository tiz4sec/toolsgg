import sys
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime
import requests
import fcntl

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

print(f"""
{GREEN}                                                                                                                                                            
▄█████  ▄▄▄▄  ▄▄▄  ▄▄  ▄▄ ▄▄  ▄▄ ▄▄ ▄▄  ▄▄  ▄▄▄▄   ▄▄▄▄  ▄▄▄▄   ▄▄▄  ▄▄ ▄▄ ▄▄ ▄▄ 
▀▀▀▄▄▄ ██▀▀▀ ██▀██ ███▄██ ███▄██ ██ ███▄██ ██ ▄▄   ██▄█▀ ██▄█▄ ██▀██ ▀█▄█▀ ▀███▀ 
█████▀ ▀████ ██▀██ ██ ▀██ ██ ▀██ ██ ██ ▀██ ▀███▀   ██    ██ ██ ▀███▀ ██ ██   █   
       {RESET}                                                                          
      """)

file = input("Masukkan file proxy: ").strip()

if not file:
    print("Nama file tidak boleh kosong")
    sys.exit(0)

if not os.path.exists(file):
    print(f"File {file} tidak ditemukan")
    sys.exit(0)

OUTPUT_FILE = "proxy_valid.txt"

def baca_proxy(file):
    proxies = []
    try:
        with open(file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if re.match(r'^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:\d+$', line):
                        proxies.append(line)
    except Exception as e:
        print(f"Gagal membaca file: {e}")
    return proxies

def simpan_proxy(proxy):
    try:
        with open(OUTPUT_FILE, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(f"{proxy}\n")
            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)
    except:
        try:
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"{proxy}\n")
        except Exception as e:
            print(f"Gagal simpan proxy: {e}")

def cek_proxy(proxy):
    try:
        proxies = {
            'http': f'http://{proxy}',
            'https': f'http://{proxy}'
        }
        start = time.time()
        response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5)
        if response.status_code == 200:
            latency = round((time.time() - start) * 1000)
            return (proxy, True, latency)
    except:
        pass
    return (proxy, False, 0)

def scan_proxy(proxies, max_workers=50):
    print(f"\nMulai scan {len(proxies)} proxy dari file: {file}")
    print(f"Hasil akan disimpan ke: {OUTPUT_FILE} (mode tambah)")
    print("File tidak akan dihapus\n")

    aktif = []
    total = len(proxies)
    selesai = 0
    start_time = time.time()

    with open(OUTPUT_FILE, "a") as f:
        f.write(f"# FROM: {os.path.basename(file)} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_proxy = {executor.submit(cek_proxy, proxy): proxy for proxy in proxies}

        for future in as_completed(future_to_proxy):
            proxy, status, latency = future.result()
            selesai += 1

            if status:
                aktif.append((proxy, latency))
                simpan_proxy(proxy)
                print(f"{GREEN}[LIVE]{RESET} {proxy} | {latency}ms | Progress: {selesai}/{total}")
            else:
                print(f"{RED}[DEAD]{RESET} {proxy} | Progress: {selesai}/{total}")

    with open(OUTPUT_FILE, "a") as f:
        f.write(f"# END SCAN: {os.path.basename(file)} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    elapsed = time.time() - start_time
    print(f"\nScan selesai dalam {elapsed:.2f} detik")

    return aktif

proxies = baca_proxy(file)

if not proxies:
    print("Tidak ada proxy valid untuk di-scan")
    sys.exit(0)

print("Memulai proses scanning...\n")
aktif = scan_proxy(proxies)

print(f"\n{'='*50}")
print(f"Proxy aktif dari scan ini: {len(aktif)}/{len(proxies)}")
print(f"Semua proxy aktif disimpan di: {OUTPUT_FILE}")

if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "r") as f:
        semua_baris = f.readlines()
        proxy_valid = [line for line in semua_baris if line.strip() and not line.startswith('#')]
        print(f"Total semua proxy di file: {len(proxy_valid)}")
        print(f"\nPreview 5 proxy terakhir:")
        for line in semua_baris[-5:]:
            if line.strip():
                print(f"  {line.strip()}")

if aktif:
    print(f"\nProxy tercepat dari scan ini:")
    aktif_sorted = sorted(aktif, key=lambda x: x[1])
    for proxy, latency in aktif_sorted[:10]:
        print(f"  {GREEN}{proxy}{RESET} | {latency}ms")
else:
    print("Tidak ada proxy yang aktif dari scan ini")
print(f"{'='*50}")