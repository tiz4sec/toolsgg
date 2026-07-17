import re
import os

patterns = [
    re.compile(r'/(wp-login\.php|wp-admin|wp-signup\.php|wp-activate\.php)', re.IGNORECASE),
    re.compile(r'/(wp-content|wp-includes|wp-json)', re.IGNORECASE),
    re.compile(r'/(xmlrpc\.php|wp-config\.php|readme\.html|license\.txt)', re.IGNORECASE),
    re.compile(r'/wp-json/wp/v2/', re.IGNORECASE),
    re.compile(r'/index\.php\?rest_route=/', re.IGNORECASE),
    re.compile(r'/wp-content/plugins/', re.IGNORECASE),
    re.compile(r'/wp-content/themes/', re.IGNORECASE),
]

def match_any_pattern(text):
    for pattern in patterns:
        if pattern.search(text):
            return True
    return False

files = input("Masukkan nama file .txt (pisahkan dengan spasi): ").split()
output_file = input("Masukkan nama file output: ")

seen_lines = set()
total_lines = 0

with open(output_file, "w", encoding="utf-8") as fout:
    for filename in files:
        if not os.path.exists(filename):
            print(f"[X] File tidak ditemukan: {filename}")
            continue

        print(f"[+] Memproses: {filename}")
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if match_any_pattern(line) and line not in seen_lines:
                    fout.write(line + "\n")
                    seen_lines.add(line)
                    total_lines += 1

print("\n=== Selesai ===")
print(f"Total file diproses : {len(files)}")
print(f"Total hasil unik    : {len(seen_lines)}")
print(f"Hasil tersimpan di  : {output_file}")