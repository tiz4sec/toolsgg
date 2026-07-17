# 🛠️ ALL-IN-ONE SECURITY TOOLS by @dex2a3

---

## 📌 Deskripsi
Tools multifungsi untuk scanning, exploit, dan enumerasi website. Support berbagai fitur mulai dari scan domain, sensitive files, SQL injection, hingga hash cracking.

---

## 🔧 DAFTAR FITUR LENGKAP

| No | Fitur | Deskripsi |
|----|-------|-----------|
| 1 | Scan Domain Massal | Scan domain hidup/mati dari file, tampilkan status code (200, 301, 404) |
| 2 | Scan .env | Cari file .env, .env.backup, .env.bak di website |
| 3 | Scan .git | Cari folder .git/config dan .git/HEAD |
| 4 | Scan phpinfo | Cari phpinfo.php, info.php, test.php |
| 5 | Scan Sensitive Files | Scan 35+ file sensitif (web.config, .htaccess, .htpasswd, dll) |
| 6 | CVE-2026-9612 | Exploit kerentanan plugin WhatsApp Order Invoices |
| 7 | CVE-2026-9227 | Exploit kerentanan plugin GutenBee (login + upload shell) |
| 8 | Domain Sorter (regex) | Ekstrak domain dari file mentahan (url campur) |
| 9 | Checker WordPress & Plugin | Cek login WordPress + detect plugin |
| 10 | Parser NIK KTP | Parse NIK 16 digit (provinsi, kabupaten, kecamatan, zodiak, pasaran) |
| 11 | Sorter Domain (WordPress) | Filter domain yang pake WordPress |
| 12 | Scan SQL Injection | Scan SQL injection di parameter GET (error-based) |
| 13 | Sorter Domain (Drupal) | Filter domain yang pake Drupal |
| 14 | Scan Port 22 SSH | Scan port 22 SSH terbuka |
| 15 | Exploit .env | Exploit .env dengan format (url\|base64:key) |
| 16 | Exploit Git Exposure | Download .git folder pake git-dumper |
| 17 | Exploit .svn Exposure | Exploit .svn folder pake svn-extractor |
| 18 | Scan .svn Exposure | Scan .svn/entries, .svn/wc.db |
| 19 | Check Proxy | Cek proxy format (ip:port) valid |
| 20 | Setup API DDoS Botnet | Setup server untuk DDoS botnet |
| 21 | Subfinder Domain | Scan subdomain pake subfinder |
| 22 | Hash Decrypt | Crack hash MD5/SHA1/SHA256/SHA384/SHA512 + auto setup environment |
| 23 | Keluar | Exit tools |

---

## 🚀 Cara Install
```bash
git clone https://github.com/Fathir95/toolsgg
cd tools
pip install -r requirements.txt
python main.py
