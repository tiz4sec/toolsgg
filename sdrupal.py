import re
import os

patterns = [
    re.compile(r'/(core/|modules/|themes/|profiles/|sites/|vendor/)', re.IGNORECASE),
    re.compile(r'/(index\.php\?q=|node/\d+|taxonomy/term/\d+|user/\d+)', re.IGNORECASE),
    re.compile(r'/(user/login|user/register|user/password|user/logout)', re.IGNORECASE),
    re.compile(r'/(admin|admin/.*|admin/structure|admin/config|admin/content)', re.IGNORECASE),
    re.compile(r'/(admin/people|admin/modules|admin/appearance|admin/reports)', re.IGNORECASE),
    
    re.compile(r'/(sites/default/settings\.php|sites/default/services\.yml)', re.IGNORECASE),
    re.compile(r'/(sites/default/files/|sites/all/modules/|sites/all/themes/)', re.IGNORECASE),
    re.compile(r'/(sites/[\w.-]+/settings\.php)', re.IGNORECASE),
    
    re.compile(r'/(CHANGELOG\.txt|COPYRIGHT\.txt|INSTALL\.txt|MAINTAINERS\.txt|README\.txt)', re.IGNORECASE),
    re.compile(r'/(composer\.json|composer\.lock|core/install\.php|update\.php)', re.IGNORECASE),
    re.compile(r'/(cron\.php|authorize\.php|install\.php|rebuild\.php)', re.IGNORECASE),
    
    re.compile(r'/api/|/rest/|/jsonapi/|/graphql/', re.IGNORECASE),
    re.compile(r'/entity/|/taxonomy/|/media/|/file/', re.IGNORECASE),
    re.compile(r'/views/ajax|/system/ajax|/autocomplete', re.IGNORECASE),
    re.compile(r'/entity_reference_autocomplete', re.IGNORECASE),
    
    re.compile(r'/(views|ctools|token|pathauto|webform|devel|admin_toolbar|paragraphs)', re.IGNORECASE),
    re.compile(r'/(commerce|ubercart|rules|feeds|migrate|search_api|facets)', re.IGNORECASE),
    re.compile(r'/(panels|page_manager|layout_builder|layout_discovery)', re.IGNORECASE),
    re.compile(r'/(metatag|redirect|xmlsitemap|honeypot|captcha|recaptcha)', re.IGNORECASE),
    
    re.compile(r'/(bartik|seven|adminimal|bootstrap|classy|stable|claro|gin)', re.IGNORECASE),
    re.compile(r'/(adaptivetheme|omega|zen|sky|garland|olivero)', re.IGNORECASE),
    
    re.compile(r'Drupal\s+[0-9]+\.[0-9]+', re.IGNORECASE),
    re.compile(r'<meta\s+name="Generator"\s+content="Drupal', re.IGNORECASE),
    re.compile(r'<meta\s+name="generator"\s+content="Drupal', re.IGNORECASE),
    re.compile(r'X-Drupal-Cache|X-Drupal-Dynamic-Cache', re.IGNORECASE),
    re.compile(r'Drupal\.[a-z]+\.css|Drupal\.[a-z]+\.js', re.IGNORECASE),
    
    re.compile(r'/sites/[\w.-]+/', re.IGNORECASE),
    re.compile(r'/sites/[\w.-]+/files/', re.IGNORECASE),
    
    re.compile(r'/cron/[\w]+|/cron\.php', re.IGNORECASE),
    

    re.compile(r'/update\.php|/update', re.IGNORECASE),
]

def match_any_pattern(text):
    for pattern in patterns:
        if pattern.search(text):
            return True
    return False

def main():    
    files = input("Masukkan nama file .txt (pisahkan dengan spasi): ").split()
    
    if not files:
        print("[X] Tidak ada file yang dimasukkan!")
        return
    
    output_file = input("Masukkan nama file output (default: drupal_urls.txt): ").strip()
    if not output_file:
        output_file = "drupal_urls.txt"
    
    seen_lines = set()
    total_lines = 0
    processed_files = 0
    total_checked = 0
    
    with open(output_file, "w", encoding="utf-8") as fout:
        for filename in files:
            if not os.path.exists(filename):
                print(f"[X] File tidak ditemukan: {filename}")
                continue
            
            processed_files += 1
            print(f"[+] Memproses: {filename}")
            
            with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    total_checked += 1
                    if match_any_pattern(line) and line not in seen_lines:
                        fout.write(line + "\n")
                        seen_lines.add(line)
                        total_lines += 1
                        print(f"  [DETECTED] {line}")
    
    print("=== SELESAI ===")
    print(f"Total file diproses    : {processed_files}")
    print(f"Total URL diperiksa    : {total_checked}")
    print(f"Total URL Drupal unik  : {len(seen_lines)}")
    print(f"Hasil tersimpan di     : {output_file}")
    print("="*50)

if __name__ == "__main__":
    main()