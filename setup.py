import os
import sys
import paramiko
import time

def ssh_connect_and_run():
    host = input("Masukkan IP: ")
    username = input("Masukkan username (default root): ") or "root"
    password = input("Masukkan password: ")
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print(f"\n🔗 Menghubungkan ke {host}...")
        client.connect(host, username=username, password=password)
        print("✅ SSH Connected!\n")
        
        print("📥 Download file dari github...")
        os.system("wget https://github.com/Fathir95/api/raw/refs/heads/main/tmpapi.zip")
        
        print("📦 Unzip file....")
        os.system("unzip tmpapi.zip")

        os.chdir("tmpapi")
        
        print("⚙️ Menginstall dependencies..")
        os.system("bash install.sh")
        
        print("🚀 Menjalankan node api.js...")
        os.system("node api.js")
        
        time.sleep(1)
        print("✅ Selesai!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
   
   
        client.close()

if __name__ == "__main__":
    ssh_connect_and_run() 