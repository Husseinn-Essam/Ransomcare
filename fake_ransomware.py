import os
import time
import random
import string

def encrypt_file(path):
    with open(path, 'wb') as f:
        f.write(os.urandom(1024))  # Simulates writing encrypted data

def create_and_encrypt_files():
    os.makedirs("/tmp/ransomware_test", exist_ok=True)
    files = []

    # Create a bunch of test files
    for i in range(30):
        fname = ''.join(random.choices(string.ascii_lowercase, k=6)) + ".wcry"
        fpath = f"/tmp/ransomware_test/{fname}"
        with open(fpath, 'w') as f:
            f.write("Initial test content.\n")
        files.append(fpath)
    
    # Rapid file modification and encryption
    for f in files:
        encrypt_file(f)
        time.sleep(0.1)  # Simulate rapid but not instantaneous writes

    # Simulate deletions
    for f in files[:10]:
        os.remove(f)

if __name__ == "__main__":
    create_and_encrypt_files()
