import sqlite3
import zlib
import os
JCACHE_PATH = r"c:\\Program Files (x86)\\Steam\\steamapps\\common\\RuneScape\\RuneScape\\js5-14.jcache"
OUTPUT_DIR = r"c:\\users\\no_ne\\Desktop\\"
conn = sqlite3.connect(JCACHE_PATH)
cursor = conn.cursor()
cursor.execute("SELECT key, data FROM cache")
rows = cursor.fetchall()
os.makedirs(OUTPUT_DIR, exist_ok=True)

for key, blob in rows:
    if blob.startswith(b"ZLB"):
        try:
            start = blob.find(b"\x78\x9c")
            if start == -1:
                start = blob.find(b"\x78\xda")
            if start == -1:
                start = blob.find(b"\x78\x01")
            if start == -1:
                print(f"[!] No zlib header found in row {key}")
                continue
            compressed_data = blob[start:]
            decompressed_data = zlib.decompress(compressed_data)
            output_path = os.path.join(OUTPUT_DIR, f"{key}.dds")
            with open(output_path, "wb") as f:
                f.write(decompressed_data)
            print(f"[+] Extracted DDS: {output_path}")
        except Exception as e:
            print(f"[!] Failed to decompress row {key}: {e}")
conn.close()
