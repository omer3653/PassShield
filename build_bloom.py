

import os
import sys
import gzip
import requests
from pybloom_live import BloomFilter

ROCKYOU_URL = (
    "https://github.com/brannondorsey/naive-hashcat/releases/download/"
    "data/rockyou.txt"
)
LOCAL_TXT  = "rockyou.txt"
OUTPUT_BIN = "rockyou_bloom.bin"

FALSE_POSITIVE_RATE = 0.001   # 0.1 % — very accurate, ~25 MB on disk


def download_rockyou():
    if os.path.exists(LOCAL_TXT):
        print(f"[✓] {LOCAL_TXT} already exists, skipping download.")
        return
    print(f"[↓] Downloading rockyou.txt from GitHub …")
    r = requests.get(ROCKYOU_URL, stream=True)
    r.raise_for_status()
    total = int(r.headers.get("content-length", 0))
    downloaded = 0
    with open(LOCAL_TXT, "wb") as f:
        for chunk in r.iter_content(chunk_size=65536):
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded / total * 100
                print(f"\r   {pct:.1f}%", end="", flush=True)
    print(f"\n[✓] Saved to {LOCAL_TXT}")


def build_filter():
    print("[…] Counting lines …")
    with open(LOCAL_TXT, "rb") as f:
        n_lines = sum(1 for _ in f)
    print(f"[✓] {n_lines:,} passwords found")

    print("[…] Building Bloom filter …")
    bf = BloomFilter(capacity=n_lines, error_rate=FALSE_POSITIVE_RATE)

    with open(LOCAL_TXT, "rb") as f:
        for i, raw in enumerate(f):
            try:
                word = raw.decode("utf-8").strip().lower()
            except UnicodeDecodeError:
                word = raw.decode("latin-1").strip().lower()
            if word:
                bf.add(word)
            if (i + 1) % 1_000_000 == 0:
                print(f"   {i+1:,} processed …")

    with open(OUTPUT_BIN, "wb") as out:
        bf.tofile(out)

    size_mb = os.path.getsize(OUTPUT_BIN) / 1_048_576
    print(f"\n[✓] Bloom filter saved → {OUTPUT_BIN}  ({size_mb:.1f} MB)")
    print(f"    Capacity : {bf.capacity:,}")
    print(f"    Error rate: {FALSE_POSITIVE_RATE*100:.1f}%")


if __name__ == "__main__":
    download_rockyou()
    build_filter()
    print("\nDone! Add rockyou_bloom.bin to your project and deploy.")