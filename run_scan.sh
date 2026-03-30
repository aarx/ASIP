#!/bin/bash

LOCKFILE="/tmp/asm_scan.lock"

if [ -f "$LOCKFILE" ]; then
    echo "Scan already running. Exiting."
    exit 1
fi

touch "$LOCKFILE"

echo "===== ASM SCAN START $(date) ====="

cd /home/kali/Desktop/Scripts/asm-platform/recon || exit

python3 recon.py seeds.txt --expand

docker exec asm_backend python ingest.py

echo "===== ASM SCAN END $(date) ====="

rm -f "$LOCKFILE"
