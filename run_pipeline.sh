#!/bin/bash

echo "===== ASM PIPELINE START $(date) ====="

echo "[1] Running Recon"
cd /home/kali/Desktop/Scripts/asm-platform/recon
python3 recon.py seeds.txt --expand

echo "[2] Running Ingest"
docker exec asm_backend python ingest.py

echo "[3] Port Scan Worker"
docker exec asm_backend python port_scan_worker.py

echo "[4] ASN Worker"
docker exec asm_backend python asn_worker.py

echo "[5] Provider Worker"
docker exec asm_backend python provider_worker.py

echo "[6] Tech Worker"
docker exec asm_backend python tech_worker.py

echo "===== ASM PIPELINE COMPLETE $(date) ====="
