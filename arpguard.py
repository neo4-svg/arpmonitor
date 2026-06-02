#!/usr/bin/env python3
"""
arpguard.py
Passive ARP cache monitor (non-root). Polls /proc/net/arp and alerts on suspicious changes.
Usage: python3 arpguard.py --interval 5 --log arpguard.log
"""

import time
import argparse
import json
import os
import socket
from collections import defaultdict
from datetime import datetime

DEFAULT_INTERVAL = 5  # seconds
DEFAULT_LOG = "arpguard.log"
SNAPSHOT_FILE = ".arpguard_snapshot.json"

def read_proc_arp():
    """Read /proc/net/arp and return dict[ip] = mac"""
    arp = {}
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return arp
    # skip header
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 4:
            ip = parts[0]
            hw_type = parts[1]
            flags = parts[2]
            mac = parts[3]
            # ignore incomplete entries
            if mac != "00:00:00:00:00:00":
                arp[ip] = mac.lower()
    return arp

def load_snapshot(path):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_snapshot(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception:
        pass

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def detect_changes(prev, curr, churn_counts, churn_threshold=3):
    """
    prev, curr: dict[ip] = mac
    churn_counts: dict[ip] = consecutive change count
    Returns list of alerts and updated churn_counts
    """
    alerts = []
    # IPs seen now
    for ip, mac in curr.items():
        prev_mac = prev.get(ip)
        if prev_mac is None:
            # new entry
            alerts.append({
                "time": now_iso(),
                "type": "NEW_ENTRY",
                "ip": ip,
                "mac": mac,
                "note": "New ARP entry observed"
            })
            churn_counts[ip] = 0
        elif prev_mac != mac:
            # IP changed MAC
            churn_counts[ip] = churn_counts.get(ip, 0) + 1
            alerts.append({
                "time": now_iso(),
                "type": "IP_MAC_CHANGED",
                "ip": ip,
                "old_mac": prev_mac,
                "new_mac": mac,
                "churn": churn_counts[ip],
                "note": "IP now maps to a different MAC"
            })
            if churn_counts[ip] >= churn_threshold:
                alerts.append({
                    "time": now_iso(),
                    "type": "HIGH_CHURN",
                    "ip": ip,
                    "churn": churn_counts[ip],
                    "note": "High churn for IP; possible ARP spoofing"
                })
        else:
            # stable
            churn_counts[ip] = 0

    # IPs removed
    for ip in set(prev.keys()) - set(curr.keys()):
        alerts.append({
            "time": now_iso(),
            "type": "ENTRY_REMOVED",
            "ip": ip,
            "old_mac": prev[ip],
            "note": "ARP entry removed"
        })
        churn_counts.pop(ip, None)

    # MAC -> multiple IPs detection
    mac_to_ips = defaultdict(list)
    for ip, mac in curr.items():
        mac_to_ips[mac].append(ip)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 3:  # heuristic threshold
            alerts.append({
                "time": now_iso(),
                "type": "MAC_MULTIPLE_IPS",
                "mac": mac,
                "ips": ips,
                "note": "Single MAC claiming many IPs (suspicious)"
            })

    # Duplicate IPs across prev+curr (different MACs seen recently)
    combined = defaultdict(set)
    for ip, mac in prev.items():
        combined[ip].add(mac)
    for ip, mac in curr.items():
        combined[ip].add(mac)
    for ip, macs in combined.items():
        if len(macs) > 1:
            alerts.append({
                "time": now_iso(),
                "type": "DUPLICATE_IP",
                "ip": ip,
                "macs": list(macs),
                "note": "IP observed with multiple MACs across snapshots"
            })

    return alerts, churn_counts

def write_log(path, alerts):
    if not alerts:
        return
    with open(path, "a") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")

def pretty_print(alert):
    t = alert.get("time")
    typ = alert.get("type")
    if typ == "IP_MAC_CHANGED":
        print(f"[{t}] {typ}: {alert['ip']} {alert['old_mac']} -> {alert['new_mac']} (churn={alert.get('churn')})")
    elif typ == "HIGH_CHURN":
        print(f"[{t}] {typ}: {alert['ip']} churn={alert['churn']}")
    elif typ == "MAC_MULTIPLE_IPS":
        print(f"[{t}] {typ}: {alert['mac']} -> {', '.join(alert['ips'])}")
    elif typ == "DUPLICATE_IP":
        print(f"[{t}] {typ}: {alert['ip']} macs={', '.join(alert['macs'])}")
    elif typ == "NEW_ENTRY":
        print(f"[{t}] {typ}: {alert['ip']} -> {alert['mac']}")
    elif typ == "ENTRY_REMOVED":
        print(f"[{t}] {typ}: {alert['ip']} removed (was {alert['old_mac']})")
    else:
        print(f"[{t}] {typ}: {json.dumps(alert)}")

def main():
    parser = argparse.ArgumentParser(description="ARPGuard — passive ARP monitor (no sudo required)")
    parser.add_argument("--interval", "-i", type=int, default=DEFAULT_INTERVAL, help="poll interval seconds")
    parser.add_argument("--log", "-l", default=DEFAULT_LOG, help="append alerts to log file (JSON lines)")
    parser.add_argument("--snapshot", "-s", default=SNAPSHOT_FILE, help="snapshot file path")
    parser.add_argument("--churn-threshold", "-c", type=int, default=3, help="churn threshold for high churn alerts")
    parser.add_argument("--quiet", "-q", action="store_true", help="suppress console output")
    args = parser.parse_args()

    prev = load_snapshot(args.snapshot)
    churn_counts = {}
    if prev:
        # ensure keys are strings
        prev = {str(k): str(v) for k, v in prev.items()}

    print("ARPGuard starting. Polling /proc/net/arp every", args.interval, "seconds.")
    try:
        while True:
            curr = read_proc_arp()
            alerts, churn_counts = detect_changes(prev, curr, churn_counts, churn_threshold=args.churn_threshold)
            if not args.quiet:
                for a in alerts:
                    pretty_print(a)
            write_log(args.log, alerts)
            save_snapshot(args.snapshot, curr)
            prev = curr
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("ARPGuard stopped by user.")

if __name__ == "__main__":
    main()
