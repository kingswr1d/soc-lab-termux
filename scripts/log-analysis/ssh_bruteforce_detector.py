#!/usr/bin/env python3
"""
SSH Log Analyzer - Detect brute force attempts
Analyzes auth.log / secure logs
"""
import re
from collections import Counter, defaultdict
import sys


def analyze_ssh_logs(logfile):
    print(f"[*] Analyzing SSH logs: {logfile}")

    failed_pattern = re.compile(
        r'Failed password for (\S+) from (\S+) port (\d+)'
    )
    accepted_pattern = re.compile(
        r'Accepted password for (\S+) from (\S+)'
    )

    failed_ips = Counter()
    failed_users = Counter()
    successful_logins = []
    ip_user_map = defaultdict(set)

    with open(logfile, 'r', errors='ignore') as f:
        for line in f:
            fail_match = failed_pattern.search(line)
            if fail_match:
                user, ip, port = fail_match.groups()
                failed_ips[ip] += 1
                failed_users[user] += 1
                ip_user_map[ip].add(user)
                continue

            acc_match = accepted_pattern.search(line)
            if acc_match:
                user, ip = acc_match.groups()
                successful_logins.append({
                    'user': user, 'ip': ip, 'line': line.strip()
                })

    print("\n=== SSH ANALYSIS RESULTS ===")
    print(f"Failed login attempts: {sum(failed_ips.values())}")
    print(f"Unique attacking IPs: {len(failed_ips)}")
    print(f"Successful logins: {len(successful_logins)}")

    print(f"\n[!] Top 10 brute force sources:")
    for ip, count in failed_ips.most_common(10):
        users = ', '.join(list(ip_user_map[ip])[:5])
        print(f"  {ip:20s} attempts={count:4d} users=[{users}]")

    if successful_logins:
        print(f"\n[!] Successful logins after failures:")
        for login in successful_logins[:10]:
            print(f"  {login['user']}@{login['ip']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ssh_bruteforce_detector.py <auth.log>")
        sys.exit(1)
    analyze_ssh_logs(sys.argv[1])
