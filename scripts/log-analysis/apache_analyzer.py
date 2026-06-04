#!/usr/bin/env python3
"""
Apache Log Analyzer - SOC Lab Practice
Analyzes access logs for suspicious patterns.
"""
import re
from collections import Counter
import sys


def analyze_apache_logs(logfile):
    print(f"[*] Analyzing: {logfile}")

    pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" '
        r'(?P<status>\d+) (?P<size>\S+)'
    )

    ip_counter = Counter()
    status_counter = Counter()
    sql_errors = 0
    xss_attempts = 0
    path_traversal = 0
    shell_uploads = 0

    with open(logfile, 'r', errors='ignore') as f:
        for line in f:
            match = pattern.match(line)
            if not match:
                continue

            ip = match.group('ip')
            status = int(match.group('status'))
            path = match.group('path').lower()

            ip_counter[ip] += 1
            status_counter[status] += 1

            if any(x in path for x in ['union', 'select', 'drop', '--', "'"]):
                sql_errors += 1
            if any(x in path for x in ['<script>', 'javascript:', 'onerror=']):
                xss_attempts += 1
            if '../' in path:
                path_traversal += 1
            if any(x in path for x in ['.php', '.asp', '.jsp']) and 'upload' in path:
                shell_uploads += 1

    print("\n=== ANALYSIS RESULTS ===")
    print(f"Total requests: {sum(ip_counter.values())}")
    print(f"Unique IPs: {len(ip_counter)}")
    print(f"\nTop 10 IPs by request count:")
    for ip, count in ip_counter.most_common(10):
        print(f"  {ip:20s} {count:6d}")

    print(f"\nStatus code distribution:")
    for code in sorted(status_counter.keys()):
        print(f"  {code}: {status_counter[code]}")

    print(f"\n[!] Suspicious patterns found:")
    print(f"  SQL injection attempts: {sql_errors}")
    print(f"  XSS attempts: {xss_attempts}")
    print(f"  Path traversal: {path_traversal}")
    print(f"  Shell upload attempts: {shell_uploads}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: apache_analyzer.py <logfile>")
        sys.exit(1)
    analyze_apache_logs(sys.argv[1])
