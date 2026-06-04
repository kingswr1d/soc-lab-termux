#!/data/data/com.termux/files/usr/bin/bash
# SOC Lab Setup Script - Termux/Android
# Sets up core tools for security analyst practice

set -e

echo "=== SOC Home Lab Setup ==="
echo "Target: Termux on Android"
echo ""

# 1. Update packages
echo "[1/6] Updating packages..."
pkg update -y && pkg upgrade -y

# 2. Core security tools
echo "[2/6] Installing core tools..."
pkg install -y \
  nmap \
  tcpdump \
  tshark \
  sqlite3 \
  python \
  python3 \
  git \
  curl \
  jq \
  whois \
  dnsutils \
  net-tools \
  openssl

# 3. Python security libraries
echo "[3/6] Installing Python security libs..."
pip install --upgrade pip
pip install \
  scapy \
  requests \
  beautifulsoup4 \
  python-nmap \
  volatility3 \
  yara-python \
  pandas \
  matplotlib \
  jupyter

# 4. Create project structure
echo "[4/6] Creating lab directory structure..."
mkdir -p ~/soc-lab/{logs,pcaps,reports,scripts,tools,training}
mkdir -p ~/soc-lab/training/{tryhackme,hackthebox,portswigger}
mkdir -p ~/soc-lab/scripts/{log-analysis,network-tools,alert-automation}

# 5. Download sample log datasets for practice
echo "[5/6] Downloading sample datasets..."
cd ~/soc-lab/logs
# Apache logs
curl -s -o apache_access.log "https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log" || echo "Download failed - will create synthetic data"
# Linux auth logs
curl -s -o linux_auth.log "https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log" || echo "Download failed - will create synthetic data"

# 6. Create starter analysis scripts
echo "[6/6] Creating starter scripts..."

cat > ~/soc-lab/scripts/log-analysis/apache_analyzer.py << 'SCRIPT'
#!/usr/bin/env python3
"""
Apache Log Analyzer - SOC Lab Practice
Analyzes access logs for suspicious patterns
"""
import re
from collections import Counter
from datetime import datetime
import sys

def analyze_apache_logs(logfile):
    """Basic Apache log analysis for SOC training."""
    print(f"[*] Analyzing: {logfile}")
    
    # Apache combined log format regex
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
            
            # Detect attack patterns
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
SCRIPT

cat > ~/soc-lab/scripts/log-analysis/ssh_bruteforce_detector.py << 'SCRIPT'
#!/usr/bin/env python3
"""
SSH Log Analyzer - Detect brute force attempts
Analyzes auth.log / secure logs
"""
import re
from collections import Counter, defaultdict
import sys
from datetime import datetime

def analyze_ssh_logs(logfile):
    """Detect SSH brute force patterns."""
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
SCRIPT

cat > ~/soc-lab/scripts/network-tools/packet_inspector.py << 'SCRIPT'
#!/usr/bin/env python3
"""
Network packet analyzer using scapy
"""
from scapy.all import *
import sys
import json

def analyze_pcap(pcap_file):
    """Analyze pcap file for SOC-relevant patterns."""
    print(f"[*] Reading packets from: {pcap_file}")
    
    packets = rdpcap(pcap_file)
    stats = {
        'total': len(packets),
        'protocols': {},
        'source_ips': {},
        'dest_ips': {},
        'ports': {},
    }
    
    for pkt in packets:
        # Protocol
        proto = pkt.__class__.__name__
        stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
        
        # IP layer
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            stats['source_ips'][src] = stats['source_ips'].get(src, 0) + 1
            stats['dest_ips'][dst] = stats['dest_ips'].get(dst, 0) + 1
            
            # TCP/UDP ports
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                stats['ports'][f"TCP:{dport}"] = stats['ports'].get(f"TCP:{dport}", 0) + 1
            elif UDP in pkt:
                dport = pkt[UDP].dport
                stats['ports'][f"UDP:{dport}"] = stats['ports'].get(f"UDP:{dport}", 0) + 1
    
    print("\n=== PCAP ANALYSIS ===")
    print(f"Total packets: {stats['total']}")
    print(f"\nProtocol distribution:")
    for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {proto:20s} {count}")
    
    print(f"\nTop source IPs:")
    for ip, count in sorted(stats['source_ips'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {ip:20s} {count}")
    
    print(f"\nTop destination ports:")
    for port, count in sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {port:20s} {count}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: packet_inspector.py <pcap_file>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
SCRIPT

chmod +x ~/soc-lab/scripts/log-analysis/apache_analyzer.py
chmod +x ~/soc-lab/scripts/log-analysis/ssh_bruteforce_detector.py
chmod +x ~/soc-lab/scripts/network-tools/packet_inspector.py

echo ""
echo "=== Lab Setup Complete ==="
echo "Lab directory: ~/soc-lab/"
echo ""
echo "Next steps:"
echo "1. cd ~/soc-lab/scripts/log-analysis/"
echo "2. python3 apache_analyzer.py ~/soc-lab/logs/apache_access.log"
echo "3. python3 ssh_bruteforce_detector.py ~/soc-lab/logs/linux_auth.log"
echo ""
echo "Resources:"
echo "- TryHackMe: https://tryhackme.com"
echo "- HackTheBox: https://hackthebox.com"
echo "- PortSwigger: https://portswigger.net/web-security"
echo "- OWASP Top 10: https://owasp.org/www-project-top-ten"
