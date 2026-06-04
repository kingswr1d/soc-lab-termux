#!/usr/bin/env python3
"""
Network packet inspector for captured pcaps.
"""
from scapy.all import rdpcap
import sys


def analyze_pcap(pcap_file):
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
        proto = pkt.__class__.__name__
        stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1

        if 'IP' in pkt:
            src = pkt['IP'].src
            dst = pkt['IP'].dst
            stats['source_ips'][src] = stats['source_ips'].get(src, 0) + 1
            stats['dest_ips'][dst] = stats['dest_ips'].get(dst, 0) + 1

            if 'TCP' in pkt:
                dport = pkt['TCP'].dport
                key = f"TCP:{dport}"
                stats['ports'][key] = stats['ports'].get(key, 0) + 1
            elif 'UDP' in pkt:
                dport = pkt['UDP'].dport
                key = f"UDP:{dport}"
                stats['ports'][key] = stats['ports'].get(key, 0) + 1

    print("\n=== PCAP ANALYSIS ===")
    print(f"Total packets: {stats['total']}")
    print(f"\nProtocol distribution:")
    for proto, count in sorted(stats['protocols'].items(),
                               key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {proto:20s} {count}")

    print(f"\nTop source IPs:")
    for ip, count in sorted(stats['source_ips'].items(),
                            key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {ip:20s} {count}")

    print(f"\nTop destination ports:")
    for port, count in sorted(stats['ports'].items(),
                              key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {port:20s} {count}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: packet_inspector.py <pcap_file>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
