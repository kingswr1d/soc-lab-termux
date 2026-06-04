#!/usr/bin/env python3
"""
Generate synthetic Apache + Linux auth logs for SOC lab practice.
All data is fabricated. No external network calls.
"""
import random
from pathlib import Path
from datetime import datetime, timedelta

BASE = datetime(2026, 6, 3, 10, 0, 0)
IPS = [f"10.0.0.{i}" for i in range(1, 20)]
ATTACKERS = ["192.168.1.100", "203.0.113.5", "198.51.100.23", "172.16.0.55"]
PATHS_NORM = ["/index.html", "/about", "/contact", "/products", "/login",
              "/dashboard", "/api/users", "/static/style.css"]
PATHS_SQLI = ["/login?user=' OR '1'='1", "/search?q= UNION SELECT 1,2,3--",
              "/product?id=1; DROP TABLE users", "/api/data?filter=' OR 1=1--"]
PATHS_XSS  = ["/search?q=<script>alert(1)</script>",
              "/comment?text=<img src=x onerror=alert(2)>",
              "/profile?name=<svg onload=alert(3)>"]
PATHS_TRAV = ["/file?path=../../../etc/passwd",
              "/download?file=....//....//....//etc/shadow",
              "/include?page=../../config/db.php"]
PATHS_SHELL= ["/upload.php", "/admin/upload", "/api/upload", "/filemanager/upload"]

OUT = Path("/data/data/com.termux/files/home/soc-lab/logs")
OUT.mkdir(parents=True, exist_ok=True)


def gen_apache(n=2000):
    lines = []
    for _ in range(n):
        ip = random.choices(IPS + ATTACKERS * 3,
                            weights=[1] * len(IPS) + [5] * len(ATTACKERS) * 3)[0]
        ts = BASE + timedelta(seconds=random.randint(0, 86400))
        time_str = ts.strftime("%d/%b/%Y:%H:%M:%S %z")
        if ip in ATTACKERS:
            r = random.random()
            path_set = (PATHS_SQLI if r < 0.3 else PATHS_XSS if r < 0.5
                        else PATHS_TRAV if r < 0.7 else PATHS_SHELL)
            method = random.choice(["GET", "POST", "GET"])
            status = random.choice([200, 403, 404, 500, 301])
        else:
            method = random.choice(["GET", "POST", "HEAD"])
            path = random.choice(PATHS_NORM)
            status = random.choice([200, 200, 200, 301, 304, 404])
            path_set = [path]
        path = random.choice(path_set)
        size = random.randint(100, 50000) if status == 200 else random.randint(0, 500)
        lines.append(
            f'{ip} - - [{time_str}] "{method} {path} HTTP/1.1" {status} {size}'
        )
    (OUT / "apache_access.log").write_text("\n".join(lines) + "\n")
    print(f"[+] apache_access.log: {len(lines)} lines")


def gen_auth(n=2000):
    lines = []
    users = ["root", "admin", "ubuntu", "oracle", "postgres", "www-data"]
    # Benign sshd messages
    benign = [
        "Accepted publickey for ubuntu from 10.0.0.5 port 52311 ssh2",
        "session opened for user ubuntu by (uid=0)",
        "session closed for user ubuntu",
        "pam_unix(sshd:session): session opened for user root by (uid=0)",
        "Received disconnect from 10.0.0.5: 11: disconnected by user",
        "Connection closed by authenticating user ubuntu 10.0.0.5 port 52310",
    ]
    for _ in range(n):
        if random.random() < 0.2:
            # attacker IP, failed logins
            ip = random.choice(ATTACKERS)
            user = random.choice(users)
            line = (f"Failed password for {user} from {ip} "
                    f"port {random.randint(40000, 65000)} ssh2")
        elif random.random() < 0.05:
            # successful brute-force login
            ip = random.choice(ATTACKERS)
            user = random.choice(users)
            line = (f"Accepted password for {user} from {ip} "
                    f"port {random.randint(40000, 65000)} ssh2")
        else:
            line = random.choice(benign)
        lines.append(line)
    (OUT / "linux_auth.log").write_text("\n".join(lines) + "\n")
    print(f"[+] linux_auth.log: {len(lines)} lines")


if __name__ == "__main__":
    gen_apache()
    gen_auth()
    print("Done. Logs written to:", OUT)
