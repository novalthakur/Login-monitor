#!/usr/bin/env python3
"""
Generate sample log files for testing SOC Login Monitor

Creates:
- logs/sample_auth.log (Linux SSH auth.log format)
- logs/sample_security.csv (Windows Security Event Log CSV export format)
"""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


LINUX_USERS = ["root", "admin", "ubuntu", "debian", "centos", "user", "test", "oracle", "postgres", "mysql", "nginx", "apache"]
WINDOWS_USERS = ["Administrator", "Admin", "Guest", "User", "Test", "Service", "Backup", "SQLAdmin", "IIS_User"]
ATTACKER_IPS = [
    "192.168.1.100", "10.0.0.50", "172.16.0.200", "203.0.113.45",
    "198.51.100.12", "192.0.2.88", "10.10.10.10", "172.17.0.5"
]
LEGIT_IPS = [
    "192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.10",
    "192.168.100.50", "10.1.1.100"
]


def generate_linux_auth_log(output_path: str, num_entries: int = 500):
    base_time = datetime.now() - timedelta(hours=24)
    entries = []

    # Normal successful logins from legit IPs
    for _ in range(int(num_entries * 0.3)):
        ip = random.choice(LEGIT_IPS)
        user = random.choice(LINUX_USERS)
        ts = base_time + timedelta(seconds=random.randint(0, 86400))
        entries.append(
            f"{ts.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
        )

    # Brute force attacks from attacker IPs
    for attacker_ip in ATTACKER_IPS:
        num_attempts = random.randint(3, 60)
        start_ts = base_time + timedelta(seconds=random.randint(0, 80000))

        for i in range(num_attempts):
            user = random.choice(LINUX_USERS)
            ts = start_ts + timedelta(seconds=i * random.randint(1, 30))
            entries.append(
                f"{ts.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {user} from {attacker_ip} port {random.randint(1024,65535)} ssh2"
            )

        # Some attackers eventually succeed
        if num_attempts > 10 and random.random() < 0.3:
            user = random.choice(LINUX_USERS)
            ts = start_ts + timedelta(seconds=num_attempts * random.randint(1, 30))
            entries.append(
                f"{ts.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: "
                f"Accepted password for {user} from {attacker_ip} port {random.randint(1024,65535)} ssh2"
            )

    # Sudo failures
    for _ in range(int(num_entries * 0.05)):
        ip = random.choice(LEGIT_IPS + ATTACKER_IPS)
        user = random.choice(LINUX_USERS)
        ts = base_time + timedelta(seconds=random.randint(0, 86400))
        entries.append(
            f"{ts.strftime('%b %d %H:%M:%S')} server sudo: "
            f"FAILED sudo: user={user} ; COMMAND=/bin/bash"
        )

    entries.sort(key=lambda x: x.split()[0:3])

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write("\n".join(entries))

    print(f"[+] Generated {len(entries)} Linux auth.log entries -> {output_path}")


def generate_windows_csv(output_path: str, num_entries: int = 300):
    base_time = datetime.now() - timedelta(hours=24)
    rows = []

    # Normal successful logons (EventID 4624)
    for _ in range(int(num_entries * 0.4)):
        ip = random.choice(LEGIT_IPS)
        user = random.choice(WINDOWS_USERS)
        ts = base_time + timedelta(seconds=random.randint(0, 86400))
        logon_type = random.choice([2, 3, 10])  # Interactive, Network, RemoteInteractive
        rows.append({
            "TimeCreated": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "EventID": 4624,
            "IpAddress": ip,
            "TargetUserName": user,
            "LogonType": logon_type,
        })

    # Failed logons (EventID 4625) - brute force
    for attacker_ip in ATTACKER_IPS:
        num_attempts = random.randint(3, 50)
        start_ts = base_time + timedelta(seconds=random.randint(0, 80000))

        for i in range(num_attempts):
            user = random.choice(WINDOWS_USERS)
            ts = start_ts + timedelta(seconds=i * random.randint(1, 20))
            logon_type = random.choice([3, 10])  # Network, RemoteInteractive
            rows.append({
                "TimeCreated": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "EventID": 4625,
                "IpAddress": attacker_ip,
                "TargetUserName": user,
                "LogonType": logon_type,
            })

        # Some succeed after failures
        if num_attempts > 10 and random.random() < 0.3:
            user = random.choice(WINDOWS_USERS)
            ts = start_ts + timedelta(seconds=num_attempts * random.randint(1, 20))
            rows.append({
                "TimeCreated": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "EventID": 4624,
                "IpAddress": attacker_ip,
                "TargetUserName": user,
                "LogonType": random.choice([3, 10]),
            })

    rows.sort(key=lambda x: x["TimeCreated"])

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["TimeCreated", "EventID", "IpAddress", "TargetUserName", "LogonType"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Generated {len(rows)} Windows Security CSV entries -> {output_path}")


def main():
    print("[*] Generating sample log files...")
    generate_linux_auth_log("logs/sample_auth.log", 500)
    generate_windows_csv("logs/sample_security.csv", 300)
    print("[+] Done! Sample logs ready in logs/")


if __name__ == "__main__":
    main()