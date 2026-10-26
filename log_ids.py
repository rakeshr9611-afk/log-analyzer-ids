#!/usr/bin/env python3
"""Log analyzer / lightweight intrusion detection system.

Parses Linux SSH auth logs (/var/log/auth.log) and web server access logs
(Apache/Nginx "combined" format) and flags suspicious activity:

  * SSH brute force: many failed logins from one IP in a short window
  * SSH user enumeration: one IP trying many different usernames
  * Successful login after failures (possible compromise)
  * Web attacks: SQL injection, XSS, path traversal, command injection
  * Web scanning: bursts of 404s or known scanner user agents
"""

import argparse
import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

SSH_FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8}).*sshd\[\d+\]: Failed password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
SSH_INVALID = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8}).*sshd\[\d+\]: Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)"
)
SSH_ACCEPTED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8}).*sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)

WEB_ATTACK_SIGNATURES = {
    "SQL injection": re.compile(
        r"(union(\s|%20|\+)+select|'\s*or\s*'?\d|%27(\s|%20|\+)*or|or(\s|%20|\+)+1=1|"
        r"sleep\(\d+\)|information_schema|;--)", re.I),
    "Cross-site scripting": re.compile(r"(<script|%3cscript|javascript:|onerror=|onload=)", re.I),
    "Path traversal": re.compile(r"(\.\./|\.\.%2f|%2e%2e/|/etc/passwd|win\.ini)", re.I),
    "Command injection": re.compile(r"(;|%3b|\||%7c|`)\s*(cat|wget|curl|nc|bash|sh|id|whoami)\b", re.I),
    "Sensitive file probe": re.compile(r"/(\.env|\.git/|wp-config\.php|phpmyadmin|\.aws/)", re.I),
}

SCANNER_AGENTS = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix)", re.I)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Alert:
    severity: str
    category: str
    ip: str
    detail: str
    first_seen: str
    count: int = 1
    samples: list = field(default_factory=list)


def parse_syslog_time(ts, year):
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse_access_time(ts):
    return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)


def detect_log_type(lines):
    for line in lines[:50]:
        if "sshd[" in line:
            return "ssh"
        if ACCESS_LINE.match(line):
            return "web"
    return "unknown"


def sliding_window_peak(times, window):
    """Largest number of events inside any `window`-long time span."""
    best, q = 0, deque()
    for t in sorted(times):
        q.append(t)
        while t - q[0] > window:
            q.popleft()
        best = max(best, len(q))
    return best


def analyze_ssh(lines, cfg):
    failures = defaultdict(list)  # ip -> [(time, user)]
    usernames = defaultdict(set)  # ip -> {user}
    successes = []                # (time, user, ip)

    for line in lines:
        m = SSH_FAILED.match(line)
        if m:
            failures[m["ip"]].append((parse_syslog_time(m["ts"], cfg.year), m["user"]))
            usernames[m["ip"]].add(m["user"])
            continue
        m = SSH_INVALID.match(line)
        if m:
            # "Invalid user" usually precedes a "Failed password" line, so it
            # only counts towards username enumeration, not failed attempts.
            usernames[m["ip"]].add(m["user"])
            continue
        m = SSH_ACCEPTED.match(line)
        if m:
            successes.append((parse_syslog_time(m["ts"], cfg.year), m["user"], m["ip"]))

    alerts = []
    window = timedelta(seconds=cfg.window)
    for ip, events in failures.items():
        times = [t for t, _ in events]
        users = usernames[ip]
        peak = sliding_window_peak(times, window)
        if peak >= cfg.ssh_threshold:
            alerts.append(Alert("HIGH", "SSH brute force", ip,
                                f"{peak} failed logins within {cfg.window}s ({len(events)} total)",
                                min(times).isoformat(), len(events)))
        if len(users) >= cfg.user_enum_threshold:
            alerts.append(Alert("MEDIUM", "SSH user enumeration", ip,
                                f"tried {len(users)} different usernames",
                                min(times).isoformat(), len(users), sorted(users)[:10]))

    for t, user, ip in successes:
        prior = [ft for ft, _ in failures.get(ip, []) if ft <= t]
        if len(prior) >= cfg.ssh_threshold:
            alerts.append(Alert("CRITICAL", "Login after brute force", ip,
                                f"successful login as '{user}' after {len(prior)} failures",
                                t.isoformat(), 1))
    return alerts


def analyze_web(lines, cfg):
    attacks = defaultdict(list)    # (ip, category) -> [path]
    not_found = defaultdict(list)  # ip -> [time]
    scanners = {}                  # ip -> agent
    first_seen = {}

    for line in lines:
        m = ACCESS_LINE.match(line)
        if not m:
            continue
        ip, path = m["ip"], m["path"]
        t = parse_access_time(m["ts"])
        first_seen.setdefault(ip, t)
        for category, pattern in WEB_ATTACK_SIGNATURES.items():
            if pattern.search(path):
                attacks[(ip, category)].append(path)
        if m["status"] == "404":
            not_found[ip].append(t)
        agent = m["agent"] or ""
        if SCANNER_AGENTS.search(agent):
            scanners[ip] = agent

    alerts = []
    for (ip, category), paths in attacks.items():
        severity = "MEDIUM" if category == "Sensitive file probe" else "HIGH"
        alerts.append(Alert(severity, f"Web attack: {category}", ip,
                            f"{len(paths)} malicious request(s)",
                            first_seen[ip].isoformat(), len(paths), paths[:3]))
    window = timedelta(seconds=cfg.window)
    for ip, times in not_found.items():
        peak = sliding_window_peak(times, window)
        if peak >= cfg.notfound_threshold:
            alerts.append(Alert("MEDIUM", "Web directory scan", ip,
                                f"{peak} 404 responses within {cfg.window}s",
                                min(times).isoformat(), len(times)))
    for ip, agent in scanners.items():
        alerts.append(Alert("LOW", "Scanner user agent", ip, agent[:80],
                            first_seen[ip].isoformat()))
    return alerts


def analyze(lines, cfg, log_type=None):
    log_type = log_type or detect_log_type(lines)
    if log_type == "ssh":
        alerts = analyze_ssh(lines, cfg)
    elif log_type == "web":
        alerts = analyze_web(lines, cfg)
    else:
        alerts = []
    alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], -a.count))
    return log_type, alerts


def print_report(path, log_type, alerts):
    print(f"\n=== {path} ({log_type} log) ===")
    if not alerts:
        print("No suspicious activity detected.")
        return
    for a in alerts:
        print(f"[{a.severity:<8}] {a.category:<32} {a.ip:<16} {a.detail}")
        for s in a.samples[:3]:
            print(f"{'':12}e.g. {s}")
    ips = sorted({a.ip for a in alerts if a.severity in ("CRITICAL", "HIGH")})
    if ips:
        print("\nSuggested blocklist (HIGH/CRITICAL):")
        for ip in ips:
            print(f"  {ip}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Detect attacks in SSH and web server logs.")
    p.add_argument("logs", nargs="+", help="log files to analyze")
    p.add_argument("--type", choices=["ssh", "web"], help="force the log type (default: auto-detect)")
    p.add_argument("--window", type=int, default=60, help="detection time window in seconds (default 60)")
    p.add_argument("--ssh-threshold", type=int, default=5, help="failed logins in window to alert (default 5)")
    p.add_argument("--user-enum-threshold", type=int, default=5, help="distinct usernames to alert (default 5)")
    p.add_argument("--notfound-threshold", type=int, default=20, help="404s in window to alert (default 20)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog timestamps")
    p.add_argument("--json", action="store_true", help="print alerts as JSON")
    cfg = p.parse_args(argv)

    report, exit_code = {}, 0
    for path in cfg.logs:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        log_type, alerts = analyze(lines, cfg, cfg.type)
        if any(a.severity in ("CRITICAL", "HIGH") for a in alerts):
            exit_code = 2
        if cfg.json:
            report[path] = {"type": log_type, "alerts": [asdict(a) for a in alerts]}
        else:
            print_report(path, log_type, alerts)
    if cfg.json:
        print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
