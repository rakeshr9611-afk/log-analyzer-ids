# Log Analyzer / Lightweight IDS

A Python tool that reads **SSH auth logs** and **web server access logs**, detects common attacks, and writes a prioritized alert report with a suggested IP blocklist. It needs no third-party packages.

## What it detects

| Log | Detection | Severity |
|-----|-----------|----------|
| SSH | Successful login from an IP right after it brute-forced the server (possible compromise) | CRITICAL |
| SSH | Brute force: N or more failed logins from one IP within a sliding time window | HIGH |
| SSH | User enumeration: one IP trying many different usernames | MEDIUM |
| Web | SQL injection, XSS, path traversal and command injection payloads in URLs (plain or URL-encoded) | HIGH |
| Web | Probes for sensitive files (`.env`, `.git/`, `wp-config.php`, …) | MEDIUM |
| Web | Directory scanning: a burst of 404 responses from one IP | MEDIUM |
| Web | Known scanner user agents (sqlmap, nikto, gobuster, nuclei, …) | LOW |

The log type (SSH `auth.log` or Apache/Nginx combined format) is detected automatically.

## Usage

```bash
python3 log_ids.py samples/auth.log samples/access.log
python3 log_ids.py /var/log/auth.log --ssh-threshold 10 --window 120
python3 log_ids.py /var/log/nginx/access.log --json > alerts.json
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--window` | 60 | Sliding detection window, in seconds |
| `--ssh-threshold` | 5 | Failed logins within the window that trigger a brute-force alert |
| `--user-enum-threshold` | 5 | Distinct usernames from one IP that trigger an enumeration alert |
| `--notfound-threshold` | 20 | 404s within the window that trigger a scan alert |
| `--type ssh\|web` | auto | Force the log type |
| `--year` | current year | Year for syslog timestamps (they don't include one) |
| `--json` | off | Print alerts as JSON for a SIEM or other scripts |

Exit codes: `0` means clean, `2` means at least one HIGH or CRITICAL alert, which is useful in cron jobs and CI.

## Example output (included sample logs)

```
=== samples/auth.log (ssh log) ===
[CRITICAL] Login after brute force          203.0.113.45     successful login as 'root' after 12 failures
[HIGH    ] SSH brute force                  203.0.113.45     12 failed logins within 60s (12 total)
[HIGH    ] SSH brute force                  198.51.100.7     7 failed logins within 60s (7 total)
[MEDIUM  ] SSH user enumeration             198.51.100.7     tried 7 different usernames

=== samples/access.log (web log) ===
[HIGH    ] Web attack: SQL injection        203.0.113.99     2 malicious request(s)
            e.g. /products?id=3%27%20OR%201=1--
[HIGH    ] Web attack: Path traversal       198.51.100.23    1 malicious request(s)
            e.g. /download?file=../../../../etc/passwd
[MEDIUM  ] Web directory scan               192.0.2.77       30 404 responses within 60s
[LOW     ] Scanner user agent               203.0.113.99     sqlmap/1.8.4#stable (https://sqlmap.org)
...
Suggested blocklist (HIGH/CRITICAL):
  198.51.100.23
  203.0.113.99
```

The sample logs in `samples/` are synthetic and use reserved documentation IP ranges.

## How it works

- **Parsing:** regular expressions pull the timestamp, IP, user, path, status and user agent out of each line.
- **Sliding window:** a deque keeps the timestamps inside the window, so a slow attack spread over hours doesn't trigger a brute-force alert, but a burst does.
- **Correlation:** a successful SSH login is compared with earlier failures from the same IP to spot brute-force attacks that worked.
- **Signatures:** web payload rules work like simple IDS signatures, similar in spirit to Snort or ModSecurity rules.

## Running tests

```bash
python3 -m unittest discover -s tests -v
```

## Ideas for extension

- Follow logs live (`tail -f`) and send alerts to Slack or email
- Generate `iptables` / `fail2ban` block rules automatically
- Add GeoIP lookup for attacker IPs

## License

MIT
