# Security Log Analyzer

A Python 3.11+ CLI tool that reads Apache / Nginx access logs, detects suspicious behaviour patterns, prints incident-response-style alerts, and optionally exports a CSV report or a matplotlib plot.

## Features

| Detection Rule | Description |
|---|---|
| **Brute-force login** | ≥ 5 failed login attempts (401/403 on `/login`) within 60 s from the same IP |
| **Rate-limit burst** | > 10 requests/second sustained for ≥ 3 consecutive seconds |
| **Excessive 404s** | ≥ 20 HTTP-404 responses within 5 minutes from the same IP |
| **Sensitive endpoint** | Any request to `/admin`, `/wp-admin`, `/.env`, or `/phpmyadmin` |

All thresholds are configurable constants at the top of `main.py`.

## Requirements

- **Python 3.11+** (standard library only)
- **matplotlib** *(optional)* — only needed for the `--plot` flag

```bash
pip install matplotlib   # optional
```

## Quick Start

```bash
# Basic analysis
python main.py --log access.log

# With CSV report
python main.py --log access.log --csv report.csv

# With JSON report
python main.py --log access.log --json report.json

# With visualization
python main.py --log access.log --plot out.png

# With allowlist / blocklist
python main.py --log access.log --allowlist allow.txt --blocklist block.txt

# Filter by time range and show top 5 IPs
python main.py --log access.log --since 2026-02-12T14:00:00 --until 2026-02-12T15:00:00 --top 5

# All options combined
python main.py --log access.log --csv report.csv --json report.json --plot out.png --top 5 --since 2026-02-12T14:30:00
```

## CLI Flags

| Flag | Required | Description |
|---|---|---|
| `--log PATH` | ✅ | Path to the access log file |
| `--csv PATH` | ❌ | Write a CSV incident report |
| `--json PATH` | ❌ | Write a JSON incident report |
| `--plot PATH` | ❌ | Save a matplotlib time-series chart to a file (PNG recommended) |
| `--top N` | ❌ | Number of top IPs in summary (default: 10) |
| `--allowlist PATH` | ❌ | Suppress detection + summaries for allowlisted IPs (one IP per line) |
| `--blocklist PATH` | ❌ | Always alert on blocklisted IPs (one IP per line) |
| `--since ISO` | ❌ | Analyse only entries ≥ this datetime |
| `--until ISO` | ❌ | Analyse only entries ≤ this datetime |

### Allowlist / Blocklist semantics

- **Allowlist wins**: if an IP appears in both allowlist and blocklist, it is **suppressed** (no incidents, no summary counts), and the tool prints a warning.
- **Allowlisted traffic** still counts toward **Total parsed lines**, but is excluded from detection, incident generation, and per-IP summary counts. The summary includes `Suppressed (allow)`.
- **Blocklisted traffic** always produces/maintains an incident with rule `blocklisted_ip`, and every request from that IP increments that incident’s `count`.

## Log Format

The parser expects **common** or **combined** log format:

```
192.168.1.10 - - [12/Feb/2026:14:32:21] "POST /login HTTP/1.1" 401
10.0.0.5 - user [12/Feb/2026:14:35:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
```

Lines that do not match are silently skipped and counted in the summary.

## Example Output

```
  [*] Reading log: C:\logs\access.log

  ========================================================================
    SECURITY INCIDENTS DETECTED
  ========================================================================

  ⚠  Suspicious activity detected
  ──────────────────────────────────────────────────────
  IP:         192.168.1.10
  Rule:       brute_force
  First seen: 2026-02-12 14:32:21
  Last seen:  2026-02-12 14:33:06
  Count:      7
  Reason:     7 failed login attempts in 45s (/login, 401/403)
  Endpoints:  /login
  Statuses:   401

  ========================================================================
    ANALYSIS SUMMARY
  ========================================================================
  Total parsed lines :      314
  Skipped (bad fmt)  :        2
  Unique IPs         :       18
  Suppressed (allow) :        6

  Incidents by rule:
    brute_force         : 1
    sensitive_path      : 3

  Top 5 IPs by request volume:
    192.168.1.10        :       87 requests
    10.0.0.5            :       53 requests
    ...

  Top Suspicious IPs:
    #1  192.168.1.10     score=9   incidents(brute_force=1, sensitive_path=1) first=2026-02-12 14:32:21 last=2026-02-12 14:45:01
    #2  203.0.113.7      score=10  incidents(blocklisted_ip=1)               first=2026-02-12 14:10:00 last=2026-02-12 14:59:59
```

## Suspicion scoring

The analyzer calculates a **suspicion score per IP** by summing score contributions for each triggered incident (one incident per IP + rule). Defaults (configurable at the top of `main.py`):

- brute-force login (`brute_force`): +5
- rate limit (`rate_limit`): +3
- excessive 404s (`excessive_404`): +2
- admin probing (`sensitive_path`): +4
- blocklisted IP (`blocklisted_ip`): +10

The **Top Suspicious IPs** section ranks by score (desc), then most recent `last_seen`.

## CSV Report Columns

| Column | Description |
|---|---|
| `incident_id` | Sequential ID |
| `ip` | Source IP address |
| `rule` | Detection rule that triggered |
| `first_seen` | ISO timestamp of first matching event |
| `last_seen` | ISO timestamp of last matching event |
| `count` | Total events in this incident |
| `sample_endpoints` | Up to 5 unique endpoint paths |
| `sample_status_codes` | Up to 5 unique HTTP status codes |

## JSON Report

The JSON report is a JSON array of incident objects with deterministic ordering (sorted by `score_contribution` desc, then `last_seen` desc).

Example entry:

```json
{
  "incident_id": 1,
  "ip": "192.168.1.10",
  "rule": "brute_force",
  "first_seen": "2026-02-12T14:32:21",
  "last_seen": "2026-02-12T14:33:06",
  "count": 7,
  "score_contribution": 5,
  "sample_endpoints": ["/login"],
  "sample_status_codes": [401]
}
```

## Project Structure

```
security_log_analyzer/
├── main.py           # All-in-one analyser
├── README.md         # This file
└── sample_access.log # Test data (included)
```

## License

MIT
