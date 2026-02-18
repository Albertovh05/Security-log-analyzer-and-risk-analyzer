#!/usr/bin/env python3
"""
security_log_analyzer — CLI tool for Apache/Nginx access-log threat detection.

Reads common/combined-format access logs, applies configurable detection rules,
prints incident-response-style alerts, and optionally exports a CSV report or
a matplotlib time-series plot.

Author:  Security Engineering Team
Python:  3.11+
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, TextIO

# ──────────────────────────────────────────────────────────────────────────────
# Configurable detection constants
# ──────────────────────────────────────────────────────────────────────────────

# Rule 1 – Failed-login brute force
BRUTE_FORCE_THRESHOLD: int = 5          # minimum failed attempts
BRUTE_FORCE_WINDOW_SEC: int = 60        # sliding window in seconds
FAILED_LOGIN_STATUSES: set[int] = {401, 403}

# Rule 2 – Rate limit (too many requests per second)
RATE_LIMIT_RPS: int = 10               # requests-per-second ceiling
RATE_LIMIT_SUSTAINED_SEC: int = 3      # consecutive seconds above ceiling

# Rule 3 – Excessive 404s
EXCESSIVE_404_THRESHOLD: int = 20
EXCESSIVE_404_WINDOW_SEC: int = 300     # 5 minutes

# Rule 4 – Sensitive / admin endpoint access
SENSITIVE_PATHS: tuple[str, ...] = (
    "/admin",
    "/wp-admin",
    "/.env",
    "/phpmyadmin",
)

# ──────────────────────────────────────────────────────────────────────────────
# Suspicion scoring (configurable)
#
# Score is aggregated per IP based on triggered incidents (one per IP + rule).
# ──────────────────────────────────────────────────────────────────────────────

SCORE_BRUTE_FORCE_LOGIN: int = 5
SCORE_RATE_LIMIT: int = 3
SCORE_EXCESSIVE_404: int = 2
SCORE_ADMIN_PROBE: int = 4
SCORE_BLOCKLISTED_IP: int = 10

# Map internal rule keys to score contributions.
# Note: existing rule keys are preserved for backwards compatibility.
_RULE_SCORE: dict[str, int] = {
    "brute_force": SCORE_BRUTE_FORCE_LOGIN,
    "rate_limit": SCORE_RATE_LIMIT,
    "excessive_404": SCORE_EXCESSIVE_404,
    "sensitive_path": SCORE_ADMIN_PROBE,
    "blocklisted_ip": SCORE_BLOCKLISTED_IP,
}

# ──────────────────────────────────────────────────────────────────────────────
# Log line regex — handles common & combined formats
# ──────────────────────────────────────────────────────────────────────────────

_LOG_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'     # IPv4
    r'\s+\S+\s+\S+'                          # ident + authuser
    r'\s+\[(?P<ts>[^\]]+)\]'                 # [timestamp]
    r'\s+"(?P<method>[A-Z]+)'                # "METHOD
    r'\s+(?P<path>\S+)'                      #  /path
    r'\s+\S+"'                               #  HTTP/x.x"
    r'\s+(?P<status>\d{3})'                  # status code
)

# Timestamp format found in most Apache / Nginx logs
_TS_FMT = "%d/%b/%Y:%H:%M:%S"

# ──────────────────────────────────────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class LogEntry:
    """Single parsed access-log line."""

    ip: str
    timestamp: datetime
    method: str
    path: str
    status_code: int


@dataclass
class Incident:
    """Aggregated security incident tied to one IP + one detection rule."""

    ip: str
    reason: str
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    sample_endpoints: list[str] = field(default_factory=list)
    sample_status_codes: list[int] = field(default_factory=list)

    # ── helpers ──

    def merge_entry(self, entry: LogEntry) -> None:
        """Fold another log entry into this incident."""
        self.count += 1
        if entry.timestamp < self.first_seen:
            self.first_seen = entry.timestamp
        if entry.timestamp > self.last_seen:
            self.last_seen = entry.timestamp
        if len(self.sample_endpoints) < 5 and entry.path not in self.sample_endpoints:
            self.sample_endpoints.append(entry.path)
        if len(self.sample_status_codes) < 5 and entry.status_code not in self.sample_status_codes:
            self.sample_status_codes.append(entry.status_code)

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()


@dataclass(slots=True)
class SuspiciousIP:
    """Aggregated per-IP scoring view derived from incidents."""

    ip: str
    score: int
    rule_incident_counts: dict[str, int]
    first_seen: datetime
    last_seen: datetime


# ──────────────────────────────────────────────────────────────────────────────
# Parsing
# ──────────────────────────────────────────────────────────────────────────────


def parse_line(line: str) -> LogEntry | None:
    """Try to parse a single log line; return *None* on failure."""
    m = _LOG_RE.search(line)
    if m is None:
        return None
    ts_raw = m.group("ts")
    # Strip optional timezone offset (e.g. " +0000") so we can parse cleanly
    ts_clean = ts_raw.split()[0]
    try:
        ts = datetime.strptime(ts_clean, _TS_FMT)
    except ValueError:
        return None
    return LogEntry(
        ip=m.group("ip"),
        timestamp=ts,
        method=m.group("method").upper(),
        path=m.group("path"),
        status_code=int(m.group("status")),
    )


def stream_entries(
    fh: TextIO,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Iterable[LogEntry | None]:
    """Yield *LogEntry* for every line (or *None* for unparseable lines)."""
    for raw_line in fh:
        stripped = raw_line.strip()
        # Allow test files / annotated logs with comments without inflating
        # the "skipped" counter.
        if not stripped or stripped.startswith("#"):
            continue
        entry = parse_line(raw_line)
        if entry is None:
            yield None
            continue
        if since and entry.timestamp < since:
            continue
        if until and entry.timestamp > until:
            continue
        yield entry


# ──────────────────────────────────────────────────────────────────────────────
# Detection engine
# ──────────────────────────────────────────────────────────────────────────────


class DetectionEngine:
    """Stateful engine that ingests *LogEntry* objects and produces *Incident*s."""

    def __init__(self) -> None:
        # Per-IP event buffers keyed by rule need
        self._login_attempts: dict[str, list[LogEntry]] = defaultdict(list)
        self._404_events: dict[str, list[LogEntry]] = defaultdict(list)

        # Deduplicated incident store: key = (ip, rule)
        self.incidents: dict[tuple[str, str], Incident] = {}

    # ── public API ──

    def ingest(self, entry: LogEntry) -> None:
        """Run all detection rules against a single entry."""
        self._check_sensitive_path(entry)
        self._check_failed_login(entry)
        self._check_excessive_404(entry)

    def record_blocklisted_event(self, entry: LogEntry) -> None:
        """Always-on incident for traffic originating from a blocklisted IP."""
        reason = "IP present in blocklist"
        self._record_incident(entry, "blocklisted_ip", reason)

    # ── rule implementations ──

    def _record_incident(self, entry: LogEntry, rule: str, reason: str) -> None:
        """Create or merge an incident for *(ip, rule)*."""
        key = (entry.ip, rule)
        if key in self.incidents:
            self.incidents[key].merge_entry(entry)
            # Keep the most recent reason text for readability.
            self.incidents[key].reason = reason
        else:
            self.incidents[key] = Incident(
                ip=entry.ip,
                reason=reason,
                first_seen=entry.timestamp,
                last_seen=entry.timestamp,
                count=1,
                sample_endpoints=[entry.path],
                sample_status_codes=[entry.status_code],
            )

    def _create_threshold_incident(
        self,
        ip: str,
        rule: str,
        entries: list[LogEntry],
        reason: str,
    ) -> None:
        """Create an incident seeded with a whole threshold window."""
        if not entries:
            return
        key = (ip, rule)
        if key in self.incidents:
            # Already exists; caller should merge current entry instead.
            return
        sample_endpoints: list[str] = []
        sample_statuses: list[int] = []
        for e in entries:
            if len(sample_endpoints) < 5 and e.path not in sample_endpoints:
                sample_endpoints.append(e.path)
            if len(sample_statuses) < 5 and e.status_code not in sample_statuses:
                sample_statuses.append(e.status_code)
        self.incidents[key] = Incident(
            ip=ip,
            reason=reason,
            first_seen=entries[0].timestamp,
            last_seen=entries[-1].timestamp,
            count=len(entries),
            sample_endpoints=sample_endpoints,
            sample_status_codes=sample_statuses,
        )

    # Rule 1 — brute-force login ──────────────────────────────────────────

    def _check_failed_login(self, entry: LogEntry) -> None:
        if "/login" not in entry.path.lower():
            return
        if entry.status_code not in FAILED_LOGIN_STATUSES:
            return

        buf = self._login_attempts[entry.ip]
        buf.append(entry)

        # Trim events outside the sliding window
        cutoff = entry.timestamp - timedelta(seconds=BRUTE_FORCE_WINDOW_SEC)
        buf[:] = [e for e in buf if e.timestamp >= cutoff]

        if len(buf) >= BRUTE_FORCE_THRESHOLD:
            window = (buf[-1].timestamp - buf[0].timestamp).total_seconds()
            reason = (
                f"{len(buf)} failed login attempts in {int(window)}s "
                f"(/login, {'/'.join(str(s) for s in sorted(FAILED_LOGIN_STATUSES))})"
            )
            key = (entry.ip, "brute_force")
            if key not in self.incidents:
                self._create_threshold_incident(entry.ip, "brute_force", buf, reason)
            else:
                # After initial trigger, count every additional matching attempt.
                self._record_incident(entry, "brute_force", reason)

    # Rule 3 — excessive 404s ─────────────────────────────────────────────

    def _check_excessive_404(self, entry: LogEntry) -> None:
        if entry.status_code != 404:
            return

        buf = self._404_events[entry.ip]
        buf.append(entry)

        cutoff = entry.timestamp - timedelta(seconds=EXCESSIVE_404_WINDOW_SEC)
        buf[:] = [e for e in buf if e.timestamp >= cutoff]

        if len(buf) >= EXCESSIVE_404_THRESHOLD:
            reason = (
                f"{len(buf)} HTTP-404 responses in "
                f"{EXCESSIVE_404_WINDOW_SEC // 60} minutes"
            )
            key = (entry.ip, "excessive_404")
            if key not in self.incidents:
                self._create_threshold_incident(entry.ip, "excessive_404", buf, reason)
            else:
                self._record_incident(entry, "excessive_404", reason)

    # Rule 4 — sensitive / admin endpoint ──────────────────────────────────

    def _check_sensitive_path(self, entry: LogEntry) -> None:
        path_lower = entry.path.lower()
        for pattern in SENSITIVE_PATHS:
            if pattern in path_lower:
                reason = "Sensitive endpoint accessed (see sampled endpoints)"
                self._record_incident(entry, "sensitive_path", reason)
                return


def detect_rate_limit(entries: list[LogEntry]) -> dict[tuple[str, str], Incident]:
    """Detect rate-limit incidents using per-IP, per-second buckets.

    Rule: Trigger if an IP exceeds RATE_LIMIT_RPS requests/second sustained for at
    least RATE_LIMIT_SUSTAINED_SEC consecutive seconds.

    Returns incidents keyed by (ip, 'rate_limit').
    """

    # ip -> sec -> (count, first_ts, last_ts, sample_endpoints, sample_statuses)
    buckets: dict[str, dict[int, tuple[int, datetime, datetime, list[str], list[int]]]] = defaultdict(dict)

    for e in entries:
        sec = int(e.timestamp.timestamp())
        existing = buckets[e.ip].get(sec)
        if existing is None:
            buckets[e.ip][sec] = (1, e.timestamp, e.timestamp, [e.path], [e.status_code])
        else:
            count, first_ts, last_ts, sample_paths, sample_statuses = existing
            count += 1
            if e.timestamp < first_ts:
                first_ts = e.timestamp
            if e.timestamp > last_ts:
                last_ts = e.timestamp
            if len(sample_paths) < 5 and e.path not in sample_paths:
                sample_paths.append(e.path)
            if len(sample_statuses) < 5 and e.status_code not in sample_statuses:
                sample_statuses.append(e.status_code)
            buckets[e.ip][sec] = (count, first_ts, last_ts, sample_paths, sample_statuses)

    incidents: dict[tuple[str, str], Incident] = {}

    for ip, sec_map in buckets.items():
        if not sec_map:
            continue
        secs_sorted = sorted(sec_map)

        # Identify runs of consecutive seconds where count > RATE_LIMIT_RPS
        runs: list[list[int]] = []
        current: list[int] = []
        for s in secs_sorted:
            count = sec_map[s][0]
            if count > RATE_LIMIT_RPS:
                if current and s != current[-1] + 1:
                    runs.append(current)
                    current = []
                current.append(s)
            else:
                if current:
                    runs.append(current)
                    current = []
        if current:
            runs.append(current)

        qualifying = [r for r in runs if len(r) >= RATE_LIMIT_SUSTAINED_SEC]
        if not qualifying:
            continue

        # Aggregate all qualifying runs into one incident per IP (dedup requirement).
        offending_secs = [s for r in qualifying for s in r]
        first_seen = min(sec_map[s][1] for s in offending_secs)
        last_seen = max(sec_map[s][2] for s in offending_secs)
        total_reqs = sum(sec_map[s][0] for s in offending_secs)
        max_run = max(len(r) for r in qualifying)

        sample_endpoints: list[str] = []
        sample_statuses: list[int] = []
        for s in offending_secs:
            _count, _first_ts, _last_ts, paths, statuses = sec_map[s]
            for p in paths:
                if len(sample_endpoints) < 5 and p not in sample_endpoints:
                    sample_endpoints.append(p)
            for st in statuses:
                if len(sample_statuses) < 5 and st not in sample_statuses:
                    sample_statuses.append(st)

        reason = (
            f">{RATE_LIMIT_RPS} req/s sustained for {max_run}s "
            f"(offending seconds: {len(offending_secs)}, total reqs: {total_reqs})"
        )
        incidents[(ip, "rate_limit")] = Incident(
            ip=ip,
            reason=reason,
            first_seen=first_seen,
            last_seen=last_seen,
            count=total_reqs,
            sample_endpoints=sample_endpoints,
            sample_status_codes=sample_statuses,
        )

    return incidents


# ──────────────────────────────────────────────────────────────────────────────
# Alert / console output
# ──────────────────────────────────────────────────────────────────────────────


_RULE_ICONS: dict[str, str] = {
    "brute_force": "\u26a0",      # ⚠
    "rate_limit": "\U0001f6a8",   # 🚨
    "excessive_404": "\U0001f50d", # 🔍
    "sensitive_path": "\U0001f6ab", # 🚫
    "blocklisted_ip": "\u26d4",  # ⛔
}


def _score_for_rule(rule_key: str) -> int:
    """Return configured score contribution for a rule key."""
    return _RULE_SCORE.get(rule_key, 0)


def print_alerts(incidents: dict[tuple[str, str], Incident]) -> None:
    """Print each incident in incident-response style."""
    if not incidents:
        print("\n  [OK] No suspicious activity detected.\n")
        return

    print("\n" + "=" * 72)
    print("  SECURITY INCIDENTS DETECTED")
    print("=" * 72)

    for (_ip, rule_key), inc in sorted(
        incidents.items(), key=lambda kv: kv[1].first_seen
    ):
        icon = _RULE_ICONS.get(rule_key, "\u26a0")
        print(f"\n  {icon}  Suspicious activity detected")
        print(f"  {'─' * 50}")
        print(f"  IP:         {inc.ip}")
        print(f"  Rule:       {rule_key}")
        print(f"  First seen: {inc.first_seen:%Y-%m-%d %H:%M:%S}")
        print(f"  Last seen:  {inc.last_seen:%Y-%m-%d %H:%M:%S}")
        print(f"  Count:      {inc.count}")
        print(f"  Reason:     {inc.reason}")
        if inc.sample_endpoints:
            print(f"  Endpoints:  {', '.join(inc.sample_endpoints[:5])}")
        if inc.sample_status_codes:
            print(
                f"  Statuses:   {', '.join(str(s) for s in inc.sample_status_codes[:5])}"
            )


def print_summary(
    total: int,
    skipped: int,
    unique_ips: int,
    suppressed_by_allowlist: int,
    incidents: dict[tuple[str, str], Incident],
    top_n: int,
    ip_counts: dict[str, int],
) -> None:
    """Print the final analysis summary."""
    print("\n" + "=" * 72)
    print("  ANALYSIS SUMMARY")
    print("=" * 72)
    print(f"  Total parsed lines : {total:>8,}")
    print(f"  Skipped (bad fmt)  : {skipped:>8,}")
    print(f"  Unique IPs         : {unique_ips:>8,}")
    print(f"  Suppressed (allow) : {suppressed_by_allowlist:>8,}")
    print()

    # Incidents by rule
    rule_counts: dict[str, int] = defaultdict(int)
    for (_ip, rule_key), inc in incidents.items():
        rule_counts[rule_key] += 1

    if rule_counts:
        print("  Incidents by rule:")
        for rule, cnt in sorted(rule_counts.items(), key=lambda x: -x[1]):
            print(f"    {rule:<20s}: {cnt}")
    else:
        print("  Incidents by rule  : (none)")

    # Top IPs by volume
    print(f"\n  Top {top_n} IPs by request volume:")
    for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1])[:top_n]:
        print(f"    {ip:<20s}: {cnt:>8,} requests")

    if skipped:
        print(
            f"\n  [!] Warning: {skipped:,} line(s) could not be parsed "
            f"and were skipped."
        )

    print()


def aggregate_suspicious_ips(
    incidents: dict[tuple[str, str], Incident]
) -> list[SuspiciousIP]:
    """Aggregate incidents into per-IP suspicion scores."""

    by_ip: dict[str, list[tuple[str, Incident]]] = defaultdict(list)
    for (_ip, rule_key), inc in incidents.items():
        by_ip[inc.ip].append((rule_key, inc))

    results: list[SuspiciousIP] = []
    for ip, items in by_ip.items():
        score = sum(_score_for_rule(rule_key) for rule_key, _inc in items)
        rule_counts: dict[str, int] = defaultdict(int)
        first_seen = min(inc.first_seen for _rule, inc in items)
        last_seen = max(inc.last_seen for _rule, inc in items)
        for rule_key, _inc in items:
            rule_counts[rule_key] += 1
        results.append(
            SuspiciousIP(
                ip=ip,
                score=score,
                rule_incident_counts=dict(rule_counts),
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )

    results.sort(key=lambda s: (-s.score, -s.last_seen.timestamp(), s.ip))
    return results


def print_top_suspicious_ips(
    incidents: dict[tuple[str, str], Incident],
    top_n: int,
) -> None:
    """Print a ranked Top Suspicious IPs section."""
    ranked = aggregate_suspicious_ips(incidents)
    if not ranked:
        print("  Top Suspicious IPs : (none)")
        return

    print("\n  Top Suspicious IPs:")
    for idx, item in enumerate(ranked[:top_n], start=1):
        counts = ", ".join(
            f"{rule}={cnt}" for rule, cnt in sorted(item.rule_incident_counts.items())
        )
        print(
            f"    #{idx:<2d} {item.ip:<15s} score={item.score:<3d} "
            f"incidents({counts}) "
            f"first={item.first_seen:%Y-%m-%d %H:%M:%S} "
            f"last={item.last_seen:%Y-%m-%d %H:%M:%S}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# CSV export
# ──────────────────────────────────────────────────────────────────────────────


def export_csv(
    incidents: dict[tuple[str, str], Incident], csv_path: str
) -> None:
    """Write incidents to a CSV incident report."""
    fieldnames = [
        "incident_id",
        "ip",
        "rule",
        "first_seen",
        "last_seen",
        "count",
        "sample_endpoints",
        "sample_status_codes",
    ]

    path = Path(csv_path)
    try:
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for idx, ((_ip, rule_key), inc) in enumerate(
                sorted(incidents.items(), key=lambda kv: kv[1].first_seen), start=1
            ):
                writer.writerow(
                    {
                        "incident_id": idx,
                        "ip": inc.ip,
                        "rule": rule_key,
                        "first_seen": inc.first_seen.isoformat(),
                        "last_seen": inc.last_seen.isoformat(),
                        "count": inc.count,
                        "sample_endpoints": "; ".join(inc.sample_endpoints[:5]),
                        "sample_status_codes": "; ".join(
                            str(s) for s in inc.sample_status_codes[:5]
                        ),
                    }
                )
        print(f"  [+] CSV report written to: {path.resolve()}")
    except OSError as exc:
        print(f"  [!] Failed to write CSV: {exc}", file=sys.stderr)


def export_json(
    incidents: dict[tuple[str, str], Incident], json_path: str
) -> None:
    """Write incidents to a JSON report with deterministic ordering."""

    def _incident_sort_key(item: tuple[tuple[str, str], Incident]) -> tuple[int, float, str, str]:
        (ip, rule_key), inc = item
        score = _score_for_rule(rule_key)
        return (-score, -inc.last_seen.timestamp(), ip, rule_key)

    path = Path(json_path)
    payload: list[dict[str, object]] = []
    for idx, ((ip, rule_key), inc) in enumerate(
        sorted(incidents.items(), key=_incident_sort_key), start=1
    ):
        payload.append(
            {
                "incident_id": idx,
                "ip": inc.ip,
                "rule": rule_key,
                "first_seen": inc.first_seen.isoformat(timespec="seconds"),
                "last_seen": inc.last_seen.isoformat(timespec="seconds"),
                "count": inc.count,
                "score_contribution": _score_for_rule(rule_key),
                "sample_endpoints": inc.sample_endpoints[:5],
                "sample_status_codes": inc.sample_status_codes[:5],
            }
        )

    try:
        with path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"  [+] JSON report written to: {path.resolve()}")
    except OSError as exc:
        print(f"  [!] Failed to write JSON: {exc}", file=sys.stderr)


# ──────────────────────────────────────────────────────────────────────────────
# Visualization (matplotlib, optional)
# ──────────────────────────────────────────────────────────────────────────────


def plot_top_ips(entries: list[LogEntry], plot_path: str, top_n: int = 5) -> None:
    """Save a time-series of requests per minute for the top *top_n* IPs."""
    try:
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
    except ImportError:
        print(
            "\n  [i] matplotlib is not installed. "
            "Run `pip install matplotlib` to enable plotting.\n"
        )
        return

    if not entries:
        print("  [i] No entries to plot.")
        return

    # Determine top IPs by total volume
    ip_totals: dict[str, int] = defaultdict(int)
    for e in entries:
        ip_totals[e.ip] += 1
    top_ips = [ip for ip, _ in sorted(ip_totals.items(), key=lambda x: -x[1])[:top_n]]

    # Bucket by minute
    ip_minutes: dict[str, dict[datetime, int]] = {ip: defaultdict(int) for ip in top_ips}
    for e in entries:
        if e.ip in ip_minutes:
            minute = e.timestamp.replace(second=0, microsecond=0)
            ip_minutes[e.ip][minute] += 1

    fig, ax = plt.subplots(figsize=(14, 6))
    for ip in top_ips:
        buckets = ip_minutes[ip]
        if not buckets:
            continue
        times = sorted(buckets)
        counts = [buckets[t] for t in times]
        ax.plot(times, counts, marker=".", linewidth=1.2, label=ip)

    ax.set_title("Request Frequency per Minute — Top IPs", fontsize=14)
    ax.set_xlabel("Time")
    ax.set_ylabel("Requests / minute")
    ax.legend(fontsize=9, loc="upper right")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.grid(True, alpha=0.3)
    fig.autofmt_xdate()
    plt.tight_layout()
    out_path = Path(plot_path)
    try:
        fig.savefig(out_path)
        print(f"  [+] Saved plot to: {out_path.resolve()}")
    except OSError as exc:
        print(f"  [!] Failed to save plot: {exc}", file=sys.stderr)
    finally:
        plt.close(fig)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="security_log_analyzer",
        description=(
            "Analyse Apache / Nginx access logs for suspicious behaviour.\n\n"
            "Example:\n"
            "  python main.py --log access.log --csv report.csv --json report.json --plot out.png --top 5\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Detection rules (configurable at the top of main.py):\n"
            "  1. Brute-force login  — ≥5 failed logins in 60 s\n"
            "  2. Rate-limit burst   — >10 req/s sustained 3+ s\n"
            "  3. Excessive 404s     — ≥20 404s in 5 min\n"
            "  4. Sensitive endpoint — /admin, /wp-admin, /.env, /phpmyadmin\n"
            "  5. Blocklisted IP     — always alert + score when seen\n"
        ),
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Path to an Apache / Nginx access log file.",
    )
    parser.add_argument(
        "--csv",
        default=None,
        metavar="PATH",
        help="Write a CSV incident report to PATH.",
    )
    parser.add_argument(
        "--json",
        default=None,
        metavar="PATH",
        help="Write a JSON incident report to PATH.",
    )
    parser.add_argument(
        "--plot",
        default=None,
        metavar="PATH",
        help="Save a matplotlib time-series plot to PATH (PNG recommended).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Number of top IPs to show in summary (default: 10).",
    )
    parser.add_argument(
        "--allowlist",
        default=None,
        metavar="PATH",
        help="Path to a file containing allowlisted IPs (one per line).",
    )
    parser.add_argument(
        "--blocklist",
        default=None,
        metavar="PATH",
        help="Path to a file containing blocklisted IPs (one per line).",
    )
    parser.add_argument(
        "--since",
        default=None,
        metavar="ISO",
        help="Only analyse entries at or after this ISO datetime (e.g. 2026-02-12T14:30:00).",
    )
    parser.add_argument(
        "--until",
        default=None,
        metavar="ISO",
        help="Only analyse entries at or before this ISO datetime.",
    )
    return parser


def _parse_iso_or_die(value: str | None, label: str) -> datetime | None:
    """Parse an ISO datetime string or exit with an error."""
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        print(
            f"  [!] Invalid --{label} value: '{value}'. "
            f"Expected ISO format like 2026-02-12T14:30:00.",
            file=sys.stderr,
        )
        sys.exit(1)


def load_ip_set(path: str | None, label: str) -> set[str]:
    """Load a set of IPs from a file (one per line, supports # comments)."""
    if path is None:
        return set()

    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        print(f"  [!] Failed to read {label}: {exc}", file=sys.stderr)
        sys.exit(1)

    ips: set[str] = set()
    for line in raw:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Allow inline comments: "1.2.3.4  # office"
        candidate = stripped.split("#", 1)[0].strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            print(
                f"  [!] Invalid IP in {label} ({p}): '{candidate}'",
                file=sys.stderr,
            )
            sys.exit(1)
        ips.add(candidate)

    return ips


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────


def main() -> None:
    """Entry point: parse CLI args, stream the log, detect, report."""
    parser = build_parser()
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.is_file():
        print(f"  [!] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    since = _parse_iso_or_die(args.since, "since")
    until = _parse_iso_or_die(args.until, "until")

    allowlist = load_ip_set(args.allowlist, "allowlist")
    blocklist = load_ip_set(args.blocklist, "blocklist")
    overlap = allowlist & blocklist
    if overlap:
        shown = ", ".join(sorted(overlap)[:5])
        more = "" if len(overlap) <= 5 else f" (+{len(overlap) - 5} more)"
        print(
            f"  [!] Warning: {len(overlap)} IP(s) appear in both allowlist and blocklist; "
            f"allowlist wins: {shown}{more}",
            file=sys.stderr,
        )

    # ── stream & analyse ──
    engine = DetectionEngine()
    entries: list[LogEntry] = []
    ip_counts: dict[str, int] = defaultdict(int)
    total_parsed = 0
    total_skipped = 0
    suppressed_by_allowlist = 0
    unique_ips: set[str] = set()

    print(f"\n  [*] Reading log: {log_path.resolve()}")

    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            for item in stream_entries(fh, since=since, until=until):
                if item is None:
                    total_skipped += 1
                    continue
                total_parsed += 1

                # Allowlist wins over blocklist and suppresses detection + summaries.
                if item.ip in allowlist:
                    suppressed_by_allowlist += 1
                    continue

                unique_ips.add(item.ip)
                ip_counts[item.ip] += 1
                if item.ip in blocklist:
                    engine.record_blocklisted_event(item)
                engine.ingest(item)
                entries.append(item)
    except OSError as exc:
        print(f"  [!] Error reading log file: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── output ──
    # Post-processing rule (rate limit) needs full entry set for correct counts.
    rate_incidents = detect_rate_limit(entries)
    engine.incidents.update(rate_incidents)

    print_alerts(engine.incidents)
    print_summary(
        total=total_parsed,
        skipped=total_skipped,
        unique_ips=len(unique_ips),
        suppressed_by_allowlist=suppressed_by_allowlist,
        incidents=engine.incidents,
        top_n=args.top,
        ip_counts=ip_counts,
    )

    # Ranked scoring output (respects --top)
    print_top_suspicious_ips(engine.incidents, top_n=args.top)

    if args.csv:
        export_csv(engine.incidents, args.csv)

    if args.json:
        export_json(engine.incidents, args.json)

    if args.plot:
        plot_top_ips(entries, plot_path=args.plot, top_n=5)


if __name__ == "__main__":
    main()
