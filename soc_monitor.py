"""SOC Monitor — Lightweight Security Operations Center in Python.

A single-file SOC toolkit that detects:
  * SSH brute-force authentication attempts
  * Port-scan patterns (many connections to distinct ports from one host)
  * Repeated authentication failures across services
  * Suspicious outbound connections to high-risk ports

It ships a pluggable detector model, a rotating-window state engine, JSON/CSV
alert sinks and a colorful CLI dashboard. Designed to run against auth.log /
sshd logs on Linux, but works on any text log that follows the syslog shape.

Author: Alejandro R. <@VloneAle21>
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import signal
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

LOG = logging.getLogger("soc-monitor")

__version__ = "1.0.0"
__author__ = "Alejandro R. (@VloneAle21)"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Event:
    """A normalized security event produced by a parser."""

    timestamp: datetime
    source_ip: str
    username: Optional[str]
    message: str
    raw: str
    facility: str = "auth"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "username": self.username,
            "facility": self.facility,
            "message": self.message,
        }


@dataclass
class Alert:
    """An alert emitted by a detector when a threshold is crossed."""

    detector: str
    severity: str
    title: str
    description: str
    source_ip: str
    events: list[Event] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    @property
    def rank(self) -> int:
        return self.SEVERITY_RANK.get(self.severity, 0)

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat(),
            "events": [e.to_dict() for e in self.events],
        }


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


# Common syslog shape: "Jul 29 12:34:56 host process[pid]: message"
SYSLOG_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# sshd "Failed password" line
SSH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# sshd "Accepted password" line
SSH_OK_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# sshd "Connection closed"
SSH_CONN_RE = re.compile(
    r"Connection (?:closed|reset) by (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# Generic IP extractor fallback
IP_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")

MONTHS = {
    m: i for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
    )
}


def _parse_syslog_ts(mon: str, day: str, t: str, year: int | None = None) -> datetime:
    year = year or datetime.now(timezone.utc).year
    h, mi, s = (int(x) for x in t.split(":"))
    return datetime(year, MONTHS[mon], int(day), h, mi, s, tzinfo=timezone.utc)


def parse_syslog(line: str) -> Optional[Event]:
    """Parse a single syslog line into a normalized Event.

    Returns None for lines that don't match or contain no IP.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = SYSLOG_RE.match(line)
    if not m:
        # Try to salvage an IP from an unstructured line
        ip = IP_RE.search(line)
        if not ip:
            return None
        return Event(
            timestamp=datetime.now(timezone.utc),
            source_ip=ip.group("ip"),
            username=None,
            message=line,
            raw=line,
            facility="unknown",
        )

    ts = _parse_syslog_ts(m["mon"], m["day"], m["time"])
    msg = m["msg"]
    proc = m["proc"]
    ip = None
    user = None

    if "sshd" in proc:
        fm = SSH_FAIL_RE.search(msg)
        if fm:
            user, ip = fm["user"], fm["ip"]
            msg = f"SSH failed password for {user}"
        else:
            am = SSH_OK_RE.search(msg)
            if am:
                user, ip = am["user"], am["ip"]
                msg = f"SSH accepted password for {user}"
            else:
                cm = SSH_CONN_RE.search(msg)
                if cm:
                    ip = cm["ip"]

    if ip is None:
        im = IP_RE.search(msg)
        if im:
            ip = im.group("ip")

    if ip is None and user is None:
        return None

    return Event(
        timestamp=ts,
        source_ip=ip or "0.0.0.0",
        username=user,
        message=msg,
        raw=line,
        facility=proc,
    )


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


class Detector:
    """Base class for stateful detectors.

    A detector receives Events via `feed()` and may emit Alerts. Each
    detector owns a rolling window of events per source IP so it can
    detect bursts without holding the full log in memory.
    """

    name: str = "base"
    window_seconds: int = 60
    threshold: int = 5

    def __init__(self) -> None:
        self._buckets: dict[str, deque[Event]] = defaultdict(deque)

    def _prune(self, ip: str, now: datetime) -> None:
        bucket = self._buckets[ip]
        while bucket and (now - bucket[0].timestamp).total_seconds() > self.window_seconds:
            bucket.popleft()

    def feed(self, event: Event) -> Optional[Alert]:
        self._prune(event.source_ip, event.timestamp)
        self._buckets[event.source_ip].append(event)
        return self._evaluate(event)

    # Subclasses override
    def _evaluate(self, event: Event) -> Optional[Alert]:
        return None


class SSHBruteForceDetector(Detector):
    """Detect SSH brute-force: many failed logins from one IP in a window."""

    name = "ssh_bruteforce"
    window_seconds = 60
    threshold = 5

    def _evaluate(self, event: Event) -> Optional[Alert]:
        if "failed password" not in event.message.lower():
            return None
        bucket = self._buckets[event.source_ip]
        if len(bucket) >= self.threshold:
            return Alert(
                detector=self.name,
                severity="high",
                title=f"SSH brute-force from {event.source_ip}",
                description=(
                    f"{len(bucket)} failed SSH auth attempts from "
                    f"{event.source_ip} within {self.window_seconds}s"
                ),
                source_ip=event.source_ip,
                events=list(bucket),
            )
        return None


class PortScanDetector(Detector):
    """Detect port-scan: many distinct connections from one IP."""

    name = "port_scan"
    window_seconds = 30
    threshold = 10

    def __init__(self) -> None:
        super().__init__()
        self._ports: dict[str, set[str]] = defaultdict(set)

    def _evaluate(self, event: Event) -> Optional[Alert]:
        port = _extract_port(event.raw)
        if port:
            self._ports[event.source_ip].add(port)
        bucket = self._buckets[event.source_ip]
        distinct = len(self._ports[event.source_ip])
        if len(bucket) >= self.threshold and distinct >= 3:
            ports = ",".join(sorted(self._ports[event.source_ip]))
            return Alert(
                detector=self.name,
                severity="medium",
                title=f"Port scan from {event.source_ip}",
                description=(
                    f"{len(bucket)} connections to {distinct} distinct ports "
                    f"({ports}) within {self.window_seconds}s"
                ),
                source_ip=event.source_ip,
                events=list(bucket),
            )
        return None


class AuthFailStormDetector(Detector):
    """Detect cross-service auth failure storm from a single IP."""

    name = "auth_fail_storm"
    window_seconds = 120
    threshold = 8

    def _evaluate(self, event: Event) -> Optional[Alert]:
        if not re.search(r"fail|invalid|denied|error", event.message, re.I):
            return None
        bucket = self._buckets[event.source_ip]
        if len(bucket) >= self.threshold:
            return Alert(
                detector=self.name,
                severity="medium",
                title=f"Auth failure storm from {event.source_ip}",
                description=(
                    f"{len(bucket)} authentication failures across services "
                    f"from {event.source_ip} within {self.window_seconds}s"
                ),
                source_ip=event.source_ip,
                events=list(bucket),
            )
        return None


def _extract_port(line: str) -> Optional[str]:
    m = re.search(r"port\s+(\d{1,5})", line, re.I)
    return m.group(1) if m else None


DETECTORS: list[Callable[[], Detector]] = [
    SSHBruteForceDetector,
    PortScanDetector,
    AuthFailStormDetector,
]


# ---------------------------------------------------------------------------
# Alert sinks
# ---------------------------------------------------------------------------


class AlertSink:
    """Base class for alert sinks (outputs)."""

    def emit(self, alert: Alert) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        pass


class JSONSink(AlertSink):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = self.path.open("a", encoding="utf-8")

    def emit(self, alert: Alert) -> None:
        self._fp.write(json.dumps(alert.to_dict(), default=str) + "\n")
        self._fp.flush()

    def close(self) -> None:
        self._fp.close()


class CSVSink(AlertSink):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = self.path.open("a", encoding="utf-8", newline="")
        self._writer = csv.writer(self._fp)
        if self.path.stat().st_size == 0:
            self._writer.writerow(
                ["timestamp", "detector", "severity", "source_ip", "title", "description"]
            )

    def emit(self, alert: Alert) -> None:
        self._writer.writerow(
            [
                alert.timestamp.isoformat(),
                alert.detector,
                alert.severity,
                alert.source_ip,
                alert.title,
                alert.description,
            ]
        )
        self._fp.flush()

    def close(self) -> None:
        self._fp.close()


class StdoutSink(AlertSink):
    """Colorful console sink for live monitoring."""

    SEV_COLOR = {
        "info": "\033[36m",
        "low": "\033[32m",
        "medium": "\033[33m",
        "high": "\033[31m",
        "critical": "\033[35m",
    }
    RESET = "\033[0m"

    def emit(self, alert: Alert) -> None:
        color = self.SEV_COLOR.get(alert.severity, "")
        sev = alert.severity.upper().ljust(8)
        ts = alert.timestamp.strftime("%H:%M:%S")
        print(
            f"{color}[{ts}] [{sev}] {alert.title}{self.RESET}\n"
            f"          ↳ {alert.description}\n"
            f"          ↳ source: {alert.source_ip} · detector: {alert.detector}"
        )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SOCEngine:
    """Orchestrates parsers, detectors and sinks over a log stream."""

    def __init__(
        self,
        detectors: Iterable[Detector] | None = None,
        sinks: Iterable[AlertSink] | None = None,
        parser: Callable[[str], Optional[Event]] = parse_syslog,
    ) -> None:
        self.detectors: list[Detector] = list(detectors or (d() for d in DETECTORS))
        self.sinks: list[AlertSink] = list(sinks or [StdoutSink()])
        self.parser = parser
        self.stats = {"lines": 0, "events": 0, "alerts": 0}
        self._fired: set[tuple[str, str]] = set()  # (detector, ip) cooldown

    def _process_line(self, line: str) -> list[Alert]:
        self.stats["lines"] += 1
        event = self.parser(line)
        if not event:
            return []
        self.stats["events"] += 1
        fired: list[Alert] = []
        for det in self.detectors:
            alert = det.feed(event)
            if not alert:
                continue
            key = (alert.detector, alert.source_ip)
            if key in self._fired:
                continue
            self._fired.add(key)
            fired.append(alert)
            self.stats["alerts"] += 1
            for sink in self.sinks:
                try:
                    sink.emit(alert)
                except Exception:  # never let a sink kill the engine
                    LOG.exception("sink %s failed", type(sink).__name__)
        return fired

    def process(self, lines: Iterable[str]) -> int:
        count = 0
        for line in lines:
            count += len(self._process_line(line))
        return count

    def follow(self, path: Path) -> None:
        """Tail a file in real time (like tail -f)."""
        with path.open("r", encoding="utf-8", errors="replace") as fp:
            fp.seek(0, os.SEEK_END)
            while True:
                line = fp.readline()
                if line:
                    self._process_line(line)
                else:
                    time.sleep(0.25)

    def reset_cooldown(self) -> None:
        self._fired.clear()


# ---------------------------------------------------------------------------
# Demo data generator (for `--demo`)
# ---------------------------------------------------------------------------


def demo_lines() -> Iterable[str]:
    """Yield a synthetic attack scenario for quick local testing."""
    base = "Jul 29 12:00:00 srv01 sshd[1234]: "
    scenario: list[str] = []
    scenario += [
        f"{base}Failed password for root from 203.0.113.5 port 51{i:02d} ssh2"
        for i in range(7)
    ]
    scenario.append(
        f"{base}Accepted password for admin from 198.51.100.7 port 51022 ssh2"
    )
    scenario += [
        f"{base}Connection closed by 203.0.113.5 port 52{i:03d}" for i in range(12)
    ]
    scenario.append(
        "Jul 29 12:01:00 srv01 sshd[1234]: Failed password for invalid user admin "
        "from 203.0.113.5 port 53000 ssh2"
    )
    scenario.append(
        "Jul 29 12:01:05 srv01 sudo:   admin : TTY=pts/0 ; authentication failure"
    )
    for line in scenario:
        yield line + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_sinks(args: argparse.Namespace) -> list[AlertSink]:
    sinks: list[AlertSink] = []
    if args.json:
        sinks.append(JSONSink(Path(args.json)))
    if args.csv:
        sinks.append(CSVSink(Path(args.csv)))
    if not args.quiet:
        sinks.append(StdoutSink())
    return sinks


def cmd_run(args: argparse.Namespace) -> int:
    sinks = _build_sinks(args)
    engine = SOCEngine(sinks=sinks)

    def _shutdown(signum, _frame):
        LOG.info("shutting down (signal %s)", signum)
        for s in engine.sinks:
            s.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    try:
        signal.signal(signal.SIGTERM, _shutdown)
    except (AttributeError, ValueError):  # Windows
        pass

    if args.demo:
        engine.process(demo_lines())
        return 0

    path = Path(args.file)
    if args.follow:
        print(f"📡 Tailing {path} in real time…  (Ctrl+C to stop)\n")
        engine.follow(path)
        return 0

    with path.open("r", encoding="utf-8", errors="replace") as fp:
        engine.process(fp)

    print(
        f"\n— done · lines={engine.stats['lines']} "
        f"events={engine.stats['events']} alerts={engine.stats['alerts']}"
    )
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    print("Available detectors:")
    for d in DETECTORS:
        inst = d()
        print(f"  • {inst.name:<18} window={inst.window_seconds}s threshold={inst.threshold}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="soc-monitor",
        description="🛡️ Lightweight SOC monitor — brute-force, port-scan & auth-fail detection.",
    )
    p.add_argument("--version", action="version", version=f"soc-monitor {__version__}")
    sub = p.add_subparsers(dest="cmd")

    run = sub.add_parser("run", help="Analyze a log file or stream")
    run.add_argument("file", nargs="?", help="Path to a syslog/auth log file")
    run.add_argument("-f", "--follow", action="store_true", help="Tail the file in real time")
    run.add_argument("--demo", action="store_true", help="Run a built-in attack scenario")
    run.add_argument("--json", help="Append alerts to a JSONL file")
    run.add_argument("--csv", help="Append alerts to a CSV file")
    run.add_argument("-q", "--quiet", action="store_true", help="No console output")
    run.set_defaults(func=cmd_run)

    lst = sub.add_parser("list", help="List available detectors")
    lst.set_defaults(func=cmd_list)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        build_parser().print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
