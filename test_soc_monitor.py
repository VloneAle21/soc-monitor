"""Unit tests for soc_monitor — run with: python -m pytest -v"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("soc_monitor", HERE / "soc_monitor.py")
soc = importlib.util.module_from_spec(spec)
sys.modules["soc_monitor"] = soc
spec.loader.exec_module(soc)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_sshd_failed_password():
    line = "Jul 29 12:00:00 srv01 sshd[1234]: Failed password for root from 203.0.113.5 port 51001 ssh2"
    ev = soc.parse_syslog(line)
    assert ev is not None
    assert ev.source_ip == "203.0.113.5"
    assert ev.username == "root"
    assert "failed password" in ev.message.lower()


def test_parse_invalid_user():
    line = "Jul 29 12:00:01 srv01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51002 ssh2"
    ev = soc.parse_syslog(line)
    assert ev is not None
    assert ev.username == "admin"
    assert ev.source_ip == "203.0.113.5"


def test_parse_accepted_password():
    line = "Jul 29 12:00:14 srv01 sshd[1234]: Accepted password for admin from 198.51.100.7 port 51022 ssh2"
    ev = soc.parse_syslog(line)
    assert ev is not None
    assert ev.username == "admin"
    assert ev.source_ip == "198.51.100.7"


def test_parse_blank_line_returns_none():
    assert soc.parse_syslog("\n") is None
    assert soc.parse_syslog("") is None


def test_parse_fallback_extracts_ip_from_unstructured_line():
    line = "random app log connection from 10.0.0.99 something"
    ev = soc.parse_syslog(line)
    assert ev is not None
    assert ev.source_ip == "10.0.0.99"


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _make_event(ip="203.0.113.5", msg="Failed password for root", seconds=0):
    from datetime import datetime, timedelta, timezone
    base = datetime(2026, 7, 29, 12, 0, 0, tzinfo=timezone.utc)
    return soc.Event(
        timestamp=base + timedelta(seconds=seconds),
        source_ip=ip,
        username="root",
        message=msg,
        raw=f"sshd: {msg} from {ip} port 1234",
    )


def test_ssh_bruteforce_fires_after_threshold():
    det = soc.SSHBruteForceDetector()
    det.threshold = 5
    alerts = []
    for i in range(5):
        a = det.feed(_make_event(seconds=i))
        if a:
            alerts.append(a)
    assert len(alerts) == 1
    assert alerts[0].severity == "high"
    assert "203.0.113.5" in alerts[0].title


def test_ssh_bruteforce_no_fire_below_threshold():
    det = soc.SSHBruteForceDetector()
    det.threshold = 10
    alerts = [det.feed(_make_event(seconds=i)) for i in range(4)]
    assert not any(alerts)


def test_port_scan_detector_fires():
    det = soc.PortScanDetector()
    det.threshold = 3
    alerts = []
    for i in range(4):
        ev = _make_event(msg=f"Connection closed by 203.0.113.5 port 50{i}", seconds=i)
        ev.raw = f"sshd: Connection closed by 203.0.113.5 port 50{i}"
        a = det.feed(ev)
        if a:
            alerts.append(a)
    assert len(alerts) >= 1
    assert alerts[0].detector == "port_scan"


def test_alert_severity_rank():
    assert soc.Alert("d", "low", "t", "desc", "1.2.3.4").rank < soc.Alert(
        "d", "critical", "t", "desc", "1.2.3.4"
    ).rank


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def test_engine_processes_demo_and_emits_alerts():
    sink = soc.StdoutSink()
    engine = soc.SOCEngine(sinks=[])
    alerts_count = engine.process(soc.demo_lines())
    assert alerts_count >= 1
    assert engine.stats["alerts"] >= 1


def test_engine_json_sink_writes_file(tmp_path):
    out = tmp_path / "alerts.jsonl"
    sink = soc.JSONSink(out)
    engine = soc.SOCEngine(sinks=[sink])
    engine.process(soc.demo_lines())
    sink.close()
    assert out.exists()
    content = out.read_text(encoding="utf-8").strip().splitlines()
    assert content
    import json
    rec = json.loads(content[0])
    assert "detector" in rec and "severity" in rec
