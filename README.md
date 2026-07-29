<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1f6feb,100:0d1117&height=180&section=header&text=SOC%20Monitor&fontSize=45&fontColor=ffffff&fontAlignY=35&desc=Lightweight%20Security%20Operations%20Center%20in%20Python&descSize=16&descColor=c9d1d9&descAlignY=58&animation=fadeIn" width="100%" alt="banner"/>

<br/>

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-11%20passing-success?style=for-the-badge&logo=pytest&logoColor=white)](#-testing)
[![License: MIT](https://img.shields.io/badge/License-MIT-1f6feb?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![No deps](https://img.shields.io/badge/Dependencies-Zero-00d4aa?style=for-the-badge&logo=python&logoColor=white)](requirements.txt)
[![Stars](https://img.shields.io/github/stars/VloneAle21/soc-monitor?style=for-the-badge&logo=github&color=yellow)](https://github.com/VloneAle21/soc-monitor/stargazers)

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3000&pause=600&color=58A6FF&center=true&vCenter=true&multiline=true&width=620&height=70&lines=Brute-force+%C2%B7+Port-scan+%C2%B7+Auth-fail+detection;Rolling-window+state+engine;JSON+%2F+CSV+alert+sinks+%2B+live+dashboard" alt="Typing SVG"/>

<br/>

</div>

---

## 🧠 What is this?

**SOC Monitor** is a lightweight, dependency-free **Security Operations Center** toolkit written in pure Python. It parses syslog / `auth.log` streams in real time and raises alerts when it spots attack patterns commonly seen by blue-team analysts:

- 🔓 **SSH brute-force** — many failed authentications from one IP within a sliding window
- 📡 **Port scanning** — many connections to distinct ports from a single source
- 🌪️ **Auth-failure storm** — cross-service authentication failures clustered together

Designed to be readable, hackable and easy to extend with your own detectors.

> Built by **[Alejandro R. (@VloneAle21)](https://github.com/VloneAle21)** — cybersecurity, AI & automation.

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🧩 | **Pluggable detectors** | Each detector owns a rolling window per source IP. Add your own by subclassing `Detector`. |
| 📊 | **Multiple sinks** | Emit alerts to console (colored), JSONL and CSV simultaneously. |
| ⏱️ | **Live tail mode** | `--follow` tails a log file like `tail -f` for real-time monitoring. |
| 🧪 | **Demo mode** | `--demo` runs a built-in attack scenario — no real logs required. |
| 🚫 | **Zero dependencies** | Standard library only. Just `python soc_monitor.py`. |
| 🧱 | **Clean architecture** | Parser → Detectors → Engine → Sinks. Easy to test and reason about. |

---

## 🚀 Quick start

```bash
# 1. Clone
git clone https://github.com/VloneAle21/soc-monitor.git
cd soc-monitor

# 2. Run the built-in attack scenario (no logs needed)
python soc_monitor.py run --demo

# 3. Or analyze a real auth.log
python soc_monitor.py run /var/log/auth.log

# 4. Tail a log in real time
python soc_monitor.py run /var/log/auth.log --follow

# 5. Save alerts to JSON + CSV while watching the console
python soc_monitor.py run auth.log --json alerts.jsonl --csv alerts.csv
```

### Demo output

```
[15:38:39] [HIGH    ] SSH brute-force from 203.0.113.5
          ↳ 5 failed SSH auth attempts from 203.0.113.5 within 60s
          ↳ source: 203.0.113.5 · detector: ssh_bruteforce
[15:38:39] [MEDIUM  ] Port scan from 203.0.113.5
          ↳ 10 connections to 10 distinct ports (5100,5101,…) within 30s
          ↳ source: 203.0.113.5 · detector: port_scan
[15:38:39] [MEDIUM  ] Auth failure storm from 203.0.113.5
          ↳ 20 authentication failures across services from 203.0.113.5 within 120s
          ↳ source: 203.0.113.5 · detector: auth_fail_storm
```

---

## 🛠️ Usage

```
usage: soc-monitor [-h] [--version] {run,list} ...

🛡️ Lightweight SOC monitor — brute-force, port-scan & auth-fail detection.

commands:
  run        Analyze a log file or stream
  list       List available detectors
```

### `run` options

| Flag | Description |
|---|---|
| `file` | Path to a syslog/auth log file |
| `-f, --follow` | Tail the file in real time (like `tail -f`) |
| `--demo` | Run the built-in attack scenario |
| `--json PATH` | Append alerts to a JSONL file |
| `--csv PATH` | Append alerts to a CSV file |
| `-q, --quiet` | Suppress console output (useful for batch jobs) |

---

## 🧩 Detectors

List the built-in detectors:

```bash
python soc_monitor.py list
```

```
Available detectors:
  • ssh_bruteforce    window=60s  threshold=5
  • port_scan         window=30s  threshold=10
  • auth_fail_storm   window=120s threshold=8
```

### Writing your own detector

```python
from soc_monitor import Detector, Event, Alert

class MyDetector(Detector):
    name = "my_detector"
    window_seconds = 90
    threshold = 3

    def _evaluate(self, event: Event) -> Alert | None:
        # your logic here — return an Alert when a threshold is crossed
        ...

# register it in the engine
engine = SOCEngine(detectors=[MyDetector()], sinks=[StdoutSink()])
engine.process(open("auth.log"))
```

Each detector maintains a per-IP `deque` window that is pruned automatically — so memory stays bounded even on high-volume logs.

---

## 🏗️ Architecture

```
            ┌──────────┐    ┌────────────┐    ┌────────┐    ┌───────┐
log lines → │  Parser  │ →  │  Detectors │ →  │ Engine │ → │ Sinks │
            └──────────┘    └────────────┘    └────────┘    └───────┘
              syslog          brute-force       orchestrates   console
              regexes         port-scan         cooldown       JSONL
              IP extract      auth-fail                        CSV
```

- **Parser** — normalizes a raw line into an `Event(timestamp, source_ip, username, message)`
- **Detectors** — stateful, per-IP rolling windows, emit `Alert`s
- **Engine** — wires parsers + detectors + sinks, dedupes alerts with a cooldown
- **Sinks** — `StdoutSink` (colored), `JSONSink`, `CSVSink`

---

## 🧪 Testing

```bash
python -m pytest test_soc_monitor.py -v
```

```
11 passed in 0.10s
```

Tests cover the syslog parser, each detector's threshold behaviour, the alert severity model and the JSON sink output.

---

## 📁 Project structure

```
soc-monitor/
├── soc_monitor.py        # The whole toolkit (single file, ~600 lines)
├── test_soc_monitor.py   # 11 pytest unit tests
├── sample_auth.log       # Example attack log to play with
├── requirements.txt      # Empty — stdlib only!
└── README.md
```

---

## 🛡️ Use cases

- **Homelab / blue-team practice** — turn your `auth.log` into live alerts
- **CTF / training** — demonstrate detection logic on synthetic traffic
- **Embedded SOC** — ship a tiny IDS where a full SIEM won't fit
- **Learning** — readable, well-commented detection code for newcomers

> ⚠️ This is a detection helper, not a hardened product. For production use, pair it with proper logging, rate limits and a managed SIEM.

---

## 🤝 Contributing

Contributions welcome — especially new detectors (web-shell detection, lateral movement, unusual geo, etc.). Fork, branch, add a test, open a PR.

```bash
git checkout -b feat/my-detector
# …write code + tests…
python -m pytest -v
git commit -m "feat: add my detector"
```

---

## 📄 License

Released under the **MIT License**. See [LICENSE](LICENSE).

---

<div align="center">

<br/>

<img src="https://komarev.com/ghpvc/?username=VloneAle21&style=flat-square&color=blueviolet" alt="views"/>
&nbsp;
<img src="https://img.shields.io/github/last-commit/VloneAle21/soc-monitor?style=flat-square&logo=github&color=blue" alt="last commit"/>
&nbsp;
<img src="https://img.shields.io/github/repo-size/VloneAle21/soc-monitor?style=flat-square&logo=github&color=green" alt="repo size"/>

**⭐ If this was useful, star the repo — it helps a lot.**

Made with 🛡️ by **[Alejandro R.](https://github.com/VloneAle21)**

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1f6feb,100:0d1117&height=100&section=footer&text=&fontSize=0&animation=fadeIn" width="100%" alt="footer"/>

</div>
