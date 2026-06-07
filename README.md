# 🚨 IDS — Python Intrusion Detection System

A real-time network intrusion detection system built in Python using Scapy.
Detects 7 categories of attacks and generates a live HTML dashboard.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.5-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Screenshot
![IDS Dashboard](https://github.com/ACHRAF5258/ids-intrusion-detection/blob/main/ids_dashboard.png)

---

## Detection Modules

| Attack | Severity | Detection Method |
|---|---|---|
| ARP Spoofing / Poisoning | CRITICAL | ARP table monitoring |
| TCP SYN Flood (DoS) | CRITICAL | SYN packet rate tracking |
| Port Scan (SYN/FIN/NULL/XMAS) | HIGH | Multi-port probe detection |
| SSH/FTP/RDP Brute Force | HIGH | Connection rate per port |
| ICMP Flood / Ping of Death | HIGH | ICMP rate + oversized packets |
| DNS Amplification | MEDIUM | DNS response rate tracking |
| Large Payload Anomaly | LOW | Packet size threshold |

---

## Installation

```bash
pip install scapy matplotlib
sudo apt install python3-dev  # Linux
```

## Usage

```bash
# Start IDS on default interface
sudo python ids.py

# Specify interface and packet count
sudo python ids.py -i eth0 -c 1000

# With trusted IP whitelist
sudo python ids.py -i eth0 --whitelist 192.168.1.1 10.0.0.1

# Adjust thresholds
sudo python ids.py --syn-threshold 50 --scan-threshold 10

# Generate HTML dashboard from results
python dashboard.py ids_summary.json
```

## Output Files

| File | Description |
|---|---|
| `ids_alerts.json` | Real-time alert log |
| `ids_summary.json` | Full session summary |
| `ids_dashboard.html` | Visual HTML dashboard |

---

## Architecture

```
Network Interface
      │
      ▼
 Packet Sniffer (Scapy)
      │
      ▼
 ┌────────────────────────┐
 │   Detection Engine     │
 │  ┌─────────────────┐   │
 │  │ ARP Monitor     │   │
 │  │ Port Scan Det.  │   │
 │  │ SYN Flood Det.  │   │
 │  │ ICMP Flood Det. │   │
 │  │ Brute Force Det.│   │
 │  │ DNS Amp. Det.   │   │
 │  └─────────────────┘   │
 └────────────┬───────────┘
              │
         Alert Engine
         ┌───┴────┐
    Terminal    JSON Log
                    │
              HTML Dashboard
```

## Tools Used
`Python 3` `Scapy` `Threading` `Chart.js` `JSON`

---

*⚠️ For educational and authorized testing purposes only.*
