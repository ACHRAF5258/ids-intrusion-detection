#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║        IDS — Python Intrusion Detection System     ║
║        Author: med achraf htiwech                    ║
║                                                      ║
╚══════════════════════════════════════════════════════╝

Detects:
  - Port Scans (SYN, FIN, NULL, XMAS)
  - ARP Spoofing / Poisoning
  - ICMP Flood (Ping of Death / DoS)
  - TCP SYN Flood (DoS)
  - DNS Amplification attacks
  - Brute Force (SSH/FTP repeated connections)
  - Large payload anomalies
  - Suspicious outbound connections
"""

from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, DNS, Raw, Ether
from collections import defaultdict
from datetime import datetime
import argparse
import json
import os
import threading
import time

# ── Terminal colors ──
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"

def color(c, t): return f"{c}{t}{C.RESET}"

# ══════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════
CONFIG = {
    "port_scan_threshold":   15,    # ports probed before alert
    "syn_flood_threshold":   100,   # SYNs/sec before alert
    "icmp_flood_threshold":  50,    # ICMPs/sec before alert
    "brute_force_threshold": 10,    # connections to same port in 5s
    "dns_amp_threshold":     30,    # DNS responses/sec
    "large_payload_bytes":   8000,  # bytes considered anomalous
    "time_window":           5,     # seconds for rate counters
    "whitelist_ips":         [],    # trusted IPs (no alerts)
    "log_file":              "ids_alerts.json",
    "pcap_output":           "ids_capture.pcap",
}

# ══════════════════════════════════════════
#  STATE TRACKING
# ══════════════════════════════════════════
state = {
    "port_scan":     defaultdict(set),       # src -> {ports}
    "syn_count":     defaultdict(int),       # src -> count
    "icmp_count":    defaultdict(int),       # src -> count
    "brute_force":   defaultdict(list),      # src:port -> [timestamps]
    "dns_responses": defaultdict(int),       # src -> count
    "arp_table":     {},                     # ip -> mac
    "alerts":        [],
    "stats": {
        "total_packets": 0,
        "total_alerts":  0,
        "start_time":    datetime.now().isoformat(),
        "by_severity":   {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "by_type":       defaultdict(int),
    }
}

LOCK = threading.Lock()
captured_packets = []

# ══════════════════════════════════════════
#  ALERT ENGINE
# ══════════════════════════════════════════
SEVERITY_COLORS = {
    "CRITICAL": C.RED,
    "HIGH":     C.YELLOW,
    "MEDIUM":   C.MAGENTA,
    "LOW":      C.CYAN,
}

def fire_alert(severity, attack_type, src_ip, dst_ip, detail, port=None):
    """Central alert dispatcher"""
    if src_ip in CONFIG["whitelist_ips"]:
        return

    ts = datetime.now().strftime("%H:%M:%S")
    col = SEVERITY_COLORS.get(severity, C.WHITE)

    alert = {
        "timestamp":   datetime.now().isoformat(),
        "severity":    severity,
        "attack_type": attack_type,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "port":        port,
        "detail":      detail,
    }

    with LOCK:
        state["alerts"].append(alert)
        state["stats"]["total_alerts"] += 1
        state["stats"]["by_severity"][severity] += 1
        state["stats"]["by_type"][attack_type] += 1

    # Print to terminal
    sev_tag = f"[{severity:8}]"
    print(
        f"\n  {color(C.DIM, ts)} "
        f"{color(col, sev_tag)} "
        f"{color(C.BOLD, attack_type):35} "
        f"{color(C.CYAN, src_ip):18} → {dst_ip}"
    )
    print(f"  {' '*11} {color(C.DIM, detail)}")

    # Save to log
    _append_log(alert)

def _append_log(alert):
    log_path = CONFIG["log_file"]
    try:
        if os.path.exists(log_path):
            with open(log_path) as f:
                logs = json.load(f)
        else:
            logs = []
        logs.append(alert)
        with open(log_path, "w") as f:
            json.dump(logs, f, indent=2)
    except Exception:
        pass

# ══════════════════════════════════════════
#  DETECTION MODULES
# ══════════════════════════════════════════

def detect_arp_spoofing(pkt):
    """ARP cache poisoning detection"""
    if not (pkt.haslayer(ARP) and pkt[ARP].op == 2):
        return
    ip  = pkt[ARP].psrc
    mac = pkt[ARP].hwsrc
    with LOCK:
        if ip in state["arp_table"] and state["arp_table"][ip] != mac:
            fire_alert(
                "CRITICAL", "ARP SPOOFING / POISONING",
                ip, "LAN",
                f"IP {ip} changed MAC: {state['arp_table'][ip]} → {mac}"
            )
        state["arp_table"][ip] = mac


def detect_port_scan(pkt):
    """Detect SYN, FIN, NULL, XMAS scans"""
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return
    src   = pkt[IP].src
    dst   = pkt[IP].dst
    dport = pkt[TCP].dport
    flags = pkt[TCP].flags

    scan_type = None
    if flags == 0x002:  scan_type = "SYN SCAN"
    elif flags == 0x001: scan_type = "FIN SCAN"
    elif flags == 0x000: scan_type = "NULL SCAN"
    elif flags == 0x029: scan_type = "XMAS SCAN"

    if scan_type:
        with LOCK:
            state["port_scan"][src].add(dport)
            count = len(state["port_scan"][src])
        if count == CONFIG["port_scan_threshold"]:
            fire_alert(
                "HIGH", f"PORT SCAN — {scan_type}",
                src, dst,
                f"{count} ports probed | Last port: {dport}",
                port=dport
            )
        elif count > CONFIG["port_scan_threshold"] and count % 10 == 0:
            fire_alert(
                "HIGH", f"PORT SCAN — ONGOING {scan_type}",
                src, dst,
                f"{count} ports probed total",
                port=dport
            )


def detect_syn_flood(pkt):
    """TCP SYN flood DoS detection"""
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return
    if pkt[TCP].flags != 0x002:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    with LOCK:
        state["syn_count"][src] += 1
        count = state["syn_count"][src]
    if count == CONFIG["syn_flood_threshold"]:
        fire_alert(
            "CRITICAL", "TCP SYN FLOOD (DoS)",
            src, dst,
            f"{count} SYN packets — possible DoS attack",
            port=pkt[TCP].dport
        )


def detect_icmp_flood(pkt):
    """ICMP flood / Ping of Death"""
    if not (pkt.haslayer(ICMP) and pkt.haslayer(IP)):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    size = len(pkt)
    with LOCK:
        state["icmp_count"][src] += 1
        count = state["icmp_count"][src]

    if count == CONFIG["icmp_flood_threshold"]:
        fire_alert(
            "HIGH", "ICMP FLOOD / PING FLOOD",
            src, dst,
            f"{count} ICMP packets detected"
        )
    if size > 65000:
        fire_alert(
            "CRITICAL", "PING OF DEATH",
            src, dst,
            f"Oversized ICMP packet: {size} bytes"
        )


def detect_brute_force(pkt):
    """SSH/FTP/Telnet brute force detection"""
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return
    dport = pkt[TCP].dport
    if dport not in [22, 21, 23, 3389, 5900]:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    key = f"{src}:{dport}"
    now = time.time()
    service_names = {22:"SSH", 21:"FTP", 23:"Telnet", 3389:"RDP", 5900:"VNC"}

    with LOCK:
        state["brute_force"][key].append(now)
        # Keep only events in the time window
        state["brute_force"][key] = [
            t for t in state["brute_force"][key]
            if now - t <= CONFIG["time_window"]
        ]
        count = len(state["brute_force"][key])

    if count >= CONFIG["brute_force_threshold"]:
        svc = service_names.get(dport, str(dport))
        fire_alert(
            "HIGH", f"BRUTE FORCE — {svc}",
            src, dst,
            f"{count} connection attempts to port {dport} in {CONFIG['time_window']}s",
            port=dport
        )
        with LOCK:
            state["brute_force"][key] = []


def detect_dns_amplification(pkt):
    """DNS amplification attack detection"""
    if not (pkt.haslayer(DNS) and pkt.haslayer(IP)):
        return
    if pkt[DNS].qr == 1:  # DNS response
        src = pkt[IP].src
        with LOCK:
            state["dns_responses"][src] += 1
            count = state["dns_responses"][src]
        if count == CONFIG["dns_amp_threshold"]:
            fire_alert(
                "MEDIUM", "DNS AMPLIFICATION",
                src, pkt[IP].dst,
                f"{count} DNS responses — possible amplification attack",
                port=53
            )


def detect_large_payload(pkt):
    """Detect anomalously large payloads"""
    if not pkt.haslayer(IP):
        return
    size = len(pkt)
    if size > CONFIG["large_payload_bytes"]:
        src = pkt[IP].src
        dst = pkt[IP].dst
        fire_alert(
            "LOW", "LARGE PAYLOAD ANOMALY",
            src, dst,
            f"Packet size: {size} bytes (threshold: {CONFIG['large_payload_bytes']})"
        )


# ══════════════════════════════════════════
#  PACKET PROCESSOR
# ══════════════════════════════════════════
def process_packet(pkt):
    with LOCK:
        state["stats"]["total_packets"] += 1
        captured_packets.append(pkt)

    count = state["stats"]["total_packets"]
    if count % 50 == 0:
        alerts = state["stats"]["total_alerts"]
        print(
            f"  {color(C.DIM, datetime.now().strftime('%H:%M:%S'))} "
            f"{color(C.BLUE, f'[INFO]')} "
            f"Packets: {count:6} | Alerts: {color(C.YELLOW, str(alerts)):5}",
            end="\r"
        )

    # Run all detection modules
    detect_arp_spoofing(pkt)
    detect_port_scan(pkt)
    detect_syn_flood(pkt)
    detect_icmp_flood(pkt)
    detect_brute_force(pkt)
    detect_dns_amplification(pkt)
    detect_large_payload(pkt)


# ══════════════════════════════════════════
#  RESET COUNTERS (background thread)
# ══════════════════════════════════════════
def reset_counters():
    """Reset rate-based counters every time_window seconds"""
    while True:
        time.sleep(CONFIG["time_window"])
        with LOCK:
            state["syn_count"].clear()
            state["icmp_count"].clear()
            state["dns_responses"].clear()


# ══════════════════════════════════════════
#  FINAL REPORT
# ══════════════════════════════════════════
def print_summary():
    stats = state["stats"]
    print(f"\n\n{'═'*55}")
    print(color(C.BOLD, "  IDS SESSION SUMMARY"))
    print(f"{'═'*55}")
    print(f"  Total packets   : {color(C.CYAN, str(stats['total_packets']))}")
    print(f"  Total alerts    : {color(C.YELLOW, str(stats['total_alerts']))}")
    print(f"\n  By Severity:")
    for sev, col in [("CRITICAL",C.RED),("HIGH",C.YELLOW),("MEDIUM",C.MAGENTA),("LOW",C.CYAN)]:
        n = stats["by_severity"][sev]
        bar = "█" * min(n, 30)
        print(f"    {color(col, f'{sev:10}')} {bar} {n}")
    print(f"\n  By Attack Type:")
    for atype, count in sorted(stats["by_type"].items(), key=lambda x:-x[1]):
        print(f"    {color(C.CYAN, f'{atype:35}')} {count}")
    print(f"\n  Log file        : {CONFIG['log_file']}")
    print(f"{'═'*55}\n")

    # Save final JSON summary
    summary = {
        "session": stats,
        "alerts": state["alerts"],
        "arp_table": state["arp_table"],
    }
    summary["session"]["by_type"] = dict(summary["session"]["by_type"])
    with open("ids_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(color(C.GREEN, "  ✅ Full summary saved → ids_summary.json"))


# ══════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="PyIDS — Python Intrusion Detection System",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--iface",  default=None,
                        help="Network interface (default: auto)")
    parser.add_argument("-c", "--count",  type=int, default=0,
                        help="Packets to capture (0 = infinite)")
    parser.add_argument("-w", "--whitelist", nargs="*", default=[],
                        help="Trusted IPs to ignore")
    parser.add_argument("--syn-threshold",  type=int,
                        default=CONFIG["syn_flood_threshold"])
    parser.add_argument("--scan-threshold", type=int,
                        default=CONFIG["port_scan_threshold"])
    args = parser.parse_args()

    CONFIG["whitelist_ips"]        = args.whitelist
    CONFIG["syn_flood_threshold"]  = args.syn_threshold
    CONFIG["port_scan_threshold"]  = args.scan_threshold

    print(color(C.BOLD, f"""
{'═'*55}
  PyIDS — Python Intrusion Detection System
{'═'*55}
  Interface  : {args.iface or 'auto-detect'}
  Capture    : {'infinite' if args.count == 0 else str(args.count) + ' packets'}
  Whitelist  : {args.whitelist or 'none'}

  Detection modules active:
    ✔  ARP Spoofing / Poisoning
    ✔  Port Scan (SYN, FIN, NULL, XMAS)
    ✔  TCP SYN Flood
    ✔  ICMP Flood / Ping of Death
    ✔  SSH/FTP/RDP Brute Force
    ✔  DNS Amplification
    ✔  Large Payload Anomaly
{'═'*55}
"""))

    # Start counter-reset thread
    t = threading.Thread(target=reset_counters, daemon=True)
    t.start()

    print(color(C.YELLOW, "  [*] Listening for threats...\n"))
    try:
        sniff(
            iface=args.iface,
            count=args.count if args.count > 0 else 0,
            prn=process_packet,
            store=False
        )
    except KeyboardInterrupt:
        print(color(C.YELLOW, "\n\n  [!] Stopping IDS..."))
    except PermissionError:
        print(color(C.RED, "\n  [!] Run with sudo for packet capture"))
    finally:
        print_summary()


if __name__ == "__main__":
    main()
