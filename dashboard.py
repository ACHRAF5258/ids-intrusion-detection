#!/usr/bin/env python3
"""
IDS Dashboard Generator
Reads ids_summary.json and generates a beautiful HTML dashboard
"""

import json
import sys
import os
from datetime import datetime

def generate_dashboard(summary_file="ids_summary.json", output="ids_dashboard.html"):
    if not os.path.exists(summary_file):
        # Generate demo data
        summary = {
            "session": {
                "total_packets": 8472,
                "total_alerts": 17,
                "start_time": "2026-06-07T10:00:00",
                "by_severity": {"CRITICAL": 3, "HIGH": 6, "MEDIUM": 5, "LOW": 3},
                "by_type": {
                    "PORT SCAN — SYN SCAN": 4,
                    "TCP SYN FLOOD (DoS)": 2,
                    "ARP SPOOFING / POISONING": 1,
                    "BRUTE FORCE — SSH": 5,
                    "ICMP FLOOD / PING FLOOD": 3,
                    "DNS AMPLIFICATION": 1,
                    "LARGE PAYLOAD ANOMALY": 1,
                }
            },
            "alerts": [
                {"timestamp":"2026-06-07T10:02:15","severity":"CRITICAL","attack_type":"ARP SPOOFING / POISONING","src_ip":"192.168.1.99","dst_ip":"LAN","detail":"IP 192.168.1.1 changed MAC: aa:bb → cc:dd","port":None},
                {"timestamp":"2026-06-07T10:03:22","severity":"HIGH","attack_type":"PORT SCAN — SYN SCAN","src_ip":"10.0.0.5","dst_ip":"192.168.1.10","detail":"15 ports probed | Last port: 8080","port":8080},
                {"timestamp":"2026-06-07T10:05:11","severity":"HIGH","attack_type":"BRUTE FORCE — SSH","src_ip":"10.0.0.8","dst_ip":"192.168.1.20","detail":"10 attempts to port 22 in 5s","port":22},
                {"timestamp":"2026-06-07T10:07:44","severity":"CRITICAL","attack_type":"TCP SYN FLOOD (DoS)","src_ip":"10.0.0.3","dst_ip":"192.168.1.1","detail":"100 SYN packets — possible DoS","port":80},
                {"timestamp":"2026-06-07T10:09:30","severity":"MEDIUM","attack_type":"DNS AMPLIFICATION","src_ip":"8.8.8.8","dst_ip":"192.168.1.5","detail":"30 DNS responses detected","port":53},
                {"timestamp":"2026-06-07T10:11:02","severity":"HIGH","attack_type":"ICMP FLOOD / PING FLOOD","src_ip":"10.0.0.12","dst_ip":"192.168.1.1","detail":"50 ICMP packets detected","port":None},
                {"timestamp":"2026-06-07T10:13:18","severity":"CRITICAL","attack_type":"PORT SCAN — XMAS SCAN","src_ip":"10.0.0.5","dst_ip":"192.168.1.10","detail":"25 ports probed total","port":443},
            ]
        }
    else:
        with open(summary_file) as f:
            summary = json.load(f)

    sess   = summary["session"]
    alerts = summary.get("alerts", [])

    sev_colors = {
        "CRITICAL": "#E74C3C",
        "HIGH":     "#E67E22",
        "MEDIUM":   "#F39C12",
        "LOW":      "#3498DB"
    }

    rows = ""
    for a in reversed(alerts[-50:]):
        col = sev_colors.get(a["severity"], "#888")
        ts  = a["timestamp"][:19].replace("T"," ")
        rows += f"""
        <tr>
          <td>{ts}</td>
          <td><span class="badge" style="background:{col}">{a['severity']}</span></td>
          <td>{a['attack_type']}</td>
          <td>{a['src_ip']}</td>
          <td>{a['dst_ip']}</td>
          <td>{a.get('port') or '—'}</td>
          <td style="color:#aaa;font-size:11px">{a['detail']}</td>
        </tr>"""

    by_type = sess.get("by_type", {})
    chart_labels = list(by_type.keys())
    chart_values = list(by_type.values())
    chart_colors = ["#E74C3C","#E67E22","#F39C12","#2ECC71","#3498DB","#9B59B6","#1ABC9C"]

    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>PyIDS Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0a0f1e;color:#e0e8f0;min-height:100vh}}
  .header{{background:linear-gradient(135deg,#0d1b3e,#1a3a5c);padding:24px 32px;
           border-bottom:2px solid #4A90D9;display:flex;align-items:center;gap:16px}}
  .header h1{{font-size:22px;color:#fff}}
  .header .sub{{color:#8BBBDD;font-size:13px;margin-top:4px}}
  .dot{{width:10px;height:10px;border-radius:50%;background:#2ECC71;
        box-shadow:0 0 8px #2ECC71;animation:pulse 1.5s infinite}}
  @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:0.4}}}}
  .container{{padding:24px 32px}}
  .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}}
  .stat-card{{background:#111827;border:1px solid #1e3a5f;border-radius:10px;
              padding:20px;text-align:center}}
  .stat-card .val{{font-size:36px;font-weight:bold;color:#4A90D9}}
  .stat-card .lbl{{color:#8899AA;font-size:12px;margin-top:6px}}
  .stat-card.critical .val{{color:#E74C3C}}
  .stat-card.high .val{{color:#E67E22}}
  .charts{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}}
  .card{{background:#111827;border:1px solid #1e3a5f;border-radius:10px;padding:20px}}
  .card h2{{font-size:14px;color:#8BBBDD;margin-bottom:16px;text-transform:uppercase;
            letter-spacing:1px;border-bottom:1px solid #1e3a5f;padding-bottom:8px}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#0d1b3e;color:#8BBBDD;padding:10px;text-align:left;
      font-size:12px;text-transform:uppercase;letter-spacing:0.5px}}
  td{{padding:9px 10px;border-bottom:1px solid #0d1b3e;font-size:13px}}
  tr:hover td{{background:#0d1b3e}}
  .badge{{padding:3px 10px;border-radius:12px;font-size:11px;
          font-weight:bold;color:#fff;display:inline-block}}
  canvas{{max-height:220px}}
  .sev-bar{{display:flex;gap:8px;align-items:center;margin-bottom:8px}}
  .sev-bar .label{{width:80px;font-size:12px;color:#8BBBDD}}
  .sev-bar .bar{{height:14px;border-radius:4px;min-width:4px}}
  .sev-bar .count{{font-size:12px;color:#aaa;margin-left:6px}}
</style></head>
<body>
<div class="header">
  <div class="dot"></div>
  <div>
    <h1>PyIDS — Intrusion Detection System Dashboard</h1>
    <div class="sub">Session started: {sess.get('start_time','')[:19].replace('T',' ')} &nbsp;|&nbsp; Report: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
  </div>
</div>
<div class="container">
  <div class="stats">
    <div class="stat-card">
      <div class="val">{sess.get('total_packets',0):,}</div>
      <div class="lbl">Packets Analyzed</div>
    </div>
    <div class="stat-card">
      <div class="val">{sess.get('total_alerts',0)}</div>
      <div class="lbl">Total Alerts</div>
    </div>
    <div class="stat-card critical">
      <div class="val">{sess.get('by_severity',{}).get('CRITICAL',0)}</div>
      <div class="lbl">Critical Alerts</div>
    </div>
    <div class="stat-card high">
      <div class="val">{sess.get('by_severity',{}).get('HIGH',0)}</div>
      <div class="lbl">High Alerts</div>
    </div>
  </div>

  <div class="charts">
    <div class="card">
      <h2>Attack Distribution</h2>
      <canvas id="pieChart"></canvas>
    </div>
    <div class="card">
      <h2>Severity Breakdown</h2>
      {''.join(f"""
      <div class="sev-bar">
        <div class="label">{sev}</div>
        <div class="bar" style="width:{min(sess.get('by_severity',{{}}).get(sev,0)*12,200)}px;background:{col}"></div>
        <div class="count">{sess.get('by_severity',{{}}).get(sev,0)}</div>
      </div>""" for sev,col in sev_colors.items())}
      <br>
      <h2 style="margin-top:12px">Attack Types</h2>
      {''.join(f'<div style="font-size:12px;color:#8BBBDD;padding:4px 0;border-bottom:1px solid #0d1b3e">'
               f'<span style="color:{chart_colors[i%len(chart_colors)]};margin-right:8px">●</span>'
               f'{k} <span style="float:right;color:#4A90D9">{v}</span></div>'
               for i,(k,v) in enumerate(by_type.items()))}
    </div>
  </div>

  <div class="card">
    <h2>Alert Log (Latest 50)</h2>
    <table>
      <tr><th>Time</th><th>Severity</th><th>Attack Type</th>
          <th>Source IP</th><th>Destination</th><th>Port</th><th>Detail</th></tr>
      {rows}
    </table>
  </div>
</div>

<script>
new Chart(document.getElementById('pieChart'), {{
  type: 'doughnut',
  data: {{
    labels: {json.dumps(chart_labels)},
    datasets: [{{
      data: {json.dumps(chart_values)},
      backgroundColor: {json.dumps(chart_colors[:len(chart_labels)])},
      borderWidth: 0
    }}]
  }},
  options: {{
    plugins: {{
      legend: {{ labels: {{ color: '#8BBBDD', font: {{ size: 11 }} }} }}
    }}
  }}
}});
</script>
</body></html>"""

    with open(output, "w") as f:
        f.write(html)
    print(f"✅ Dashboard saved → {output}")

if __name__ == "__main__":
    summary = sys.argv[1] if len(sys.argv) > 1 else "ids_summary.json"
    generate_dashboard(summary)
