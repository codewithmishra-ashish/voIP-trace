#!/usr/bin/env python3
from flask import Flask, render_template_string, jsonify
import sqlite3, time

DB = "voip_meta.db"

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html>
<head>
  <title>VoIP Trace Dashboard (Prototype)</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <meta http-equiv="refresh" content="6">
</head>
<body class="p-4">
  <div class="container">
    <h1>VoIP Trace Dashboard — Prototype</h1>
    <p>Auto-refresh every 6s. Use only in authorized environments.</p>

    <h3>Active / Recent Calls</h3>
    <table class="table table-sm table-striped">
      <thead><tr><th>#</th><th>proto</th><th>call_id</th><th>signaling</th><th>media</th><th>start</th><th>dur(s)</th><th>pkts</th><th>pacing(ms)</th><th>risk</th></tr></thead>
      <tbody>
      {% for r in rows %}
        <tr class="{{ 'table-danger' if r['risk']>=50 else '' }}">
          <td>{{r['id']}}</td><td>{{r['proto']}}</td><td>{{r['call_id']}}</td>
          <td>{{r['signaling_src']}} → {{r['signaling_dst']}}</td>
          <td>{{r['media_src']}} → {{r['media_dst']}}</td>
          <td>{{r['start_ts']|datetime}}</td><td>{{r['duration']}}</td><td>{{r['pkts']}}</td><td>{{r['pacing_ms']}}</td><td>{{r['risk']}}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>

    <h3>Alerts</h3>
    <table class="table table-sm">
      <thead><tr><th>#</th><th>ts</th><th>call_row</th><th>reason</th><th>risk</th></tr></thead>
      <tbody>
      {% for a in alerts %}
        <tr><td>{{a['id']}}</td><td>{{a['ts']|datetime}}</td><td>{{a['call_row']}}</td><td>{{a['reason']}}</td><td>{{a['risk']}}</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</body>
</html>
"""

from jinja2 import Markup, Environment

env = Environment()
env.filters['datetime'] = lambda v: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v)) if v else ""

def query_db(q, args=()):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(q, args)
    cols = [d[0] for d in cur.description] if cur.description else []
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    conn.close()
    return rows

@app.route("/")
def index():
    rows = query_db("SELECT * FROM calls ORDER BY start_ts DESC LIMIT 50;")
    alerts = query_db("SELECT * FROM alerts ORDER BY ts DESC LIMIT 50;")
    return render_template_string(TEMPLATE, rows=rows, alerts=alerts)

@app.route("/api/calls")
def api_calls():
    r = query_db("SELECT * FROM calls ORDER BY start_ts DESC LIMIT 500;")
    return jsonify(r)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
so