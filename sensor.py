#!/usr/bin/env python3
"""
sensor.py
Lightweight VoIP metadata sensor: sniff UDP, detect SIP INVITE and RTP-like flows by timing,
assemble calls, store metadata in SQLite, compute simple risk score, emit alerts to DB.
Run with root (for sniffing) or use --pcap <file>
"""

import argparse, time, threading, sqlite3, json, os
from scapy.all import sniff, UDP, IP, Raw
from collections import defaultdict, deque
from datetime import datetime, timezone

DB = "voip_meta.db"
LOCK = threading.Lock()

# Parameters (tunable)
RTP_MIN_PKTS = 20
RTP_PACING_MS_RANGE = (12, 100)   # detect mean interpacket gaps in this range
SHORT_CALL_SEC = 20               # short-call heuristic
SHORT_CALL_COUNT_THRESHOLD = 3    # for risk score

# Utility: SQLite init
def init_db():
    with LOCK:
        conn = sqlite3.connect(DB, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS calls (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          call_id TEXT,
          proto TEXT,
          signaling_src TEXT,
          signaling_dst TEXT,
          media_src TEXT,
          media_dst TEXT,
          start_ts REAL,
          end_ts REAL,
          duration REAL,
          pkts INTEGER,
          pacing_ms REAL,
          turn INTEGER DEFAULT 0,
          risk INTEGER DEFAULT 0,
          meta TEXT
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          call_row INTEGER,
          ts REAL,
          reason TEXT,
          risk INTEGER
        );
        """)
        conn.commit()
        conn.close()

# In-memory trackers
# Map candidate flow key -> deque of timestamps
flow_ts = defaultdict(lambda: deque(maxlen=5000))
# Map synthetic_call_key -> assembled call record
active_calls = {}
short_call_counter = defaultdict(int)  # entity -> short call count (sliding window not implemented in prototype)

def now_ts():
    return time.time()

def ip_pair(pkt):
    return (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport)

# Simple risk computation
def compute_risk(call):
    score = 0
    if call['duration'] < SHORT_CALL_SEC:
        score += 10
    if call['pkts'] < 50:
        score += 10
    # TURN hint
    if call.get('turn', False):
        score += 15
    # frequency heuristic: if this src had several short calls, increase risk
    sc = short_call_counter.get(call['media_src'], 0)
    if sc >= SHORT_CALL_COUNT_THRESHOLD:
        score += 20
    # cap
    if score > 100:
        score = 100
    return score

def persist_call(call):
    with LOCK:
        conn = sqlite3.connect(DB)
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO calls (call_id, proto, signaling_src, signaling_dst, media_src, media_dst, start_ts, end_ts, duration, pkts, pacing_ms, turn, risk, meta)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);
        """, (
            call.get('call_id'),
            call.get('proto'),
            call.get('signaling_src'),
            call.get('signaling_dst'),
            call.get('media_src'),
            call.get('media_dst'),
            call.get('start_ts'),
            call.get('end_ts'),
            call.get('duration'),
            call.get('pkts'),
            call.get('pacing_ms'),
            int(call.get('turn', False)),
            call.get('risk'),
            json.dumps(call.get('meta', {}))
        ))
        rowid = cur.lastrowid
        conn.commit()
        conn.close()

        # alert threshold
        if call.get('risk', 0) >= 50:
            with LOCK:
                conn = sqlite3.connect(DB)
                cur = conn.cursor()
                cur.execute("INSERT INTO alerts (call_row, ts, reason, risk) VALUES (?,?,?,?)",
                            (rowid, now_ts(), "High risk call (heuristic)", call.get('risk')))
                conn.commit()
                conn.close()

# Heuristic: detect "RTP-like" flows using timing of UDP payloads
def process_udp_packet(pkt_ts, pkt):
    if not pkt.haslayer(UDP):
        return
    # SIP detection (very simple): look for ASCII INVITE or BYE in UDP payload on port 5060
    try:
        payload = bytes(pkt[UDP].payload)
        if payload and (b"INVITE " in payload or b"BYE " in payload or b"REGISTER " in payload):
            # record signaling metadata
            call_id = None
            # attempt to extract Call-ID loosely (naive)
            try:
                payload_text = payload.decode(errors='ignore')
                for line in payload_text.splitlines():
                    if line.lower().startswith("call-id:"):
                        call_id = line.split(":",1)[1].strip()
                        break
            except Exception:
                pass
            # store a signaling hint (not a full SIP parser)
            key = f"sip-{pkt[IP].src}-{pkt[IP].dst}-{pkt[UDP].sport}-{pkt[UDP].dport}-{int(pkt_ts)}"
            active_calls[key] = {
                'call_id': call_id,
                'proto': 'SIP',
                'signaling_src': pkt[IP].src,
                'signaling_dst': pkt[IP].dst,
                'media_src': None,
                'media_dst': None,
                'start_ts': pkt_ts,
                'end_ts': pkt_ts,
                'pkts': 0,
                'pacing_ms': None,
                'turn': False,
                'meta': {'sip_sample': payload_text[:512] if isinstance(payload_text, str) else None}
            }
            return
    except Exception:
        pass

    # track flow timestamps
    key = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport)
    flow_ts[key].append(pkt_ts)
    # analyze if flow looks RTP-like after enough samples
    if len(flow_ts[key]) >= RTP_MIN_PKTS:
        ts_list = list(flow_ts[key])
        gaps = [ (ts_list[i+1]-ts_list[i]) for i in range(len(ts_list)-1) if ts_list[i+1]-ts_list[i] < 1.0 ]
        if len(gaps) < RTP_MIN_PKTS/2:
            # not enough steady traffic
            return
        mean_gap = sum(gaps)/len(gaps)
        pacing_ms = mean_gap*1000.0
        # packet size heuristic
        payload_len = len(bytes(pkt[UDP].payload))
        # basic RTP-like check: pacing in allowed window and payload size reasonable
        if RTP_PACING_MS_RANGE[0] <= pacing_ms <= RTP_PACING_MS_RANGE[1] and payload_len >= 50:
            # associate to nearest SIP-call if exists (within 30s)
            # otherwise create synthetic call
            matched = None
            nowt = pkt_ts
            for k,v in list(active_calls.items()):
                if v['proto']=='SIP' and nowt - v['start_ts'] < 60:
                    matched = k
                    break
            if matched:
                call = active_calls[matched]
            else:
                # synthetic
                matched = f"rtp-{pkt[IP].src}-{pkt[IP].dst}-{pkt[UDP].sport}-{pkt[UDP].dport}"
                call = active_calls.get(matched, {
                    'call_id': None,
                    'proto': 'RTP',
                    'signaling_src': None,
                    'signaling_dst': None,
                    'media_src': pkt[IP].src,
                    'media_dst': pkt[IP].dst,
                    'start_ts': pkt_ts,
                    'end_ts': pkt_ts,
                    'pkts': 0,
                    'pacing_ms': None,
                    'turn': False,
                    'meta': {}
                })
            # update call
            call['end_ts'] = pkt_ts
            call['pkts'] += 1
            call['media_src'] = pkt[IP].src
            call['media_dst'] = pkt[IP].dst
            call['pacing_ms'] = pacing_ms
            active_calls[matched] = call

def flush_old_calls(timeout=5.0):
    """Periodically flush calls that have been idle for timeout seconds"""
    while True:
        nowt = now_ts()
        to_remove = []
        for k,v in list(active_calls.items()):
            if nowt - v['end_ts'] > timeout:
                # finalize call
                duration = v['end_ts'] - v['start_ts']
                v['duration'] = duration
                # compute risk
                risk = compute_risk(v)
                v['risk'] = risk
                # persist only if meets minimal criteria
                if v['proto']=='RTP' and v['pkts'] >= 10:
                    persist_call(v)
                    # short-call counter
                    if v['duration'] < SHORT_CALL_SEC:
                        short_call_counter[v.get('media_src','unknown')] += 1
                elif v['proto']=='SIP':
                    # SIP-only event; may not have RTP
                    persist_call(v)
                to_remove.append(k)
        for k in to_remove:
            try:
                del active_calls[k]
            except KeyError:
                pass
        time.sleep(1.0)

# Scapy packet callback
def pkt_cb(pkt):
    try:
        if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
            return
        ts = now_ts()
        process_udp_packet(ts, pkt)
    except Exception as e:
        print("pkt_cb error:", e)

def main(args):
    init_db()
    # start flusher thread
    th = threading.Thread(target=flush_old_calls, daemon=True)
    th.start()

    if args.pcap:
        print("[*] Reading pcap:", args.pcap)
        sniff(offline=args.pcap, prn=pkt_cb, store=False)
    else:
        print("[*] Sniffing on interface:", args.interface)
        sniff(iface=args.interface, prn=pkt_cb, store=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", "-i", default="eth0", help="interface to sniff (requires root)")
    parser.add_argument("--pcap", "-r", help="read packets from pcap file instead of live")
    args = parser.parse_args()
    main(args)
