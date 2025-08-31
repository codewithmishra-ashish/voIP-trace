#!/usr/bin/env python3
import os
import sys
import time
import json
import threading
import queue
import re
import logging
import ctypes
from datetime import datetime, timezone
from collections import defaultdict, deque
from scapy.all import sniff, UDP, TCP, Raw, IP, IPv6, get_if_list
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Suppress Scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
console = Console()
event_queue = queue.Queue()

# ---------------- Config ----------------
VOIP_UDP_PORTS = {5060, 3478, 3479, 5349, 19302}  # Added TURN port
VOIP_TCP_PORTS = {5060, 5061}
MEDIA_PT_RANGE = range(0, 128)
FLOW_IDLE_TIMEOUT = 120
CALL_IDLE_TIMEOUT = 300
ALERT_SCORE_THRESHOLD = 70
BLACKLIST_IPS = set()  # Replace with real blacklist
RELAY_IPS = {"172.217.0.0/16", "31.13.64.0/18"}  # Example WhatsApp/Meta ranges
EVENTS_TO_SHOW = 15  # Limit to 15 recent events

# ---------------- State -----------------
flows = {}
calls = {}
recent_events = deque(maxlen=100)
flow_to_call = {}  # Map flows to call IDs

def now_iso(): return datetime.now(timezone.utc).isoformat()

def log_event(et, details):
    evt = {"time": now_iso(), "event": et, "details": details}
    event_queue.put(evt)
    recent_events.append(evt)

# -------------- Utilities ---------------
def normalize_5tuple(pkt, l4):
    ip = pkt[IP] if IP in pkt else pkt[IPv6]
    return ("IPv6" if IPv6 in pkt else "IPv4",
            ip.src, l4.sport, ip.dst, l4.dport,
            "UDP" if UDP in pkt else "TCP")

def other_dir(t5):
    fam, src, sport, dst, dport, proto = t5
    return (fam, dst, dport, src, sport, proto)

def is_relay_ip(ip):
    from ipaddress import ip_network, ip_address
    try:
        for net in RELAY_IPS:
            if '/' in net and ip_address(ip) in ip_network(net):
                return True
    except:
        pass
    return ip in RELAY_IPS

# --- SIP ---
SIP_HDR_RE = re.compile(r"^([A-Za-z\-]+):\s*(.+)$")
def is_sip_text(payload: bytes) -> bool:
    try:
        head = payload[:8].decode("ascii", "ignore")
        return any(head.startswith(p) for p in
                   ("INVITE", "REGISTER", "ACK", "CANCEL", "BYE", "OPTIONS", "MESSAGE", "SIP/2.0"))
    except: return False

def parse_sip(payload: bytes):
    try:
        text = payload.decode("utf-8", "ignore")
        head, _, _ = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        if not lines: return None
        start = lines[0].strip()
        hdrs = {}
        for line in lines[1:]:
            m = SIP_HDR_RE.match(line)
            if m:
                k, v = m.group(1).lower(), m.group(2).strip()
                hdrs[k] = v
        return {"start_line": start, "headers": hdrs}
    except: return None

# --- STUN / TURN / RTP / DTLS ---
def is_stun(payload: bytes) -> bool:
    return len(payload) >= 20 and payload[4:8] == b"\x21\x12\xa4\x42"

def stun_msg_type(payload: bytes) -> int:
    return int.from_bytes(payload[0:2], "big")

def parse_stun(payload: bytes):
    try:
        msg_type = stun_msg_type(payload)
        length = int.from_bytes(payload[2:4], "big")
        cookie = payload[4:8]
        trans_id = payload[8:20]
        attrs = {}
        off, end = 20, 20 + length
        while off + 4 <= end:
            atype = int.from_bytes(payload[off:off+2], "big")
            alen = int.from_bytes(payload[off+2:off+4], "big")
            aval = payload[off+4:off+4+alen]
            off += 4 + alen
            if off % 4: off += (4 - (off % 4))
            if atype == 0x0020 and alen >= 8:  # XOR-MAPPED-ADDRESS
                fam = aval[1]
                port = int.from_bytes(aval[2:4], "big") ^ int.from_bytes(cookie[:2], "big")
                if fam == 0x01:
                    ipraw = bytearray(aval[4:8])
                    for i in range(4): ipraw[i] ^= cookie[i]
                    attrs["xor-mapped"] = {"ip": ".".join(map(str, ipraw)), "port": port}
                elif fam == 0x02:
                    ipraw = bytearray(aval[4:20])
                    for i in range(16): ipraw[i] ^= cookie[i % 4]
                    from ipaddress import ip_address
                    attrs["xor-mapped"] = {"ip": str(ip_address(ipraw)), "port": port}
            elif atype == 0x0001 and alen >= 8:  # MAPPED-ADDRESS
                fam = aval[1]
                port = int.from_bytes(aval[2:4], "big")
                if fam == 0x01:
                    attrs["mapped"] = {"ip": ".".join(map(str, aval[4:8])), "port": port}
                elif fam == 0x02:
                    from ipaddress import ip_address
                    attrs["mapped"] = {"ip": str(ip_address(aval[4:20])), "port": port}
            elif atype == 0x0016 and alen >= 8:  # RELAYED-ADDRESS
                fam = aval[1]
                port = int.from_bytes(aval[2:4], "big")
                if fam == 0x01:
                    attrs["relayed"] = {"ip": ".".join(map(str, aval[4:8])), "port": port}
                elif fam == 0x02:
                    from ipaddress import ip_address
                    attrs["relayed"] = {"ip": str(ip_address(aval[4:20])), "port": port}
        return {"msg_type": msg_type, "trans_id": trans_id.hex(), "attrs": attrs}
    except: return None

def looks_like_rtp(payload: bytes) -> bool:
    if len(payload) < 12: return False
    v, pt = payload[0] >> 6, payload[1] & 0x7F
    return v == 2 and pt in MEDIA_PT_RANGE

def is_dtls(payload: bytes) -> bool:
    return len(payload) >= 13 and (20 <= payload[0] <= 64) and (payload[1:3] in (b"\xfe\xff", b"\xfe\xfd"))

# -------------- Models ------------------
class Flow:
    def __init__(self, key):
        self.key = key
        self.roles = set()
        self.last_ts = time.time()
        self.packets = 0
        self.bytes = 0
        self.mapped_addr = None
        self.call_id = None

class Call:
    def __init__(self, cid):
        self.cid = cid
        self.created = time.time()
        self.updated = self.created
        self.flows = set()
    def touch(self):
        self.updated = time.time()
        return self

# -------------- Packet Handler ----------
def handle_packet(pkt):
    console.print(f"[debug] Received packet: {pkt.summary()} from {pkt.getlayer(IP).src if IP in pkt else 'N/A'} to {pkt.getlayer(IP).dst if IP in pkt else 'N/A'}")
    l4 = pkt[UDP] if UDP in pkt else (pkt[TCP] if TCP in pkt else None)
    if (IP not in pkt and IPv6 not in pkt) or l4 is None or Raw not in pkt: 
        console.print("[debug] Packet filtered out due to layer check")
        return
    key = normalize_5tuple(pkt, l4)
    rev = other_dir(key)
    if key not in flows: flows[key] = Flow(key)
    f = flows[key]
    f.last_ts = time.time()
    f.packets += 1
    f.bytes += len(pkt[Raw].load)
    payload = bytes(pkt[Raw].load)
    fam, src, sport, dst, dport, proto = key

    if is_sip_text(payload):
        sip = parse_sip(payload)
        if sip:
            cid = sip["headers"].get("call-id", "unknown")
            c = calls.get(cid) or Call(cid)
            c.flows.add(key)
            calls[cid] = c.touch()
            f.call_id = cid
            flow_to_call[key] = cid
            log_event("SIP", {"call_id": cid, "start": sip["start_line"], "flow": key})
            if is_relay_ip(src) or is_relay_ip(dst):
                log_event("ALERT", {"reason": "Relay server detected", "flow": key})
    elif is_stun(payload):
        stun = parse_stun(payload)
        if stun and stun["attrs"]:
            f.mapped_addr = stun["attrs"].get("xor-mapped") or stun["attrs"].get("mapped") or stun["attrs"].get("relayed")
            log_event("STUN", {"flow": key, "attrs": stun["attrs"], "trans_id": stun["trans_id"]})
            if f.mapped_addr and not is_relay_ip(f.mapped_addr["ip"]):
                log_event("ALERT", {"reason": "Endpoint IP recovered", "flow": key, "endpoint": f.mapped_addr})
            if is_relay_ip(src) or is_relay_ip(dst):
                log_event("ALERT", {"reason": "Relay server detected", "flow": key})
    elif is_dtls(payload):
        log_event("DTLS", {"flow": key})
        if is_relay_ip(src) or is_relay_ip(dst):
            log_event("ALERT", {"reason": "Relay server detected", "flow": key})
    elif looks_like_rtp(payload):
        log_event("RTP", {"flow": key})
        if is_relay_ip(src) or is_relay_ip(dst):
            log_event("ALERT", {"reason": "Relay server detected", "flow": key})

# ---------------- Cleanup Thread --------
def cleanup_thread():
    while True:
        time.sleep(10)
        now = time.time()
        for key, f in list(flows.items()):
            if now - f.last_ts > FLOW_IDLE_TIMEOUT:
                log_event("FLOW_END", {
                    "flow": key,
                    "packets": f.packets,
                    "bytes": f.bytes,
                    "duration": now - f.last_ts,
                    "mapped_addr": f.mapped_addr
                })
                if f.packets < 10 or (now - f.last_ts) < 10:
                    log_event("ALERT", {"reason": "Suspicious short flow", "flow": key})
                del flows[key]
        for cid, c in list(calls.items()):
            if now - c.updated > CALL_IDLE_TIMEOUT:
                log_event("CALL_END", {
                    "call_id": cid,
                    "duration": now - c.created,
                    "flows": list(c.flows)
                })
                del calls[cid]

# ---------------- UI --------------------
def render_ui():
    while not event_queue.empty():
        event = event_queue.get()
        recent_events.append(event)
    layout = Table.grid(expand=True)
    layout.add_column(justify="center", ratio=1)
    layout.add_column(justify="center", ratio=1)
    
    # Calls
    calls_table = Table(title="[bold green]Active Calls[/bold green]", expand=True)
    calls_table.add_column("Call-ID")
    calls_table.add_column("Flows")
    calls_table.add_column("Duration")
    for cid, c in calls.items():
        flows_str = ", ".join(f"{f[1]}:{f[2]}->{f[3]}:{f[4]}" for f in c.flows)
        calls_table.add_row(cid, flows_str, f"{int(time.time() - c.created)}s")
    
    # Flows (only those with mapped endpoints)
    flows_table = Table(title="[bold blue]Active Flows with Endpoints[/bold blue]", expand=True)
    flows_table.add_column("Flow")
    flows_table.add_column("Mapped Endpoint")
    flows_table.add_column("Packets")
    for key, f in flows.items():
        if f.mapped_addr:
            flow_str = f"{key[1]}:{key[2]}->{key[3]}:{key[4]} ({key[5]})"
            mapped = f"{f.mapped_addr['ip']}:{f.mapped_addr['port']}"
            flows_table.add_row(flow_str, mapped, str(f.packets))
    
    # Events (fixed height, limited to 15 recent)
    ev_panel = Panel.fit("\n".join([
        f"[cyan]{e['time']}[/cyan] [yellow]{e['event']}[/yellow] {json.dumps(e['details'])}"
        for e in list(recent_events)[-EVENTS_TO_SHOW:]
    ]), title=f"Events (Last {EVENTS_TO_SHOW})", border_style="magenta", height=10)
    
    layout.add_row(calls_table, flows_table)
    layout.add_row(ev_panel)
    return layout

# ---------------- Main ------------------
def sniffer_thread(iface):
    sniff(iface=iface, filter="udp port 3478 or udp port 3479 or tcp port 443", prn=handle_packet, store=False, promisc=False)

def list_ifaces():
    ifaces = get_if_list()
    console.print("[*] Interfaces:")
    for i, iface in enumerate(ifaces):
        console.print(f"  {i}: {iface}")
    return ifaces

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        return False

def main():
    if sys.platform == "win32" and not is_admin():
        console.print("[red] This script requires administrative privileges on Windows. Please run as Administrator.[/red]")
        sys.exit(1)
    elif sys.platform != "win32" and os.geteuid() != 0:
        console.print("[red] This script requires root privileges on Unix-like systems. Please run with sudo.[/red]")
        sys.exit(1)
    
    ifaces = list_ifaces()
    choice = input("\n[?] Enter interface index, name, or 'all': ").strip()
    iface = None if choice == "all" else (ifaces[int(choice)] if choice.isdigit() and int(choice) < len(ifaces) else choice)
    if iface and iface not in ifaces:
        console.print("[red] Invalid interface. Using first available interface.[/red]")
        iface = ifaces[0] if ifaces else None
    console.print(f"[*] Sniffing on: {iface if iface else 'ALL INTERFACES'}")
    t = threading.Thread(target=sniffer_thread, args=(iface,), daemon=True)
    t.start()
    cleaner = threading.Thread(target=cleanup_thread, daemon=True)
    cleaner.start()
    with Live(render_ui(), refresh_per_second=2, screen=True) as live:
        while True:
            try:
                live.update(render_ui())
                time.sleep(1)
            except KeyboardInterrupt:
                console.print("[red]\nStopped.")
                sys.exit(0)

if __name__ == "__main__":
    main()