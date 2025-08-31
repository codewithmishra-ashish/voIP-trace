#!/usr/bin/env python3
import sys
import logging
import time
import threading
from datetime import datetime
from collections import deque

from scapy.all import sniff, UDP, Raw, IP, get_if_list
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

console = Console()

# Track active call flows (seen connections)
active_calls = {}
recent_events = deque(maxlen=50)
lock = threading.RLock()

# --- Protocol Heuristics ---

def is_stun(payload: bytes) -> bool:
    return len(payload) >= 20 and payload[4:8] == b"\x21\x12\xa4\x42"

def stun_msg_type(payload: bytes) -> int:
    return int.from_bytes(payload[0:2], "big")

def is_dtls(payload: bytes) -> bool:
    return len(payload) >= 13 and (20 <= payload[0] <= 64) and payload[1:3] in [b"\xfe\xff", b"\xfe\xfd"]

def looks_like_rtp(payload: bytes) -> bool:
    return len(payload) >= 12 and (payload[0] >> 6) == 2 and 0 <= (payload[1] & 0x7F) <= 127

# --- STUN Parser (for XOR-MAPPED-ADDRESS) ---

def parse_stun(payload: bytes):
    try:
        magic_cookie = payload[4:8]
        length = int.from_bytes(payload[2:4], "big")
        offset = 20
        attrs = {}
        while offset < 20 + length:
            atype = int.from_bytes(payload[offset:offset+2], "big")
            alen = int.from_bytes(payload[offset+2:offset+4], "big")
            aval = payload[offset+4:offset+4+alen]
            offset += 4 + alen
            if offset % 4:
                offset += 4 - (offset % 4)
            if atype == 0x0020:  # XOR-MAPPED-ADDRESS
                family = aval[1]
                port = int.from_bytes(aval[2:4], "big") ^ int.from_bytes(magic_cookie[:2], "big")
                if family == 0x01:  # IPv4
                    ip_raw = bytearray(aval[4:8])
                    for i in range(4):
                        ip_raw[i] ^= magic_cookie[i]
                    ip = ".".join(map(str, ip_raw))
                    attrs["XOR-MAPPED-ADDRESS"] = {"ip": ip, "port": port}
        return attrs
    except Exception:
        return None

# --- Helpers ---

def normalize_flow(ip, sport, dst, dport):
    return tuple(sorted([(ip, sport), (dst, dport)]))

def log_event(event, details, severity="info"):
    now = datetime.now().isoformat()
    evt = {"time": now, "event": event, "details": details, "severity": severity}
    with lock:
        recent_events.append(evt)

# --- Packet Handler ---

def pkt_cb(pkt):
    if IP in pkt and UDP in pkt and Raw in pkt:
        ip, sport = pkt[IP].src, pkt[UDP].sport
        dst, dport = pkt[IP].dst, pkt[UDP].dport
        flow = normalize_flow(ip, sport, dst, dport)
        payload = bytes(pkt[Raw].load)

        proto, mapped, direction = None, None, None
        if is_stun(payload):
            msg_type = stun_msg_type(payload)
            proto = "STUN"
            if msg_type == 0x0001:
                direction = "REQ"
            elif msg_type == 0x0101:
                direction = "RESP"
                stun_info = parse_stun(payload)
                if stun_info and "XOR-MAPPED-ADDRESS" in stun_info:
                    mapped = stun_info["XOR-MAPPED-ADDRESS"]
                    log_event("STUN-MAPPED", {"src": ip, "dst": dst, "mapped": mapped}, severity="warning")
        elif is_dtls(payload):
            proto = "DTLS"
        elif looks_like_rtp(payload):
            proto = "RTP/SRTP"

        if proto:
            now = time.time()
            with lock:
                if flow not in active_calls:
                    active_calls[flow] = {
                        "proto": proto,
                        "first_seen": now,
                        "last_seen": now,
                        "mapped": mapped,
                        "direction": direction
                    }
                    log_event(proto, {"flow": flow, "status": "new", "direction": direction})
                else:
                    f = active_calls[flow]
                    f["last_seen"] = now
                    if mapped:
                        f["mapped"] = mapped
                    if direction:
                        f["direction"] = direction
                    log_event(proto, {"flow": flow, "status": "update", "direction": direction})

# --- UI Rendering ---

def render_ui():
    flows_table = Table(title="[bold cyan]Active Flows[/bold cyan]", expand=True)
    flows_table.add_column("Flow")
    flows_table.add_column("Proto")
    flows_table.add_column("Direction")
    flows_table.add_column("Mapped")
    flows_table.add_column("Age (s)", justify="right")

    now = time.time()
    with lock:
        for flow, meta in active_calls.items():
            flow_str = f"{flow[0][0]}:{flow[0][1]} <-> {flow[1][0]}:{flow[1][1]}"
            proto = meta.get("proto", "-")
            direction = meta.get("direction", "-")
            mapped = f"{meta['mapped']['ip']}:{meta['mapped']['port']}" if meta.get("mapped") else "-"
            age = int(now - meta.get("first_seen", now))
            flows_table.add_row(flow_str, proto, direction, mapped, str(age))

        ev_lines = []
        for e in list(recent_events)[-15:]:
            sev, line = e.get("severity", "info"), f"{e['time']} {e['event']} {e['details']}"
            style = {"warning": "yellow", "error": "red"}.get(sev, "cyan")
            ev_lines.append(Text(line, style=style))

    ev_panel = Panel(Text("\n").join(ev_lines) if ev_lines else Text("No events yet"),
                     title="Recent Events", border_style="magenta", height=12)

    layout = Table.grid(expand=True)
    layout.add_row(flows_table)
    layout.add_row(ev_panel)
    return layout

# --- Sniffing + UI Threads ---

def sniff_thread(iface):
    sniff(iface=iface, filter="udp", prn=pkt_cb, store=False, promisc=True)

def ui_thread():
    with Live(render_ui(), refresh_per_second=1, screen=False) as live:
        while True:
            time.sleep(1)
            live.update(render_ui())

# --- Interface Selection ---

def list_ifaces():
    ifaces = get_if_list()
    print("[*] Available interfaces:")
    for i, iface in enumerate(ifaces):
        print(f"  {i}: {iface}")
    return ifaces

def main():
    ifaces = list_ifaces()
    choice = input("\n[?] Enter interface index, name, or 'all': ").strip()
    if choice == "all":
        iface = None
    elif choice.isdigit():
        iface = ifaces[int(choice)]
    else:
        iface = choice

    console.print(f"[*] Sniffing on: {iface if iface else 'ALL INTERFACES'}")
    console.print("[*] Press Ctrl+C to stop.\n")

    t_sniff = threading.Thread(target=sniff_thread, args=(iface,), daemon=True)
    t_sniff.start()

    try:
        ui_thread()
    except KeyboardInterrupt:
        console.print("\n[red][!] Stopped by user[/red]")
        sys.exit(0)

if __name__ == "__main__":
    main()
