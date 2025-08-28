import sys
import logging
from datetime import datetime
from scapy.all import sniff, UDP, Raw, IP, get_if_list

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Track active call flows (seen connections)
active_calls = {}

# --- Protocol Heuristics ---

def is_stun(payload: bytes) -> bool:
    if len(payload) < 20:
        return False
    magic_cookie = payload[4:8]
    return magic_cookie == b"\x21\x12\xa4\x42"

def stun_msg_type(payload: bytes) -> int:
    return int.from_bytes(payload[0:2], "big")

def is_dtls(payload: bytes) -> bool:
    if len(payload) < 13:
        return False
    content_type = payload[0]
    version = payload[1:3]
    return content_type in range(20, 65) and version in [b"\xfe\xff", b"\xfe\xfd"]

def looks_like_rtp(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    b = payload[0]
    version = b >> 6
    payload_type = payload[1] & 0x7F
    return version == 2 and 0 <= payload_type <= 127

# --- STUN Parser (for XOR-MAPPED-ADDRESS) ---

def parse_stun(payload: bytes):
    try:
        msg_type = int.from_bytes(payload[0:2], "big")
        length = int.from_bytes(payload[2:4], "big")
        magic_cookie = payload[4:8]
        trans_id = payload[8:20]

        attrs = {}
        offset = 20
        while offset < 20 + length:
            atype = int.from_bytes(payload[offset:offset+2], "big")
            alen = int.from_bytes(payload[offset+2:offset+4], "big")
            aval = payload[offset+4:offset+4+alen]
            offset += 4 + alen
            if offset % 4 != 0:
                offset += 4 - (offset % 4)

            # XOR-MAPPED-ADDRESS
            if atype == 0x0020:  
                family = aval[1]
                port = int.from_bytes(aval[2:4], "big") ^ (int.from_bytes(magic_cookie[:2], "big"))
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
    """Treat A<->B as same flow regardless of direction."""
    return tuple(sorted([(ip, sport), (dst, dport)]))

def log_event(event, details):
    now = datetime.now().isoformat()
    print({
        "time": now,
        "event": event,
        "details": details
    })

# --- Packet Handler ---

def pkt_cb(pkt):
    if IP in pkt and UDP in pkt and Raw in pkt:
        ip, sport = pkt[IP].src, pkt[UDP].sport
        dst, dport = pkt[IP].dst, pkt[UDP].dport
        flow = normalize_flow(ip, sport, dst, dport)
        payload = bytes(pkt[Raw].load)

        proto = None
        if is_stun(payload):
            msg_type = stun_msg_type(payload)
            if msg_type == 0x0001:  # Binding Request
                proto = "STUN-REQ"
            elif msg_type == 0x0101:  # Binding Success Response
                proto = "STUN-RESP"
                stun_info = parse_stun(payload)
                if stun_info and "XOR-MAPPED-ADDRESS" in stun_info:
                    log_event("STUN-MAPPED", {
                        "src": ip,
                        "dst": dst,
                        "mapped": stun_info["XOR-MAPPED-ADDRESS"]
                    })
        elif is_dtls(payload):
            proto = "DTLS"
        elif looks_like_rtp(payload):
            proto = "RTP/SRTP"

        if proto:
            if flow not in active_calls:
                active_calls[flow] = proto
                log_event(proto, {"flow": flow, "status": "new"})

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
        iface = None  # scapy sniff on all
    elif choice.isdigit():
        iface = ifaces[int(choice)]
    else:
        iface = choice

    print(f"[*] Sniffing on: {iface if iface else 'ALL INTERFACES'}")
    print("[*] Press Ctrl+C to stop.\n")

    sniff(iface=iface, filter="udp", prn=pkt_cb, store=False, promisc=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
        sys.exit(0)
