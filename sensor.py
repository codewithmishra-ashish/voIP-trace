import sys
import logging
from datetime import datetime
from scapy.all import sniff, UDP, Raw, IP, get_if_list

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Track active call flows
active_calls = {}

# --- Protocol Heuristics ---

def is_stun(payload: bytes) -> bool:
    """Check if payload looks like STUN (used in VoIP NAT traversal)."""
    if len(payload) < 20:
        return False
    msg_type = int.from_bytes(payload[0:2], "big")
    magic_cookie = payload[4:8]
    return (
        msg_type in [0x0001, 0x0101] and
        magic_cookie == b"\x21\x12\xa4\x42"
    )

def is_dtls(payload: bytes) -> bool:
    """Check if payload looks like DTLS handshake (VoIP encryption)."""
    if len(payload) < 13:
        return False
    content_type = payload[0]
    version = payload[1:3]
    return content_type in range(20, 65) and version in [b"\xfe\xff", b"\xfe\xfd"]

def looks_like_rtp(payload: bytes) -> bool:
    """Check if payload looks like RTP/SRTP (media streaming)."""
    if len(payload) < 12:
        return False
    b = payload[0]
    version = b >> 6
    payload_type = payload[1] & 0x7F
    return version == 2 and 0 <= payload_type <= 127

# --- Packet Handler ---

def pkt_cb(pkt):
    """Handle each captured packet."""
    if IP in pkt and UDP in pkt and Raw in pkt:
        ip, sport = pkt[IP].src, pkt[UDP].sport
        dst, dport = pkt[IP].dst, pkt[UDP].dport
        flow = (ip, sport, dst, dport)
        payload = bytes(pkt[Raw].load)

        now = datetime.now().strftime("%H:%M:%S")

        if is_stun(payload):
            if flow not in active_calls:
                print(f"[{now}] [STUN] {ip}:{sport} -> {dst}:{dport}")
                active_calls[flow] = "STUN"

        elif is_dtls(payload):
            if flow not in active_calls:
                print(f"[{now}] [DTLS] {ip}:{sport} <-> {dst}:{dport} (secure handshake)")
                active_calls[flow] = "DTLS"

        elif looks_like_rtp(payload):
            if flow in active_calls and active_calls[flow] in ["DTLS", "STUN"]:
                print(f"[{now}] [RTP/SRTP] {ip}:{sport} <-> {dst}:{dport} (media flowing)")

# --- Interface Selection ---

def list_ifaces():
    """List available interfaces."""
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

    # Only capture UDP over IP (reduces noise, avoids warnings)
    sniff(iface=iface, filter="udp and ip", prn=pkt_cb, store=False)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
        sys.exit(0)
