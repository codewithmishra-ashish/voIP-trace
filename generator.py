#!/usr/bin/env python3
"""
generator.py
Generate a synthetic SIP INVITE + RTP-like UDP stream to localhost for testing the sensor.
"""

import socket, time, threading
from datetime import datetime

# Config
LOCAL = "127.0.0.1"
SIP_SRC_PORT = 5060
SIP_DST_PORT = 5062  # arbitrary
RTP_SRC_PORT = 40000
RTP_DST_PORT = 40002

def send_sip_invite():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sip_msg = "\r\n".join([
        "INVITE sip:target@example.com SIP/2.0",
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1",
        "From: <sip:caller@example.com>;tag=1234",
        "To: <sip:target@example.com>",
        "Call-ID: testcall-001@example.com",
        "CSeq: 1 INVITE",
        "Contact: <sip:caller@127.0.0.1>",
        "Max-Forwards: 70",
        "User-Agent: TestGen/1.0",
        "", ""
    ])
    s.sendto(sip_msg.encode(), (LOCAL, SIP_DST_PORT))
    print("[generator] sent INVITE")
    s.close()

def send_rtp(duration_s=15, ptime_ms=20):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'\x80' + b'\x00' * 160  # fake RTP-like payload
    interval = ptime_ms / 1000.0
    end = time.time() + duration_s
    cnt = 0
    while time.time() < end:
        sock.sendto(payload, (LOCAL, RTP_DST_PORT))
        cnt += 1
        time.sleep(interval)
    print("[generator] sent %d RTP packets" % cnt)
    sock.close()

if __name__ == "__main__":
    # send an INVITE
    send_sip_invite()
    time.sleep(0.5)
    # spawn RTP thread
    send_rtp(duration_s=10, ptime_ms=20)
    # send BYE (optional)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bye = "BYE sip:target@example.com SIP/2.0\r\nCall-ID: testcall-001@example.com\r\n\r\n"
    s.sendto(bye.encode(), (LOCAL, SIP_DST_PORT))
    s.close()
    print("[generator] done")
