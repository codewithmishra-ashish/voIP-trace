# VoIP / STUN / RTP Flow Sniffer

A Python-based command-line tool to **detect and visualize UDP flows** commonly used in VoIP/WebRTC calls.  
It inspects traffic for **STUN**, **DTLS**, and **RTP/SRTP** packets and shows live updates in a terminal dashboard.

---

## ✨ Features
- Detects and classifies:
  - **STUN** (with XOR-MAPPED-ADDRESS parsing to reveal public IP/port mappings)
  - **DTLS** (used for SRTP key exchange)
  - **RTP/SRTP** (voice/video streams)
- Tracks **active flows** with:
  - Protocol type  
  - Direction (request/response when applicable)  
  - Public mapped addresses (from STUN responses)  
  - Flow age in seconds
- Live **TUI (Text User Interface)** using [rich](https://github.com/Textualize/rich)
- Keeps a rolling history of the **most recent 50 events**

---

## 📦 Requirements

- Python **3.8+**
- [Scapy](https://scapy.net/) (packet sniffing)
- [rich](https://github.com/Textualize/rich) (UI rendering)

Install dependencies with:

```bash
pip install scapy rich
```

## 🚀 Usage

Clone or download this repository.

Save the script (e.g., voip_sniffer.py).

Run it:

```bash
sudo python3 voip_sniffer.py
```

On startup, you’ll see a list of available interfaces:

[*] Available interfaces:
  0: eth0
  1: wlan0
  2: lo


Select an interface by entering:

Its index (0, 1, etc.)

Its name (eth0, wlan0, etc.)

Or type all to sniff on all interfaces.

📊 Example Output
```bash
Active Flows
──────────────────────────────────────────────
Flow                  Proto   Direction   Mapped         Age (s)
192.168.1.10:54321 ↔ 34.102.1.2:3478   STUN    RESP    103.45.67.89:6000     12
192.168.1.10:60002 ↔ 34.102.1.2:5004   RTP/SRTP   -     -                    8

Recent Events
──────────────────────────────────────────────
2025-08-31T14:52:13 STUN-MAPPED {'src': '192.168.1.10', 'dst': '34.102.1.2', 'mapped': {'ip': '103.45.67.89', 'port': 6000}}
2025-08-31T14:52:15 RTP/SRTP {'flow': (('192.168.1.10', 60002), ('34.102.1.2', 5004)), 'status': 'new'}
```

## ⚠️ Disclaimer

This tool is intended for research, debugging, and educational purposes only.
Do not use it for unauthorized packet sniffing, surveillance, or intrusion. The author is not responsible for misuse.

🛠️ Roadmap

 Export captured flows to JSON/CSV

 Support SIP message detection

 Better handling of RTP stream stats (packet loss, jitter, etc.)
