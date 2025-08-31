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
