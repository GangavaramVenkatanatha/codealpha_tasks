# 🔍 Python Network Sniffer

A raw-socket packet analyser built with **zero external dependencies** — pure Python standard library. Captures live network traffic and decodes IP, TCP, UDP, and ICMP layers with a colour-coded terminal output and a summary report on exit.

> Built as Task 1 of a Cybersecurity lab assignment.

---

## Features

- **Cross-platform** — works on Windows, Linux, and macOS
- **No third-party libraries** — uses only `socket`, `struct`, `argparse`, and `collections`
- **Protocol support** — IPv4, TCP, UDP, ICMP, IGMP, OSPF
- **Layer-by-layer decoding** — Ethernet → IP → Transport → Payload
- **Well-known port labels** — automatically names ports (HTTP, HTTPS, DNS, SSH, MySQL, etc.)
- **Colour-coded output** — TCP in cyan, UDP in green, ICMP in yellow
- **CLI filters** — filter by protocol, IP address, or port number
- **Exit summary** — protocol breakdown, top source IPs, most-used ports

---

## Requirements

- Python 3.8+
- **Administrator / root privileges** (raw sockets require elevated access)
- No `pip install` needed

---

## Usage

```bash
# Linux / macOS
sudo python3 network_sniffer.py

# Windows — run terminal as Administrator
python network_sniffer.py
```

### CLI Options

| Flag | Description | Example |
|------|-------------|---------|
| `-n N` | Stop after N packets | `-n 100` |
| `-p PROTO` | Filter by protocol(s) | `-p TCP UDP` |
| `-i IP` | Filter by source or destination IP | `-i 192.168.1.1` |
| `--port PORT` | Filter by port number(s) | `--port 80 443` |
| `-v` | Verbose output | `-v` |

### Examples

```bash
# Capture 50 packets then stop
sudo python3 network_sniffer.py -n 50

# Watch only TCP traffic
sudo python3 network_sniffer.py -p TCP

# Monitor a specific host
sudo python3 network_sniffer.py -i 10.0.0.5

# Capture only DNS and HTTPS traffic
sudo python3 network_sniffer.py --port 53 443

# Combine filters: 100 UDP packets to/from port 53
sudo python3 network_sniffer.py -n 100 -p UDP --port 53
```

---

## Sample Output

```
  ╔══════════════════════════════════════════════════╗
  ║         🔍  PYTHON NETWORK SNIFFER  🔍           ║
  ╚══════════════════════════════════════════════════╝

  ────────────────────────────────────────────────────────────────────────
  #1     14:32:01.847  [TCP  ]  74 bytes

  IP Layer
    src  192.168.1.10        dst  142.250.80.46       TTL 64

  TCP Segment
    src port  52341/ephemeral      dst port  443/HTTPS
    flags     .AP...   seq 482910   ack 1930271   win 65535

  Payload (32 bytes)
    TLS 1.3 Application Data
```

---

## How It Works

The sniffer opens a **raw socket**, which sits below the OS TCP/IP stack and receives every packet on the network interface — before the OS filters it. Each packet is decoded manually using Python's `struct.unpack` with big-endian format strings that match the protocol byte layouts defined in the RFCs.

```
Raw bytes
  └── Ethernet header  (14 bytes)   — src/dst MAC, EtherType
        └── IP header  (20 bytes)   — src/dst IP, TTL, protocol
              ├── TCP header (20+ bytes)  — ports, seq/ack, flags, window
              ├── UDP header  (8 bytes)  — ports, length
              └── ICMP header (4 bytes)  — type, code
                    └── Payload  — application data
```

**Platform differences:**

| Platform | Socket type | Notes |
|----------|-------------|-------|
| Linux | `AF_PACKET / SOCK_RAW` | Full Ethernet frames |
| Windows | `AF_INET / IPPROTO_IP` + `SIO_RCVALL` | Raw IP, promiscuous mode via ioctl |
| macOS | `AF_INET / IPPROTO_IP` | Raw IP, no Ethernet header |

---

## Project Structure

```
.
├── network_sniffer.py   # Main script — all logic in one file
└── README.md
```

---
## Screenshots
```
<img width="1498" height="921" alt="WhatsApp Image 2026-06-10 at 6 53 20 PM" src="https://github.com/user-attachments/assets/a3a23e62-4b9f-4d12-a067-b84f45a5f084" />
<img width="1600" height="1200" alt="WhatsApp Image 2026-06-10 at 6 53 11 PM" src="https://github.com/user-attachments/assets/97ce93f9-682c-4db6-aac0-074685aa0d9d" />

```

## Concepts Demonstrated

- Raw socket programming in Python
- Manual binary protocol parsing with `struct`
- IPv4, TCP, UDP, ICMP header structure (per RFC 791, 793, 768, 792)
- Promiscuous mode and OS-level packet capture
- Cross-platform privilege escalation detection
- ANSI terminal formatting

---

## Legal & Ethical Notice

This tool is intended for **educational use on networks you own or have explicit permission to monitor**. Capturing traffic on networks without authorisation may violate computer misuse laws in your jurisdiction. Use responsibly.

---

## License

MIT
