#!/usr/bin/env python3
"""
Basic Network Sniffer
Captures and analyzes network packets using raw sockets.
Works without scapy — uses only the Python standard library.
"""

import socket
import struct
import textwrap
import sys
import time
import os
import argparse
from datetime import datetime
from collections import defaultdict

# ─── ANSI Colors ────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_DARK = "\033[40m"

# ─── Protocol Maps ───────────────────────────────────────────────────────────
PROTO_NAMES = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
    2:  "IGMP",
    41: "IPv6",
    89: "OSPF",
}

PROTO_COLORS = {
    "TCP":  C.CYAN,
    "UDP":  C.GREEN,
    "ICMP": C.YELLOW,
    "IGMP": C.MAGENTA,
    "IPv6": C.BLUE,
    "OSPF": C.RED,
}

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
    194: "IRC", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 27017: "MongoDB",
}

# ─── Stats ───────────────────────────────────────────────────────────────────
stats = {
    "total": 0,
    "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
    "bytes": 0,
    "src_ips": defaultdict(int),
    "dst_ips": defaultdict(int),
    "ports": defaultdict(int),
    "start_time": time.time(),
}

# ─── Packet Parsers ──────────────────────────────────────────────────────────

def parse_ethernet_header(data):
    """Extract Ethernet II frame fields."""
    dst_mac = ":".join(f"{b:02x}" for b in data[0:6])
    src_mac = ":".join(f"{b:02x}" for b in data[6:12])
    eth_type = struct.unpack("!H", data[12:14])[0]
    return dst_mac, src_mac, eth_type, data[14:]

def parse_ip_header(data):
    """Parse IPv4 header."""
    version_ihl = data[0]
    version  = version_ihl >> 4
    ihl      = (version_ihl & 0xF) * 4
    tos      = data[1]
    total_len = struct.unpack("!H", data[2:4])[0]
    ttl      = data[8]
    proto    = data[9]
    checksum = struct.unpack("!H", data[10:12])[0]
    src_ip   = socket.inet_ntoa(data[12:16])
    dst_ip   = socket.inet_ntoa(data[16:20])
    payload  = data[ihl:]
    return {
        "version": version, "ihl": ihl, "tos": tos,
        "total_len": total_len, "ttl": ttl, "proto": proto,
        "checksum": checksum, "src": src_ip, "dst": dst_ip,
        "payload": payload,
    }

def parse_tcp_segment(data):
    """Parse TCP segment."""
    src_port, dst_port, seq, ack = struct.unpack("!HHLL", data[0:12])
    offset_flags = struct.unpack("!H", data[12:14])[0]
    offset  = (offset_flags >> 12) * 4
    flags   = offset_flags & 0x1FF
    flag_str = "".join([
        "U" if flags & 0x020 else ".",
        "A" if flags & 0x010 else ".",
        "P" if flags & 0x008 else ".",
        "R" if flags & 0x004 else ".",
        "S" if flags & 0x002 else ".",
        "F" if flags & 0x001 else ".",
    ])
    window  = struct.unpack("!H", data[14:16])[0]
    payload = data[offset:]
    return {
        "src_port": src_port, "dst_port": dst_port,
        "seq": seq, "ack": ack,
        "flags": flag_str, "window": window,
        "payload": payload,
    }

def parse_udp_datagram(data):
    """Parse UDP datagram."""
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[0:8])
    payload = data[8:]
    return {
        "src_port": src_port, "dst_port": dst_port,
        "length": length, "checksum": checksum,
        "payload": payload,
    }

def parse_icmp_packet(data):
    """Parse ICMP packet."""
    icmp_type, code, checksum = struct.unpack("!BBH", data[0:4])
    type_names = {
        0: "Echo Reply", 3: "Dest Unreachable", 5: "Redirect",
        8: "Echo Request", 11: "Time Exceeded", 12: "Param Problem",
    }
    return {
        "type": icmp_type, "code": code, "checksum": checksum,
        "type_name": type_names.get(icmp_type, f"Type-{icmp_type}"),
        "payload": data[4:],
    }

# ─── Helpers ─────────────────────────────────────────────────────────────────

def port_label(port):
    name = WELL_KNOWN_PORTS.get(port, "")
    return f"{port}{C.DIM}/{name}{C.RESET}" if name else str(port)

def decode_payload(data, max_bytes=64):
    """Show payload as ASCII where printable, hex otherwise."""
    if not data:
        return ""
    sample = data[:max_bytes]
    try:
        text = sample.decode("utf-8", errors="replace")
        printable = "".join(c if 32 <= ord(c) < 127 else "." for c in text)
        return textwrap.shorten(printable, width=80, placeholder="…")
    except Exception:
        return sample.hex()

def divider(char="─", width=72, color=C.GRAY):
    return f"{color}{char * width}{C.RESET}"

def proto_tag(name):
    color = PROTO_COLORS.get(name, C.WHITE)
    return f"{color}{C.BOLD}[{name:^5}]{C.RESET}"

# ─── Display ─────────────────────────────────────────────────────────────────

def print_banner():
    print(f"\n{C.CYAN}{C.BOLD}")
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║         🔍  PYTHON NETWORK SNIFFER  🔍           ║")
    print("  ║         Raw socket packet analyser               ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print(C.RESET)
    print(f"  {C.GRAY}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"  {C.GRAY}Press Ctrl+C to stop and view summary{C.RESET}\n")

def display_packet(pkt_num, ip, transport, proto_name, raw_size):
    """Print a formatted packet summary."""
    color = PROTO_COLORS.get(proto_name, C.WHITE)
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    print(divider())
    # Header line
    print(f"  {C.GRAY}#{pkt_num:<5}{C.RESET}  {C.DIM}{ts}{C.RESET}  "
          f"{proto_tag(proto_name)}  {C.GRAY}{raw_size} bytes{C.RESET}")

    # IP layer
    print(f"\n  {C.BOLD}IP Layer{C.RESET}")
    print(f"    {C.DIM}src{C.RESET}  {color}{ip['src']:<18}{C.RESET}  "
          f"{C.DIM}dst{C.RESET}  {color}{ip['dst']:<18}{C.RESET}  "
          f"{C.DIM}TTL{C.RESET} {ip['ttl']}")

    payload = ip["payload"]

    if proto_name == "TCP" and transport:
        t = transport
        print(f"\n  {C.BOLD}TCP Segment{C.RESET}")
        print(f"    {C.DIM}src port{C.RESET}  {color}{port_label(t['src_port']):<22}{C.RESET}"
              f"  {C.DIM}dst port{C.RESET}  {color}{port_label(t['dst_port'])}{C.RESET}")
        print(f"    {C.DIM}flags{C.RESET}     {C.YELLOW}{t['flags']}{C.RESET}   "
              f"  {C.DIM}seq{C.RESET} {t['seq']}   {C.DIM}ack{C.RESET} {t['ack']}   "
              f"  {C.DIM}win{C.RESET} {t['window']}")
        payload = t["payload"]

    elif proto_name == "UDP" and transport:
        t = transport
        print(f"\n  {C.BOLD}UDP Datagram{C.RESET}")
        print(f"    {C.DIM}src port{C.RESET}  {color}{port_label(t['src_port']):<22}{C.RESET}"
              f"  {C.DIM}dst port{C.RESET}  {color}{port_label(t['dst_port'])}{C.RESET}  "
              f"  {C.DIM}len{C.RESET} {t['length']}")
        payload = t["payload"]

    elif proto_name == "ICMP" and transport:
        t = transport
        print(f"\n  {C.BOLD}ICMP Packet{C.RESET}")
        print(f"    {C.DIM}type{C.RESET}  {C.YELLOW}{t['type_name']}{C.RESET} ({t['type']})  "
              f"  {C.DIM}code{C.RESET} {t['code']}")
        payload = t["payload"]

    # Payload
    if payload:
        decoded = decode_payload(payload)
        if decoded.strip("."):
            print(f"\n  {C.BOLD}Payload{C.RESET} {C.DIM}({len(payload)} bytes){C.RESET}")
            print(f"    {C.GREEN}{decoded}{C.RESET}")

def print_summary():
    elapsed = time.time() - stats["start_time"]
    total   = stats["total"]
    mb      = stats["bytes"] / (1024 * 1024)
    pps     = total / elapsed if elapsed > 0 else 0

    print(f"\n\n{C.CYAN}{C.BOLD}{'═'*70}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  CAPTURE SUMMARY{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'═'*70}{C.RESET}\n")

    print(f"  {C.BOLD}Duration  {C.RESET}{elapsed:.1f}s   "
          f"{C.BOLD}Packets  {C.RESET}{total}   "
          f"{C.BOLD}Data  {C.RESET}{mb:.2f} MB   "
          f"{C.BOLD}Rate  {C.RESET}{pps:.1f} pkt/s\n")

    print(f"  {C.BOLD}Protocol Breakdown{C.RESET}")
    for name, key, color in [("TCP","tcp",C.CYAN),("UDP","udp",C.GREEN),
                              ("ICMP","icmp",C.YELLOW),("Other","other",C.GRAY)]:
        n = stats[key]
        pct = (n / total * 100) if total else 0
        bar = "█" * int(pct / 3)
        print(f"    {color}{name:<6}{C.RESET}  {n:>5}  {pct:5.1f}%  {color}{bar}{C.RESET}")

    if stats["src_ips"]:
        print(f"\n  {C.BOLD}Top 5 Source IPs{C.RESET}")
        top = sorted(stats["src_ips"].items(), key=lambda x: -x[1])[:5]
        for ip, cnt in top:
            print(f"    {C.CYAN}{ip:<18}{C.RESET}  {cnt} packets")

    if stats["ports"]:
        print(f"\n  {C.BOLD}Top 5 Ports{C.RESET}")
        top = sorted(stats["ports"].items(), key=lambda x: -x[1])[:5]
        for port, cnt in top:
            label = WELL_KNOWN_PORTS.get(port, "unknown")
            print(f"    {C.GREEN}{port:<6}{C.RESET} {C.DIM}{label:<15}{C.RESET}  {cnt} packets")

    print(f"\n{C.CYAN}{'═'*70}{C.RESET}\n")

# ─── Main ─────────────────────────────────────────────────────────────────────

def is_admin():
    """Cross-platform admin/root check."""
    if sys.platform == "win32":
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def run_sniffer(count=0, proto_filter=None, ip_filter=None, port_filter=None, verbose=False):
    if not is_admin():
        print(f"\n{C.RED}✗ Administrator privileges required.{C.RESET}")
        if sys.platform == "win32":
            print(f"  Right-click your terminal and choose {C.YELLOW}\"Run as administrator\"{C.RESET},")
            print(f"  then re-run: {C.YELLOW}python network_sniffer.py{C.RESET}\n")
        else:
            print(f"  Run with: {C.YELLOW}sudo python3 network_sniffer.py{C.RESET}\n")
        sys.exit(1)

    print_banner()

    # Create the raw socket — method depends on platform
    if sys.platform == "win32":
        # Windows: raw socket over IPPROTO_IP, bound to the local machine's IP
        host = socket.gethostbyname(socket.gethostname())
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((host, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Enable promiscuous mode on Windows via SIO_RCVALL
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        try:
            # Linux: AF_PACKET gives full Ethernet frames
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        except AttributeError:
            # macOS fallback
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind(("0.0.0.0", 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    pkt_num = 0

    try:
        while True:
            if count and pkt_num >= count:
                break

            raw_data, _ = sock.recvfrom(65536)
            stats["bytes"] += len(raw_data)

            # Linux gives full Ethernet frames; Windows/macOS give raw IP
            if sys.platform == "linux":
                try:
                    dst_mac, src_mac, eth_type, ip_data = parse_ethernet_header(raw_data)
                    if eth_type != 0x0800:   # Only IPv4
                        continue
                except Exception:
                    ip_data = raw_data
            else:
                ip_data = raw_data       # Windows & macOS: already raw IP

            try:
                ip = parse_ip_header(ip_data)
            except Exception:
                continue

            proto_num  = ip["proto"]
            proto_name = PROTO_NAMES.get(proto_num, f"PROTO-{proto_num}")

            # ── Filters ──────────────────────────────────────────────────
            if proto_filter and proto_name.upper() not in [p.upper() for p in proto_filter]:
                continue
            if ip_filter and ip["src"] != ip_filter and ip["dst"] != ip_filter:
                continue

            transport = None
            src_port = dst_port = None

            if proto_num == 6:    # TCP
                try:
                    transport = parse_tcp_segment(ip["payload"])
                    src_port, dst_port = transport["src_port"], transport["dst_port"]
                    stats["tcp"] += 1
                except Exception:
                    pass

            elif proto_num == 17: # UDP
                try:
                    transport = parse_udp_datagram(ip["payload"])
                    src_port, dst_port = transport["src_port"], transport["dst_port"]
                    stats["udp"] += 1
                except Exception:
                    pass

            elif proto_num == 1:  # ICMP
                try:
                    transport = parse_icmp_packet(ip["payload"])
                    stats["icmp"] += 1
                except Exception:
                    pass
            else:
                stats["other"] += 1

            # Port filter
            if port_filter:
                if src_port not in port_filter and dst_port not in port_filter:
                    continue

            # ── Stats update ─────────────────────────────────────────────
            pkt_num += 1
            stats["total"] += 1
            stats["src_ips"][ip["src"]] += 1
            stats["dst_ips"][ip["dst"]] += 1
            if src_port: stats["ports"][src_port] += 1
            if dst_port: stats["ports"][dst_port] += 1

            display_packet(pkt_num, ip, transport, proto_name, len(raw_data))

    except KeyboardInterrupt:
        pass
    finally:
        if sys.platform == "win32":
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        sock.close()
        print_summary()


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer — raw socket packet analyser",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-n", "--count",   type=int, default=0,
                        help="Stop after N packets (0 = unlimited)")
    parser.add_argument("-p", "--proto",   nargs="+", metavar="PROTO",
                        help="Filter by protocol(s): TCP UDP ICMP")
    parser.add_argument("-i", "--ip",      metavar="IP",
                        help="Filter by source or destination IP")
    parser.add_argument("--port",          type=int, nargs="+", metavar="PORT",
                        help="Filter by port number(s)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show extra detail")

    args = parser.parse_args()
    run_sniffer(
        count=args.count,
        proto_filter=args.proto,
        ip_filter=args.ip,
        port_filter=set(args.port) if args.port else None,
        verbose=args.verbose,
    )