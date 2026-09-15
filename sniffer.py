#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sniffer.py — Basic Network Sniffer
====================================================================
CodeAlpha Cyber Security Internship | Task 1

A lightweight, extensible packet sniffer built on Scapy. Captures
live network traffic and reports, per packet:

    * Timestamp
    * Source / destination IP address
    * Transport-layer protocol (TCP / UDP / ICMP / Other)
    * Source / destination port and TCP flags (where applicable)
    * A sanitized, printable preview of the payload
    * A running summary of protocol distribution and traffic volume

Design notes
------------
The module is split into three responsibilities so each part can be
tested or reused independently:

    1. ``PacketInfo``       — a typed, immutable record of one packet's
                              relevant fields (parsing logic).
    2. ``CaptureSession``   — owns capture state: packet counters,
                              optional file logging, and summary stats
                              (I/O and bookkeeping).
    3. ``main`` / CLI       — wires the two together and drives Scapy's
                              ``sniff()`` loop.

Requirements
------------
    pip install scapy

Root/administrator privileges are required to open a raw socket for
live capture.

Usage
-----
    sudo python3 sniffer.py                        # default interface
    sudo python3 sniffer.py -i eth0                 # specific interface
    sudo python3 sniffer.py -c 100                  # stop after 100 packets
    sudo python3 sniffer.py -f "tcp port 443"        # BPF filter
    sudo python3 sniffer.py -o capture.log           # log to file
    sudo python3 sniffer.py --json report.json       # structured export
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

__author__ = "CodeAlpha Cyber Security Internship — Task 1"
__version__ = "1.0.0"

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    from scapy.packet import Packet
except ImportError:
    sys.stderr.write(
        "[!] Scapy is not installed. Install it with:\n"
        "    pip install scapy\n"
    )
    sys.exit(1)


logger = logging.getLogger("network_sniffer")


# ----------------------------------------------------------------------
# Packet parsing
# ----------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class PacketInfo:
    """A parsed, human-readable summary of a single captured packet."""

    timestamp: str
    protocol: str
    src_ip: str
    dst_ip: str
    length: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    payload_preview: str = ""

    @property
    def is_ip(self) -> bool:
        return self.src_ip != "" and self.dst_ip != ""

    def as_line(self) -> str:
        """Render a single console/log line for this packet."""
        port_info = ""
        if self.src_port is not None and self.dst_port is not None:
            port_info = f"  {self.src_port} -> {self.dst_port}"
            if self.tcp_flags:
                port_info += f"  flags={self.tcp_flags}"

        line = (
            f"[{self.timestamp}] {self.protocol:5s}  "
            f"{self.src_ip:15s} -> {self.dst_ip:15s}  "
            f"len={self.length:<5d}{port_info}"
        )
        if self.payload_preview:
            line += f"\n{'':11s}payload: {self.payload_preview}"
        return line

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def _protocol_name(pkt: Packet) -> str:
    """Identify the transport-layer protocol of a packet."""
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP):
        return f"IP/{pkt[IP].proto}"
    return "OTHER"


def _payload_preview(pkt: Packet, max_len: int = 64) -> str:
    """
    Return a printable preview of the packet payload.

    Non-printable bytes are rendered as '.' so binary data never
    corrupts the terminal or log file. Output is truncated to
    ``max_len`` characters with a trailing ellipsis when longer.
    """
    if not pkt.haslayer(Raw):
        return ""
    raw = bytes(pkt[Raw].load)
    printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw[:max_len])
    return printable + ("..." if len(raw) > max_len else "")


def parse_packet(pkt: Packet) -> PacketInfo:
    """Convert a raw Scapy packet into a structured :class:`PacketInfo`."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    if not pkt.haslayer(IP):
        return PacketInfo(
            timestamp=timestamp,
            protocol="NON-IP",
            src_ip="",
            dst_ip="",
            length=len(pkt),
            payload_preview=pkt.summary(),
        )

    ip_layer = pkt[IP]
    src_port = dst_port = None
    tcp_flags = None

    if pkt.haslayer(TCP):
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        tcp_flags = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport

    return PacketInfo(
        timestamp=timestamp,
        protocol=_protocol_name(pkt),
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        length=len(pkt),
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        payload_preview=_payload_preview(pkt),
    )


# ----------------------------------------------------------------------
# Capture session: state, logging, statistics
# ----------------------------------------------------------------------

class CaptureSession:
    """
    Owns the mutable state of a capture run: packet count, per-protocol
    statistics, and optional output sinks (console / log file / JSON).
    """

    def __init__(self, log_path: Optional[Path] = None, json_path: Optional[Path] = None):
        self.log_path = log_path
        self.json_path = json_path
        self._log_fh = open(log_path, "a", encoding="utf-8") if log_path else None
        self.packets: list[PacketInfo] = []
        self.protocol_counts: Counter = Counter()
        self.total_bytes = 0

    def handle(self, pkt: Packet) -> None:
        """Callback passed to ``scapy.sniff(prn=...)`` for each packet."""
        info = parse_packet(pkt)
        self.packets.append(info)
        self.protocol_counts[info.protocol] += 1
        self.total_bytes += info.length

        line = info.as_line()
        print(line)
        if self._log_fh:
            self._log_fh.write(line + "\n")
            self._log_fh.flush()

    def summary(self) -> str:
        """Build a human-readable end-of-capture summary."""
        rows = "\n".join(
            f"    {proto:8s} {count:>6d}" for proto, count in self.protocol_counts.most_common()
        )
        return (
            "\n" + "-" * 70 +
            f"\nCapture summary\n"
            f"  Total packets : {len(self.packets)}\n"
            f"  Total bytes   : {self.total_bytes}\n"
            f"  By protocol   :\n{rows or '    (none)'}\n" +
            "-" * 70
        )

    def close(self) -> None:
        """Flush and close all open output sinks."""
        if self._log_fh:
            self._log_fh.close()
        if self.json_path:
            with open(self.json_path, "w", encoding="utf-8") as fh:
                json.dump([p.as_dict() for p in self.packets], fh, indent=2)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffer.py",
        description="Basic Network Sniffer — CodeAlpha Cyber Security Internship, Task 1.",
    )
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: Scapy auto-detect)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter expression, e.g. 'tcp port 443'")
    parser.add_argument("-o", "--output", type=Path, help="Append human-readable capture log to this file")
    parser.add_argument("--json", dest="json_output", type=Path, help="Write structured packet data as JSON on exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug-level logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def print_banner(args: argparse.Namespace) -> None:
    print("=" * 70)
    print(" CodeAlpha Cyber Security Internship — Task 1: Network Sniffer")
    print("=" * 70)
    print(f" Interface : {args.interface or 'default'}")
    print(f" Filter    : {args.filter or 'none (all traffic)'}")
    print(f" Count     : {'unlimited' if args.count == 0 else args.count}")
    print(" Press Ctrl+C to stop.\n")


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    session = CaptureSession(log_path=args.output, json_path=args.json_output)
    print_banner(args)

    try:
        sniff(
            iface=args.interface or None,
            filter=args.filter or None,
            prn=session.handle,
            count=args.count,
            store=False,
        )
    except PermissionError:
        logger.error("Permission denied — try running with sudo/administrator privileges.")
        return 1
    except OSError as exc:
        logger.error("Could not start capture: %s", exc)
        return 1
    except KeyboardInterrupt:
        pass
    finally:
        print(session.summary())
        session.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
