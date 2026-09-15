# CodeAlpha Network Sniffer

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Scapy](https://img.shields.io/badge/built%20with-Scapy-informational)
![License](https://img.shields.io/badge/license-MIT-green)

**CodeAlpha Cyber Security Internship — Task 1**

A lightweight, extensible packet sniffer built with [Scapy](https://scapy.net/) that captures live network traffic and reports source/destination IPs, protocol, ports, TCP flags, and a sanitized payload preview for every packet — with an end-of-run traffic summary and optional structured (JSON) export.

## Table of Contents

- [Features](#features)
- [How Data Flows Through a Network](#how-data-flows-through-a-network)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Project Structure](#project-structure)
- [Ethical & Legal Notice](#ethical--legal-notice)

## Features

| Feature | Description |
|---|---|
| Live capture | Captures packets on any interface in real time via Scapy |
| Protocol detection | Identifies TCP, UDP, ICMP, and other IP protocols |
| Port & flag reporting | Extracts source/destination ports and TCP flags |
| Safe payload preview | Renders payload bytes as printable text, truncated and sanitized |
| BPF filtering | Scope capture with standard filter expressions (e.g. `tcp port 443`) |
| Traffic summary | Per-protocol packet counts and total bytes at the end of a run |
| File logging | Append human-readable output to a log file |
| JSON export | Write structured, per-packet data for further analysis or tooling |
| CLI-first design | All options configurable via flags; no code edits required |

## How Data Flows Through a Network

Every packet on an IP network is layered, like an envelope inside an envelope:

1. **IP layer** — carries the source and destination *addresses*, telling routers where a packet came from and where it's going.
2. **Transport layer (TCP/UDP)** — sits inside the IP layer and adds *port numbers*, identifying which application on each host is communicating (e.g. port 80/443 for HTTP/HTTPS, 53 for DNS). TCP is connection-oriented and reliable, using flags like `SYN`/`ACK` to manage handshakes; UDP is connectionless and faster, with no delivery guarantees.
3. **Application layer / payload** — the actual data being exchanged, such as an HTTP request or a DNS query.

Sniffing works by putting the network interface into a mode where it passes every observed frame up to the OS (not just traffic addressed to this machine), so Scapy can capture and dissect each layer described above.

## Architecture

The script is split into three responsibilities so each part is easy to read, test, and reuse:

```
PacketInfo        → typed, immutable record of one packet's fields (parsing)
CaptureSession    → capture state: counters, file/JSON output, summary stats
main() / CLI      → argument parsing, banner, wires the above into scapy.sniff()
```

## Installation

```bash
git clone <this-repo-url>
cd CodeAlpha_NetworkSniffer
pip install -r requirements.txt
```

Root/administrator privileges are required to open a raw socket for live capture.

## Usage

```bash
# Sniff on the default interface, all traffic
sudo python3 sniffer.py

# Sniff on a specific interface
sudo python3 sniffer.py -i eth0

# Stop after 100 packets
sudo python3 sniffer.py -c 100

# Only capture HTTPS traffic
sudo python3 sniffer.py -f "tcp port 443"

# Log human-readable output to a file
sudo python3 sniffer.py -o capture.log

# Export structured packet data as JSON
sudo python3 sniffer.py --json report.json

# Verbose (debug-level) logging
sudo python3 sniffer.py -v
```

Run `python3 sniffer.py --help` for the full option list.

## Sample Output

```
======================================================================
 CodeAlpha Cyber Security Internship — Task 1: Network Sniffer
======================================================================
 Interface : default
 Filter    : none (all traffic)
 Count     : unlimited
 Press Ctrl+C to stop.

[15:03:35] TCP    192.168.1.10    -> 93.184.216.34    len=40     51423 -> 80    flags=S
[15:03:35] UDP    192.168.1.10    -> 8.8.8.8          len=42     51000 -> 53
           payload: DNS query stub
[15:03:35] ICMP   192.168.1.1     -> 192.168.1.10     len=28
[15:03:35] TCP    192.168.1.10    -> 93.184.216.34    len=77     51423 -> 443   flags=PA
           payload: GET / HTTP/1.1..Host: example.com....

----------------------------------------------------------------------
Capture summary
  Total packets : 4
  Total bytes   : 187
  By protocol   :
    TCP           2
    UDP           1
    ICMP          1
----------------------------------------------------------------------
```

## Project Structure

```
CodeAlpha_NetworkSniffer/
├── sniffer.py          # Main sniffer implementation + CLI
├── requirements.txt    # Python dependencies
├── LICENSE              # MIT License
├── .gitignore
└── README.md
```

## Ethical & Legal Notice

This tool is provided for educational purposes as part of the CodeAlpha internship. Only run it on networks and systems you own or have explicit, written authorization to monitor. Capturing traffic on networks without authorization is illegal in most jurisdictions and may violate organizational policy or law.

---

Submitted as part of the **CodeAlpha Cyber Security Internship**, Task 1: Basic Network Sniffer.
