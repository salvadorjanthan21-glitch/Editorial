# 📡 Full-Stack Lesson: tcpdump and BPF Capture Filters

## 📊 Executive Summary

tcpdump is the gold-standard command-line packet capture and analysis tool for UNIX-like systems. It uses **Berkeley Packet Filter (BPF)** syntax—a low-level, kernel-optimised filtering language that determines *which* packets are captured *before* they reach user space. Unlike Wireshark's display filters, which filter packets already in memory, BPF capture filters operate at the interface level, making them critical for high-throughput traffic analysis. This lesson covers tcpdump fundamentals, BPF syntax, practical capture strategies, and how to extract security-relevant traffic (suspicious IPs, port scans, DNS anomalies) directly from the command line.

```mermaid
flowchart LR
    A[Network Interface] --> B[BPF Capture Filter]
    B --> C[kernel: packet matches?]
    C -->|Yes| D[tcpdump captures packet]
    C -->|No| E[Packet discarded]
    D --> F[Write to .pcap file]
    F --> G[Offline analysis]
    G --> H[Wireshark / tshark]
    G --> I[Python scapy / dpkt]
    
    subgraph B [BPF Filter Examples]
        B1[host 192.168.1.1]
        B2[port 53]
        B3[net 10.0.0.0/8]
        B4[tcp and port 80]
    end
    
    F --> J[Display filters<br/>(post-capture)]
    J --> H
```

## 🏗️ Phase 1: tcpdump Fundamentals

### Basic Usage

```bash
# List available interfaces
tcpdump -D

# Capture on a specific interface
tcpdump -i eth0

# Capture with DNS resolution disabled (faster, cleaner)
tcpdump -i eth0 -n

# Capture and write to file
tcpdump -i eth0 -w capture.pcap

# Read a pcap file
tcpdump -r capture.pcap

# Capture with verbose output
tcpdump -i eth0 -v

# Capture exactly N packets and stop
tcpdump -i eth0 -c 1000

# Capture with time-stamp precision
tcpdump -i eth0 -tttt
```

### Key Command-Line Flags

| Flag | Purpose | Example |
|------|---------|---------|
| `-i` | Interface to capture on | `-i eth0` |
| `-n` | Don't resolve hostnames | `-n` |
| `-nn` | Don't resolve hostnames **or** port names | `-nn` |
| `-v`, `-vv`, `-vvv` | Verbosity level | `-vv` |
| `-w` | Write raw packets to file | `-w output.pcap` |
| `-r` | Read packets from file | `-r capture.pcap` |
| `-c` | Stop after N packets | `-c 5000` |
| `-s` | Snap length (bytes per packet) | `-s 0` (full) |
| `-X` | Print hex + ASCII payload | `-X` |
| `-A` | Print ASCII payload only | `-A` |
| `-e` | Print link-level header (MAC addresses) | `-e` |
| `-S` | Print absolute (not relative) sequence numbers | `-S` |
| `-tttt` | Human-readable timestamps | `-tttt` |

> 💡 **Performance Tip**: Always use `-n` (or `-nn`) in production captures. DNS resolution blocks the capture and introduces latency that can cause packet loss under load.

### Output Anatomy

```
12:34:56.789012 IP 10.0.0.5.54321 > 93.184.216.34.80: Flags [S], seq 123456789, win 65535, options [mss 1460,sackOK,TS val 123 ecr 0], length 0
```

| Field | Meaning |
|-------|---------|
| `12:34:56.789012` | Timestamp (microsecond precision) |
| `IP` | Protocol (IP, IPv6, ARP) |
| `10.0.0.5.54321` | Source IP and port (dot-separated) |
| `>` | Direction indicator |
| `93.184.216.34.80` | Destination IP and port |
| `Flags [S]` | TCP flags: `S`=SYN, `F`=FIN, `R`=RST, `P`=PSH, `A`=ACK, `U`=URG |
| `seq 123456789` | Sequence number |
| `win 65535` | TCP window size |
| `options [...]` | TCP options |
| `length 0` | Payload length |

## 🔍 Phase 2: BPF Capture Filter Syntax

### What is BPF?

Berkeley Packet Filter (BPF) is a filter expression language evaluated inside the OS kernel's packet filter. It operates on a limited set of primitives—you **cannot** do deep packet inspection with BPF; for that you need display filters after capture.

> ⚠️ **Critical Difference**: BPF capture filters drop packets at the kernel level—they never reach user space. Wireshark display filters filter packets already in memory. A bad BPF filter means **you permanently lose the data**.

### BPF Primitives

| Primitive | Syntax | Matches |
|-----------|--------|---------|
| **host** | `host 192.168.1.1` | All traffic to/from host |
| **src host** | `src host 10.0.0.1` | Traffic *from* host |
| **dst host** | `dst host 8.8.8.8` | Traffic *to* host |
| **net** | `net 10.0.0.0/8` | Traffic to/from network |
| **port** | `port 80` | Traffic on port 80 |
| **src port** | `src port 443` | Traffic from source port 443 |
| **dst port** | `dst port 53` | Traffic to destination port 53 |
| **portrange** | `portrange 8000-8080` | Port range |
| **arp** | `arp` | ARP protocol only |
| **icmp** | `icmp` | ICMP protocol only |
| **tcp** | `tcp` | TCP protocol only |
| **udp** | `udp` | UDP protocol only |
| **broadcast** | `broadcast` | Broadcast packets |
| **multicast** | `multicast` | Multicast packets |
| **less** | `less 128` | Packets shorter than 128 bytes |
| **greater** | `greater 1024` | Packets longer than 1024 bytes |

### Boolean Operators

| Operator | Syntax | Example |
|----------|--------|---------|
| **AND** | `and` or `&&` | `tcp and port 80` |
| **OR** | `or` or `\|\|` | `port 53 or port 80` |
| **NOT** | `not` or `!` | `not arp` |
| **Parentheses** | `(...)` | `tcp and (port 80 or port 443)` |

### Combining Primitives

```bash
# HTTP traffic from a specific host
tcpdump -i eth0 -nn 'host 10.0.0.5 and tcp port 80'

# DNS only (UDP port 53)
tcpdump -i eth0 -nn 'udp port 53'

# Exclude local broadcast chatter
tcpdump -i eth0 -nn 'not broadcast and not multicast'

# Traffic to a subnet excluding DNS
tcpdump -i eth0 -nn 'dst net 10.0.0.0/24 and not port 53'

# SYN packets only (TCP flags filter via raw offset)
tcpdump -i eth0 -nn 'tcp[tcpflags] & tcp-syn != 0'

# Full three-way handshake
tcpdump -i eth0 -nn 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'

# RST or FIN packets (connection teardown)
tcpdump -i eth0 -nn 'tcp[tcpflags] & (tcp-rst|tcp-fin) != 0'
```

## 🧪 Phase 3: Practical Capture Filter Examples

### Security Analysis Scenarios

### 🛡️ Scenario 1: Suspicious Outbound Beaconing

```bash
# Capture traffic to a known C2 IP
tcpdump -i eth0 -nn 'host 51.15.43.214'

# Capture traffic on non-standard ports (suspicious)
tcpdump -i eth0 -nn 'tcp port 4444 or tcp port 6667 or tcp port 1337'

# Capture small packets at regular intervals (beacon pattern)
tcpdump -i eth0 -nn -c 1000 'greater 0 and less 200'
```

### 🔎 Scenario 2: DNS Tunneling Indicators

```bash
# Capture all DNS queries with unusually long hostnames
tcpdump -i eth0 -nn 'udp port 53 and greater 200'

# TXT record queries (common for exfiltration)
tcpdump -i eth0 -nn 'udp port 53 and greater 400'

# High-frequency DNS lookups to same domain
tcpdump -i eth0 -nn -c 1000 'udp port 53' | awk '{print $NF}' | sort | uniq -c | sort -rn | head -20
```

### 🚨 Scenario 3: Port Scan Detection

```bash
# SYN scan to multiple ports from same host
tcpdump -i eth0 -nn 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'

# Full connect scan with RST from closed ports
tcpdump -i eth0 -nn 'tcp[tcpflags] & (tcp-syn|tcp-rst) != 0'

# Horizontal scan (same port across multiple hosts)
tcpdump -i eth0 -nn 'tcp dst port 22 and tcp[tcpflags] & tcp-syn != 0'
```

### Cheat Sheet: Quick Security Captures

```bash
# ====================================
# FULL SESSION CAPTURE (production)
# ====================================
tcpdump -i eth0 -nn -s 0 -w full_capture.pcap

# ====================================
# HTTP REQUEST/HEADER LOGGING
# ====================================
tcpdump -i eth0 -nn -A tcp port 80

# ====================================
# DNS QUERY MONITORING
# ====================================
tcpdump -i eth0 -nn udp port 53 -w dns_queries.pcap

# ====================================
# CREDENTIAL HARVEST (unencrypted)
# ====================================
tcpdump -i eth0 -nn -X 'tcp port 80 or tcp port 21 or tcp port 23 or tcp port 25'

# ====================================
# ICMP (possible covert channel)
# ====================================
tcpdump -i eth0 -nn -X icmp

# ====================================
# ARP (spoofing detection)
# ====================================
tcpdump -i eth0 -nn -e arp
```

## 🐍 Phase 4: Programmatic Analysis with tcpdump Output

### Parsing tcpdump with Python

```python
import subprocess
import re
from collections import Counter
from datetime import datetime

def capture_packets(interface: str, filter_expr: str, count: int = 100) -> str:
    """Capture packets and return raw tcpdump output."""
    cmd = [
        "tcpdump", "-i", interface, "-nn", "-c", str(count),
        "-tttt", filter_expr
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout

def parse_tcpdump_output(output: str) -> list:
    """Parse tcpdump output lines into structured dicts."""
    pattern = re.compile(
        r'(\S+\s+\S+)\s+IP\s+'
        r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+'
        r'(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+'
        r'Flags\s+\[(\S+)\],.*seq\s+(\d+).*length\s+(\d+)'
    )
    packets = []
    for line in output.strip().split('\n'):
        match = pattern.search(line)
        if match:
            packets.append({
                'timestamp': match.group(1),
                'src_ip': match.group(2),
                'src_port': int(match.group(3)),
                'dst_ip': match.group(4),
                'dst_port': int(match.group(5)),
                'flags': match.group(6),
                'seq': int(match.group(7)),
                'length': int(match.group(8))
            })
    return packets

def find_beaconing(packets: list, threshold_sec: float = 1.0) -> list:
    """Identify potential beaconing by analysing time deltas."""
    beacon_candidates = []
    host_times = {}

    for p in packets:
        key = f"{p['src_ip']} -> {p['dst_ip']}:{p['dst_port']}"
        if key not in host_times:
            host_times[key] = []
        host_times[key].append(p['timestamp'])

    for host_key, timestamps in host_times.items():
        if len(timestamps) < 3:
            continue
        deltas = []
        for i in range(1, len(timestamps)):
            t1 = datetime.strptime(timestamps[i-1], '%Y-%m-%d %H:%M:%S.%f')
            t2 = datetime.strptime(timestamps[i], '%Y-%m-%d %H:%M:%S.%f')
            deltas.append((t2 - t1).total_seconds())

        avg_delta = sum(deltas) / len(deltas)
        std_dev = (sum((d - avg_delta) ** 2 for d in deltas) / len(deltas)) ** 0.5

        # Low std dev = regular interval = possible beacon
        if std_dev < threshold_sec and avg_delta < 3600:
            beacon_candidates.append({
                'host_pair': host_key,
                'avg_delta_sec': round(avg_delta, 3),
                'std_dev': round(std_dev, 3),
                'packet_count': len(timestamps)
            })

    return sorted(beacon_candidates, key=lambda x: x['std_dev'])

# Example usage
output = capture_packets('eth0', 'tcp', count=500)
packets = parse_tcpdump_output(output)
beacons = find_beaconing(packets)
for b in beacons:
    print(f"⚠️  {b['host_pair']} — delta={b['avg_delta_sec']}s "
          f"σ={b['std_dev']}s count={b['packet_count']}")
```

### Live Bandwidth Monitoring with tcpdump

```python
import subprocess
import re
import time
from collections import defaultdict

def live_size_monitor(interface: str, duration: int = 30):
    """Monitor packet sizes per flow in real time."""
    cmd = ["tcpdump", "-i", interface, "-nn", "-c", "10000", "-tttt"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    flows = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'start': None})
    size_pattern = re.compile(r'length\s+(\d+)')
    ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)')

    start_time = time.time()
    try:
        for line in proc.stdout:
            if time.time() - start_time > duration:
                proc.terminate()
                break

            size_match = size_pattern.search(line)
            ip_match = ip_pattern.search(line)
            if not size_match or not ip_match:
                continue

            flow_key = f"{ip_match.group(1)}:{ip_match.group(2)} -> {ip_match.group(3)}:{ip_match.group(4)}"
            size = int(size_match.group(1))
            flows[flow_key]['bytes'] += size
            flows[flow_key]['packets'] += 1

    except KeyboardInterrupt:
        proc.terminate()

    print(f"\n{'Flow':<50} {'Packets':>8} {'Bytes':>10}")
    print("=" * 70)
    for flow, stats in sorted(flows.items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]:
        print(f"{flow:<50} {stats['packets']:>8} {stats['bytes']:>10}")
```

## 🚨 Phase 5: BPF vs Wireshark Display Filters

### Critical Differences

| Feature | BPF Capture Filter | Wireshark Display Filter |
|---------|-------------------|--------------------------|
| **Evaluation point** | Kernel (pre-capture) | User space (post-capture) |
| **Speed** | Near line rate | Depends on pcap size |
| **Packet loss** | Prevents it (drops early) | Cannot prevent (already captured) |
| **Deep inspection** | No (header fields only) | Yes (full payload) |
| **String search** | No | Yes (`http.request.uri contains "admin"`) |
| **Field extraction** | No | Yes (`tcp.payload[0:4]`) |
| **Compound logic** | Limited (primitives + booleans) | Full expression language |
| **Syntax** | `tcp port 80 and host 1.2.3.4` | `tcp.port == 80 && ip.addr == 1.2.3.4` |

### Equivalent Expressions

| Intent | BPF | Wireshark Display Filter |
|--------|-----|-------------------------|
| HTTP traffic | `tcp port 80` | `tcp.port == 80` |
| Host communication | `host 10.0.0.5` | `ip.addr == 10.0.0.5` |
| Subnet traffic | `net 10.0.0.0/24` | `ip.src == 10.0.0.0/24` |
| DNS queries | `udp port 53` | `dns.flags.response == 0` |
| SYN packets | `tcp[tcpflags] & tcp-syn != 0` | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Non-local traffic | `not net 10.0.0.0/8` | `!(ip.src == 10.0.0.0/8)` |
| HTTP POST | *Cannot express* | `http.request.method == "POST"` |

> 💡 **Strategy**: Use BPF to narrow traffic to a manageable scope (e.g., `host X and tcp port 80`), save the pcap, then use Wireshark display filters for detailed analysis. This gives you the speed of BPF with the power of display filters.

## ⚡ Phase 6: Advanced BPF & Raw Offset Filtering

### Byte Offset / Link-Layer Filters

BPF supports direct byte-offset matching for fields not exposed as primitives:

```bash
# Match IP protocol field at offset 9 (1 byte)
# 1 = ICMP, 6 = TCP, 17 = UDP
tcpdump -i eth0 -nn 'ip[9] = 6'           # TCP only
tcpdump -i eth0 -nn 'ip[9] = 17'          # UDP only
tcpdump -i eth0 -nn 'ip[9] = 1'           # ICMP only

# Match TCP flags at offset 13 (1 byte)
tcpdump -i eth0 -nn 'tcp[13] & 2 != 0'    # SYN (bit 1)
tcpdump -i eth0 -nn 'tcp[13] & 16 != 0'   # ACK (bit 4)
tcpdump -i eth0 -nn 'tcp[13] & 4 != 0'    # RST (bit 2)

# Match on specific byte values in payload
# HTTP GET request (hex: 47 45 54 = GET)
tcpdump -i eth0 -nn 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

# Match on TTL value (ip[8])
tcpdump -i eth0 -nn 'ip[8] < 64'          # Low TTL (possibly traceroute)
tcpdump -i eth0 -nn 'ip[8] = 255'         # Max TTL (possibly scanning)
```

### Named TCP Flag Comparisons

tcpdump provides named constants for readability:

| Constant | Flag | Binary | Decimal |
|----------|------|--------|---------|
| `tcp-syn` | SYN | 0000 0010 | 2 |
| `tcp-ack` | ACK | 0001 0000 | 16 |
| `tcp-fin` | FIN | 0000 0001 | 1 |
| `tcp-rst` | RST | 0000 0100 | 4 |
| `tcp-psh` | PSH | 0000 1000 | 8 |
| `tcp-urg` | URG | 0010 0000 | 32 |

```bash
# SYN-ACK
tcpdump -i eth0 -nn 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# SYN only (not SYN-ACK)
tcpdump -i eth0 -nn 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
```

### VLAN and MPLS Filtering

```bash
# Capture VLAN-tagged traffic (802.1Q)
tcpdump -i eth0 -nn 'vlan'

# Capture specific VLAN ID
tcpdump -i eth0 -nn 'vlan 100'

# Capture MPLS traffic
tcpdump -i eth0 -nn 'mpls'
```

## 🛠️ Phase 7: tcpdump in Security Operations

### Workflow: Suspicious Host Triage

```
1. Identify suspicious IP from SIEM/alert
       ↓
2. Capture live traffic to/from IP
   tcpdump -i eth0 -nn host 10.0.0.99 -w suspect.pcap
       ↓
3. Analyse port usage
   tcpdump -r suspect.pcap -nn | awk '{print $4, $6}' | sort | uniq -c | sort -rn | head -20
       ↓
4. Check for beacon timing
   tcpdump -r suspect.pcap -nn -tttt | awk '{print $1, $2, $4, $6}' > timing.txt
       ↓
5. Extract payloads
   tcpdump -r suspect.pcap -A > payloads.txt
       ↓
6. Correlate with threat intel
```

### Stealthy/Production Capture Tips

```bash
# Write to ring buffer (3 files of 1GB each, rotate when full)
tcpdump -i eth0 -nn -s 0 -C 1000 -W 3 -w ring.pcap

# Capture with minimal overhead (no resolution, no promiscuous mode)
tcpdump -i eth0 -nn -p -s 256 -w minimal.pcap

# Background capture with nohup
nohup tcpdump -i eth0 -nn -s 0 -w background.pcap > /dev/null 2>&1 &

# Capture specific PID traffic via iptables + tcpdump
iptables -A OUTPUT -m owner --pid-owner 1234 -j LOG
tcpdump -i lo -nn 'port 80'
```

### Common Mistakes

| Mistake | Consequence | Fix |
|---------|-------------|-----|
| **Forgetting `-n`** | Capture stalling on DNS | Always use `-n` or `-nn` |
| **No BPF filter** | Captures everything (disk fills fast) | Always specify a filter |
| **Wrong interface** | Zero packets captured | Use `tcpdump -D` to list |
| **Snap length `-s 0`** | Huge pcap files | Use `-s 256` unless payload needed |
| **Filter too restrictive** | Missing evidence | Start broad, narrow after capture |
| **Writing to NFS/SMB** | Performance drop + packet loss | Always capture to local disk |

## 📝 Phase 8: Conclusion & Mastery Checklist

### Key Takeaways

1. **BPF filters operate at kernel level**—they discard unwanted packets before they reach user space, making them ideal for high-throughput environments
2. **Save first, filter later**—always capture broadly with `-w` to file, then analyse with Wireshark display filters to avoid losing evidence
3. **Raw offset filtering** gives you access to any byte in the packet header for scenarios where BPF primitives are insufficient
4. **Time-delta analysis** from tcpdump timestamps is a powerful technique for detecting beaconing and other regular-interval traffic

### Mastery Checklist

## tcpdump & BPF Proficiency Checklist

### Basic Usage
- [ ] List interfaces with `-D`
- [ ] Capture live packets with `-i`
- [ ] Suppress name/port resolution with `-n`/`-nn`
- [ ] Write captures to .pcap with `-w`
- [ ] Read captures with `-r`
- [ ] Limit packet count with `-c`
- [ ] Add verbosity with `-v`/`-vv`/`-vvv`

### BPF Filtering
- [ ] Filter by host, net, port, portrange
- [ ] Filter by protocol (tcp, udp, icmp, arp)
- [ ] Combine primitives with and/or/not
- [ ] Use src/dst qualifiers
- [ ] Filter by packet size (less/greater)

### Advanced BPF
- [ ] Raw byte offset filtering (ip[9], tcp[13])
- [ ] TCP flag matching (tcp-syn, tcp-ack, tcp-rst)
- [ ] VLAN/MPLS filtering
- [ ] Named flag constants

### Security Analysis
- [ ] Capture C2 beacon traffic
- [ ] Detect port scans (SYN-only, horizontal)
- [ ] Monitor DNS query patterns
- [ ] Identify large ICMP packets (covert channel)
- [ ] Extract payloads with `-A`/`-X`

### Production Operations
- [ ] Ring buffer rotation with `-C`/`-W`
- [ ] Background/nohup captures
- [ ] Minimal snap length for efficiency
- [ ] Local disk capture best practices
