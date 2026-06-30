---
tags: [packet-analysis, tcpdump]
---

# Reading and Interpreting tcpdump Output

## TCM Exam Objectives

Before taking the PSAA exam, you must be able to:

- Apply Berkeley Packet Filter (BPF) syntax to isolate network traffic by host, port, and protocol
- Capture packets to PCAP files using tcpdump with appropriate flags and filters
- Filter traffic by TCP flag combinations (SYN, SYN-ACK, RST, FIN) for attack detection
- Read and interpret tcpdump output including flags, sequence numbers, and options
- Identify anomalous traffic patterns including port scans, DNS tunneling, and beaconing
- Follow TCP streams to reconstruct application-layer conversations
- Analyze specific flag combinations to detect reconnaissance and scanning activity
- Document network forensic findings in a professional incident report

tcpdump output is the SOC analyst's first view into network traffic. Its default output is dense but extremely consistent � once the format is known, an analyst can scan hundreds of packets per minute to identify port scans, SYN floods, brute-force attempts, and data exfiltration directly from the terminal. Every line consists of timestamp, protocol, source, direction, destination, TCP flags, sequence numbers, window size, options, and packet length.?turn0search0??turn0search1?

- Anatomy of a single tcpdump line
- Critical tcpdump options that shape output
- Decoding TCP flags
- Reading ARP, UDP, and ICMP output
- Practical SOC analysis scenarios


## Anatomy of a Single tcpdump Line

**Default output example**:
```
12:34:56.789123 IP 192.168.1.100.54321 > 10.0.0.10.80: Flags [S], seq 123456789, win 65535, options [mss 1460,sackOK,TS val 123456 ecr 0,nop,wscale 7], length 0
```

| Field | Example | Meaning |
|-------|---------|---------|
| **Timestamp** | `12:34:56.789123` | Absolute time with microsecond precision |
| **Layer 3 Protocol** | `IP` | Network protocol (IP, IP6, ARP, ICMP) |
| **Source** | `192.168.1.100.54321` | Source IP address and port |
| **Direction** | `>` | Traffic flow source to destination |
| **Destination** | `10.0.0.10.80` | Destination IP address and port |
| **TCP Flags** | `Flags [S]` | Control bits set in the TCP header |
| **Sequence Number** | `seq 123456789` | Initial sequence number (relative unless -S) |
| **Acknowledgment** | `ack 987654321` | Acknowledgment number (when ACK flag set) |
| **Window Size** | `win 65535` | Advertised receive window in bytes |
| **TCP Options** | `options [mss 1460,...]` | MSS, SACK, timestamp, window scale |
| **Packet Length** | `length 0` | Payload length in bytes (excluding headers) |

**Always use `-n` or `-nn` in investigations** � this prevents DNS resolution and keeps IPs/ports as numbers, making analysis faster and more precise.

---

## Critical tcpdump Options

| Option | Purpose | SOC Analyst Note |
|--------|---------|------------------|
| `-n` | No DNS resolution | Keeps IPs as numbers |
| `-nn` | No port + IP resolution | Use this by default |
| `-v`, `-vv`, `-vvv` | Increasing verbosity | -v adds TTL, IP ID, total length |
| `-e` | Print link-layer header | Shows MAC addresses; vital for ARP spoofing |
| `-X` | Hex and ASCII payload | Best way to inspect application data |
| `-A` | ASCII payload only | Useful for HTTP, SMTP, Telnet |
| `-t` | Suppress timestamp | Cleaner output for pattern recognition |
| `-ttt` | Delta between packets | Reveals gaps, bursts, beacon intervals |
| `-S` | Absolute sequence numbers | Use for deep TCP analysis |
| `-c N` | Stop after N packets | Safe testing |
| `-i any` | Listen on all interfaces | See everything on a sensor |

**Typical investigation alias**: `tcpdump -nnev` (MACs, no name resolution, verbose).
---

```mermaid
flowchart LR
    PACKET[Raw Packet] --> TIMESTAMP[Timestamp: 12:34:56.789123]
    TIMESTAMP --> PROTO[Protocol: IP]
    PROTO --> SRC[Source: 192.168.1.100.54321]
    SRC --> DIR[Direction: >]
    DIR --> DST[Destination: 10.0.0.10.80]
    DST --> FLAGS[Flags: [S] - SYN]
    FLAGS --> SEQ[Sequence: seq 123456789]
    SEQ --> WIN[Window: win 65535]
    WIN --> OPTIONS[Options: mss 1460, sackOK]
    OPTIONS --> LEN[Length: 0]
```

## Decoding TCP Flags

TCP flags appear in square brackets after `Flags`.

| Flag | Meaning | Malicious Association |
|------|---------|----------------------|
| `S` | SYN | Many [S] without replies = SYN scan or flood |
| `A` or `.` | ACK | Normal data acknowledgment |
| `F` | FIN | Graceful close |
| `R` | RST | Abrupt reset; can indicate closed port or RST scan |
| `P` | PSH | Push data; large bursts = data transfer or exfiltration |
| `U` | URG | Urgent pointer (rare) |
| `.` after letter | ACK flag set | [S.] = SYN-ACK, [P.] = PSH+ACK |

### Normal TCP Handshake

```
client > server: Flags [S], seq 0, win 65535, length 0
server > client: Flags [S.], seq 0, ack 1, win 65535, length 0
client > server: Flags [.], ack 1, win 65535, length 0
```

If you see `[R]` instead of `[S.]`, the port is closed.

---

?? **Exam Tip:** When triaging alerts, prioritize by severity and potential business impact. A single true positive C2 alert is more critical than 1,000 false positive scan alerts.


## Reading ARP, UDP, and ICMP Output

### ARP
```
arp who-has 192.168.1.1 tell 192.168.1.100
arp reply 192.168.1.1 is-at 00:11:22:33:44:55
```
A flood of ARP requests from the same MAC indicates ARP scanning.

### UDP
```
12:34:56.789123 IP 192.168.1.100.54321 > 10.0.0.10.53: 12345+ A? www.example.com. (32)
```
No flags; length is UDP payload. Large responses indicate amplification or tunneling.

### ICMP
```
12:34:56.789123 IP 192.168.1.100 > 8.8.8.8: ICMP echo request, id 1, seq 1, length 64
```
Look for unusual type codes or oversized packets (potential ICMP tunneling).

---

## Practical SOC Analysis Scenarios

### Detecting a SYN Port Scan

```bash
tcpdump -nnr capture.pcap 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0'
```

Output: Rapid [S] packets from same source to different ports, no [S.] replies.

### Brute-Force Followed by Success

Multiple short [S] -> [S.] -> [.] connections, then a [P.] packet with large data push after fresh handshake � likely login credentials being sent after successful brute-force.

### DNS Tunneling

```
10.0.0.105.54321 > 8.8.8.8.53: 12345+ A? exfiltrated-data.malicious.com. (58)
10.0.0.105.54322 > 8.8.8.8.53: 12346+ TXT? aaaabbbbcccc.malicious.com. (512)
```

Large query lengths and repeated long subdomains indicate data being smuggled out.

### Abnormal PSH Flood

Continuous [P.] from an internal host to an external IP on a non-standard port with large segments (length 1400+) suggests a data transfer over a C2 channel.

---

## Best Practices for Quick Analysis

1. **Always `-n` or `-nn`** � DNS resolution destroys speed.
2. **Limit packets with `-c`** when exploring unknown captures.
3. **Add `-e`** if you suspect ARP spoofing.
4. **Use `-ttt`** to spot beaconing or time gaps instantly.
5. **Combine with `grep` and `awk`** to extract IPs, ports, or flags.
6. **Pre-filter with BPF** before reading.
7. **Save filtered PCAPs with `-w`** for deeper analysis in Wireshark.

---

## Analyst Cheat Sheet

| What You See | Flag Pattern | Likely Meaning |
|--------------|--------------|----------------|
| [S] repeated rapidly to different ports | [S] only | SYN port scan |
| [S] -> [R] | Source gets RST in response | Closed port |
| [S.] then normal data | [S.] + [P.] | Successful connection |
| [F.] after long idle | Graceful finish | Session ended normally |
| [R] after data flow | [R] | Aborted connection |
| win 0 | Window zero | Receiver overwhelmed |
| Large length on DNS (UDP/53) | length > 512 | Potential tunneling |

---

## Recap

```mermaid
flowchart TD
    TCPDUMP_OUT[tcpdump Output Line] --> EXTRACT_FLAGS[Read Flags Field]
    EXTRACT_FLAGS --> FLAG_PATTERN{Flag Pattern}
    FLAG_PATTERN -->|Many [S] no reply| SCAN[SYN Scan Detected]
    FLAG_PATTERN -->|[S] -> [S.] -> [.]| HANDSHAKE[Normal Handshake]
    FLAG_PATTERN -->|[S] -> [R]| CLOSED[Port Closed]
    FLAG_PATTERN -->|[P.] Large Data| DATA_TRANSFER[Data Transfer / Exfil]
    FLAG_PATTERN -->|DNS length > 512| TUNNEL[DNS Tunneling Suspected]
    SCAN --> SOURCE_IP[Identify Source IP]
    DATA_TRANSFER --> SOURCE_IP
    SOURCE_IP --> ACTION[Take Remediation Action]
```