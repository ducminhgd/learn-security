---
title: "nmap from First Principles — SYN Scan, Connect Scan, UDP Scan"
tags: [recon, active-recon, nmap, port-scanning, SYN-scan, UDP-scan, TCP-state-machine,
       T1046, network-service-discovery, bug-bounty]
module: 02-Recon-02
day: 63
related_topics:
  - IP Subnetting and TCP State Machine (Day 002)
  - Passive vs Active Recon and OpSec (Day 052)
  - nmap Service Detection NSE and Evasion (Day 064)
  - MITRE ATT&CK T1046 (Network Service Discovery)
---

# Day 063 — nmap from First Principles

## Goals

By the end of this lesson you will be able to:

1. Explain precisely what packets nmap sends for a SYN scan and why root privileges
   are required.
2. Distinguish between SYN scan, connect scan, UDP scan, and null/FIN/Xmas scans —
   and choose the right one for a given scenario.
3. Interpret all five nmap port states (open, closed, filtered, open|filtered,
   unfiltered).
4. Perform a targeted port scan, a full-range scan, and a top-1000 scan and explain
   what each output field means.
5. Understand the legal and ethical constraints that apply before scanning any target.

---

## Prerequisites

- [Day 002 — IP Subnetting and TCP State Machine](../01-Foundation-01/DAY-0002-IP-Subnetting-and-TCP-State-Machine.md)
- [Day 052 — Passive vs Active Recon and OpSec](../02-Recon-01/DAY-0052-Passive-vs-Active-Recon-and-OpSec.md)

---

## Main Content

> "Port scanning without understanding TCP is like lock-picking without
> understanding how a lock works. You might get in, but you will not know
> why, and you will not know when it fails."
>
> — Ghost

### 1. Why nmap Matters (and When to Use It)

Before touching nmap, understand the boundary:

```
Passive recon:  No packets reach the target. Target cannot detect you.
Active recon:   Packets reach the target. Logs will capture your source IP.
                A SYN scan IS active recon. Always.
```

**Before scanning in bug bounty context:**

1. Confirm the target IP/hostname is explicitly in scope.
2. Confirm the programme allows port scanning (most do; some explicitly ban it).
3. Use your scanning VPS, not your home IP.
4. Rate-limit: do not DoS the target.

MITRE ATT&CK maps port scanning to **T1046 — Network Service Scanning**.

---

### 2. The Ghost Method Applied

#### Recon (Stage 1) — How TCP Works Before Any Tool

A TCP connection requires the three-way handshake:

```
Client → SYN     → Server
Client ← SYN/ACK ← Server   (if port is open)
Client → ACK     → Server
```

nmap exploits the first two steps without completing the handshake (for SYN
scan). Understanding this is the difference between using nmap and understanding
nmap.

---

### 3. nmap Scan Types — Packet Level

#### 3.1 SYN Scan (-sS) — Default with Root

Also called a "half-open" or "stealth" scan. Sends a SYN, reads the response,
never completes the handshake.

```
nmap sends:  SYN
Target:      SYN/ACK  → port is OPEN
             RST      → port is CLOSED
             <nothing> → port is FILTERED (firewall drops the packet)

After receiving SYN/ACK, nmap sends RST (not ACK).
This means no full connection is logged by the application layer.
However, firewalls and IDS will still see the SYN.
```

**Why root is required:** Crafting a raw TCP SYN packet without completing
the OS TCP stack requires raw socket access, which requires root/Administrator.

```bash
# Basic SYN scan (requires root)
sudo nmap -sS 10.10.10.5

# Verify with Wireshark: capture on interface, filter: tcp.flags.syn == 1
```

#### 3.2 Connect Scan (-sT) — No Root Required

Uses the OS's `connect()` syscall. Completes the full three-way handshake.
Noisier — the full connection appears in the target's logs.

```
nmap calls: connect()
OS sends:   SYN
Target:     SYN/ACK
OS sends:   ACK → connection established
nmap sends: RST (to close)

Port states are the same as SYN scan, but application-layer connections
are logged.
```

```bash
# Connect scan (no root required)
nmap -sT 10.10.10.5
```

**When to use -sT:**
- When you cannot get root (e.g. scanning from a non-privileged account).
- When you need maximum accuracy and stealth does not matter.

#### 3.3 UDP Scan (-sU)

UDP has no handshake. nmap sends an empty (or protocol-specific) UDP packet.

```
nmap sends:  UDP packet
Target:      <nothing>          → OPEN or FILTERED (ambiguous — open|filtered)
             ICMP unreachable   → CLOSED (port is not listening)
             UDP response       → OPEN
```

**Why UDP scanning is slow:** nmap must wait for a response timeout for each
port. Rate-limiting (most systems limit ICMP unreachable to ~1/sec) makes UDP
scanning orders of magnitude slower than TCP scanning.

```bash
# UDP scan of top 100 UDP ports
sudo nmap -sU --top-ports 100 10.10.10.5

# Common critical UDP services: DNS 53, SNMP 161, TFTP 69, NTP 123
sudo nmap -sU -p 53,67,69,123,161,162,500,4500 10.10.10.5
```

#### 3.4 Null / FIN / Xmas Scans (-sN / -sF / -sX)

These exploit an RFC 793 quirk: when a non-SYN, non-RST packet arrives at a
closed port, the target MUST respond with RST. Open ports silently drop the
packet.

```
Null scan  (-sN): No TCP flags set
FIN scan   (-sF): FIN flag only
Xmas scan  (-sX): FIN + PSH + URG flags ("lit up like a Christmas tree")

Response:
  RST           → CLOSED
  <nothing>     → OPEN or FILTERED
```

**Important limitation:** These scans do not work reliably against Windows
targets. Windows always responds with RST regardless of port state, making
all ports appear closed.

```bash
sudo nmap -sN 10.10.10.5    # Null scan
sudo nmap -sF 10.10.10.5    # FIN scan
sudo nmap -sX 10.10.10.5    # Xmas scan
```

---

### 4. Port States Explained

| State | Meaning | How to identify |
|---|---|---|
| **open** | A service is actively accepting connections | SYN/ACK received (TCP), UDP response received |
| **closed** | Port is accessible but no service listening | RST received (TCP), ICMP unreachable (UDP) |
| **filtered** | A firewall is dropping packets silently | No response; SYN dropped, ICMP unreachable blocked |
| **open\|filtered** | Cannot determine — no response and could be open or filtered | UDP scan with no response |
| **unfiltered** | Port is accessible but state cannot be determined | ACK scan only; ACK gets through, no state inference |

---

### 5. Practical nmap Usage — Core Commands

#### 5.1 Target Specification

```bash
# Single host
nmap 10.10.10.5

# Multiple hosts
nmap 10.10.10.5 10.10.10.6 10.10.10.7

# CIDR range
nmap 10.10.10.0/24

# IP range notation
nmap 10.10.10.5-20

# From file
nmap -iL targets.txt

# Exclude hosts
nmap 10.10.10.0/24 --exclude 10.10.10.1
```

#### 5.2 Port Specification

```bash
# Single port
nmap -p 22 10.10.10.5

# Port range
nmap -p 1-1000 10.10.10.5

# Specific list
nmap -p 22,80,443,8080,8443 10.10.10.5

# Top N most common ports (by frequency data)
nmap --top-ports 100 10.10.10.5
nmap --top-ports 1000 10.10.10.5    # nmap's default

# All 65535 ports
nmap -p- 10.10.10.5

# Fast scan (top 100)
nmap -F 10.10.10.5
```

#### 5.3 Output Formats

```bash
# Normal output to file
nmap -oN scan_results.txt 10.10.10.5

# XML output (for parsing with tools)
nmap -oX scan_results.xml 10.10.10.5

# Grepable output
nmap -oG scan_results.gnmap 10.10.10.5

# All formats simultaneously
nmap -oA scan_results 10.10.10.5
# → scan_results.nmap, scan_results.xml, scan_results.gnmap

# JSON (via nmap-formatter tool)
nmap -oX - 10.10.10.5 | nmap-formatter json > scan_results.json
```

#### 5.4 Host Discovery

By default nmap pings before scanning. On a live target where you already
know the host is up, skip host discovery:

```bash
# Skip ping (treat host as up — important when ICMP is blocked)
nmap -Pn 10.10.10.5

# Ping sweep only (no port scan)
nmap -sn 10.10.10.0/24

# ARP ping (Layer 2 — only works on same subnet; most reliable local discovery)
sudo nmap -PR 192.168.1.0/24
```

---

### 6. Reading nmap Output

```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for target.lab (10.10.10.5)
Host is up (0.012s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
443/tcp  open     https
8080/tcp filtered http-proxy

Nmap done: 1 IP address (1 host up) scanned in 1.52 seconds
```

**What each field means:**

| Field | Meaning |
|---|---|
| `22/tcp open ssh` | Port 22, TCP, is open; nmap guesses service = ssh (by port number only, no version probe yet) |
| `8080/tcp filtered http-proxy` | Firewall is dropping packets to 8080 |
| `997 closed tcp ports (reset)` | 997 ports responded with RST — not shown for brevity |
| `0.012s latency` | Round-trip time — used for calibrating timing |

---

### 7. Minimal Lab Exercise

```bash
# Step 1: Start a lab target (use your Docker lab or TryHackMe/HTB)
# For local testing, use a known VM or a Docker container:
docker run -d -p 22:22 -p 80:80 -p 443:443 --name lab-target linuxserver/openssh-server

# Step 2: Confirm target is up
ping -c 1 <target-ip>

# Step 3: SYN scan top 1000 ports
sudo nmap -sS --top-ports 1000 <target-ip>

# Step 4: Full port scan (all 65535)
sudo nmap -sS -p- <target-ip>

# Step 5: UDP top 100
sudo nmap -sU --top-ports 100 <target-ip>

# Step 6: Save all results
sudo nmap -sS -p- -oA fullscan <target-ip>

# Step 7: Grep for open ports only
grep "open" fullscan.gnmap
```

---

### 8. What Gets Logged

Understanding what the defender sees is as important as what you get:

```
Apache access log: Only logs connections that reach the application layer.
                   -sS does NOT create application log entries.

Firewall log:      Sees every SYN packet regardless of scan type.
                   Source IP, destination IP, destination port, timestamp logged.

IDS (Suricata):    Will alert on nmap signatures, port scan rate, TTL values,
                   window size anomalies.

SIEM:              Correlates firewall events — 1000 SYNs in 1 second = port scan.
```

A SYN scan is NOT invisible. It is invisible to the application but visible
to any competent network monitoring setup.

---

## Key Takeaways

1. **A SYN scan is not a stealth scan — it is a half-open scan.** The SYN packet
   leaves a trace in every firewall and IDS. "Stealth" refers to avoiding full
   application connections, not avoiding detection entirely.
2. **Port state is determined by what nmap receives in response to its probe.**
   SYN/ACK = open, RST = closed, silence = filtered. This is all nmap is doing
   at the packet level.
3. **UDP scanning is slow by design.** Rate limiting of ICMP unreachable responses
   forces nmap to wait. Budget 10–30 minutes for a UDP scan of common ports.
4. **-Pn skips host discovery.** In bug bounty scenarios, targets often block
   ICMP. If nmap says "host down" but you know it is up, add -Pn.
5. **Always save output with -oA.** You will reference scan results repeatedly.
   Rescan noise is wasted scan budget and creates unnecessary log noise on the
   target.

---

## Exercises

### Exercise 1 — Port State Analysis

Without using nmap, determine what port state would be reported in each scenario:

1. You send a SYN to port 443. You receive a SYN/ACK back.
2. You send a SYN to port 8888. You receive a RST back.
3. You send a SYN to port 9200. No response after 3 retries.
4. You send a UDP packet to port 161. You receive an ICMP Port Unreachable back.
5. You send a UDP packet to port 53. No response after 3 retries.

---

### Exercise 2 — Core Scan Commands

On a lab target (your own Docker container or a TryHackMe machine):

1. Run a SYN scan of the top 1000 ports. How many are open?
2. Run a full -p- scan. Did it find any ports the top-1000 scan missed?
3. Run a UDP scan of the top 100 ports. Note how much longer it takes.
4. Save all results with -oA and examine the .gnmap file. Write a one-liner using
   `grep` and `awk` to extract just the open port numbers.

---

### Exercise 3 — Packet Analysis

1. Start a Wireshark capture on your scanning interface.
2. Run: `sudo nmap -sS -p 80,443,8080 <target>`
3. Apply filter: `tcp.flags.syn == 1 && !tcp.flags.ack`
4. Count how many SYN packets were sent.
5. For each: what was the response? Match each response to a port state.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 062 — Subdomain Takeover and Dangling DNS](../02-Recon-01/DAY-0062-Subdomain-Takeover-and-Dangling-DNS.md)*
*Next: [Day 064 — nmap Service Detection, NSE and Evasion](DAY-0064-nmap-Service-Detection-NSE-and-Evasion.md)*
