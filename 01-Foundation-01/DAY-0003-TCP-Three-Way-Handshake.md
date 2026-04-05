---
title: "TCP Three-Way Handshake — State Machine, Flags, and What a Scanner Sees"
tags: [foundation, networking, tcp, handshake, port-scanning, nmap, dos, attacker-mindset]
module: 01-Foundation-01
day: 3
related_topics:
  - OSI Model (Layer 4 — Transport)
  - IP Addressing and Subnetting
  - UDP and ICMP
  - nmap port scanning
  - Firewall evasion
  - SYN flood DoS
---

# Day 003 — TCP Three-Way Handshake

## Goals

By the end of this lesson you will be able to:

1. Name the key fields in a TCP header and explain what each one does.
2. Describe the three-way handshake step by step, including what each packet contains.
3. Draw the TCP state machine and identify the states you will see on a live system.
4. Explain the difference between a graceful connection teardown (FIN) and an abrupt reset (RST).
5. Explain what `nmap -sS` does at the TCP level and why it differs from `nmap -sT`.
6. Map each nmap port state (`open`, `closed`, `filtered`) to the TCP response that produces it.
7. Describe three attack techniques that exploit TCP's design — SYN flood, RST injection, and
   session hijacking — and state the underlying assumption each one abuses.

---

## Prerequisites

- [Day 001 — OSI Model](DAY-0001-OSI-Model-and-Why-It-Matters.md): TCP is a Layer 4 protocol.
  You need to know what Layer 4 does.
- [Day 002 — IP Addressing and Subnetting](DAY-0002-IP-Addressing-and-Subnetting.md): TCP segments
  travel inside IP packets. Port numbers live at Layer 4; IP addresses live at Layer 3.

---

## Main Content

### 1. Why TCP Exists — The Reliability Contract

IP is unreliable by design. An IP packet can be dropped, duplicated, reordered, or silently
discarded by any router along the path. IP does not know or care. It is a best-effort delivery
service.

**TCP** (Transmission Control Protocol, RFC 793) sits on top of IP and provides a **reliability
layer**. Its contract with the application is:

- Every byte you send will arrive at the other end.
- Bytes will arrive in the order you sent them.
- If the other end stops receiving, you will be told.

TCP achieves this through **sequence numbers**, **acknowledgements**, **retransmission**, and
**flow control**. Every one of those mechanisms is also an attack surface.

> **Ghost's rule:** TCP's reliability guarantees require *state* — both sides must track what has
> been sent and received. State is expensive, and state can be exhausted. That is the root cause of
> every SYN flood DoS attack ever written.

---

### 2. The TCP Header — Fields That Matter to Security

A TCP segment header is 20 bytes minimum. You do not need to memorise every field, but you need to
know these:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────────────────┬───────────────────────────────────────┤
│      Source Port (16)     │      Destination Port (16)            │
├───────────────────────────────────────────────────────────────────┤
│                    Sequence Number (32)                           │
├───────────────────────────────────────────────────────────────────┤
│                 Acknowledgement Number (32)                       │
├────────────┬──────────────┬───────────────────────────────────────┤
│ Data Offset│   Reserved   │  Flags (9 bits)    │  Window Size(16) │
├────────────┴──────────────┴────────────────────┴──────────────────┤
│              Checksum (16)          │     Urgent Pointer (16)     │
└───────────────────────────────────────────────────────────────────┘
```

| Field | Size | Security relevance |
|-------|------|--------------------|
| **Source Port** | 16 bits | Ephemeral (1024–65535); can be spoofed |
| **Destination Port** | 16 bits | Identifies the service; primary target of a port scan |
| **Sequence Number** | 32 bits | Tracks byte position; predictable ISNs enable session hijacking |
| **Acknowledgement Number** | 32 bits | Next expected byte; must be correct to inject data |
| **Flags** | 9 bits | Control bits — the language of the TCP state machine |
| **Window Size** | 16 bits | Flow control; also used for OS fingerprinting |
| **Checksum** | 16 bits | Integrity check over header + data; does not provide auth |

#### TCP Flags — The Ones You Need to Know Cold

| Flag | Full name | What it means |
|------|-----------|---------------|
| **SYN** | Synchronise | "I want to start a connection; here is my initial sequence number" |
| **ACK** | Acknowledge | "I have received up to byte N" |
| **FIN** | Finish | "I have no more data to send; begin teardown" |
| **RST** | Reset | "Abort the connection immediately; discard all state" |
| **PSH** | Push | "Deliver this to the application now, do not buffer" |
| **URG** | Urgent | "Some data in this segment is urgent; check the urgent pointer" |

SYN, ACK, FIN, and RST are the four you will see constantly in Wireshark, nmap output, and firewall
logs. The others are less common but URG has been used in evasion attacks against older IDS systems.

---

### 3. The Three-Way Handshake

Before any data flows, TCP performs a handshake to:

1. Exchange **Initial Sequence Numbers (ISN)** — the starting byte count for each direction.
2. Confirm that both sides are reachable and ready to communicate.
3. Agree on window sizes.

```
Client                                  Server
  │                                       │
  │  ── SYN (seq=x) ──────────────────►  │   Step 1: Client sends SYN
  │                                       │   Seq=x (random ISN)
  │                                       │   No data yet
  │                                       │
  │  ◄── SYN-ACK (seq=y, ack=x+1) ────  │   Step 2: Server replies SYN-ACK
  │                                       │   Seq=y (server's random ISN)
  │                                       │   Ack=x+1 ("I got your SYN; send byte x+1 next")
  │                                       │
  │  ── ACK (seq=x+1, ack=y+1) ───────►  │   Step 3: Client acknowledges
  │                                       │   Ack=y+1 ("I got your SYN-ACK; send byte y+1 next")
  │                                       │
  │         [Connection ESTABLISHED]      │
  │                                       │
  │  ── HTTP GET / ────────────────────►  │   Data flows now
```

**Key detail: the ISN is supposed to be random.** Before 1996, many systems used predictable ISNs
(incrementing counters or time-based values). Kevin Mitnick exploited predictable ISNs in the
famous 1994 Tsutomu Shimomura attack to forge a TCP session without completing the handshake — the
first documented TCP session hijacking in the wild.

Modern OSes use cryptographically random ISNs. Predictable ISNs are still found in embedded
devices and poorly implemented TCP stacks.

---

### 4. TCP Connection Teardown

#### 4.1 Graceful Close — The Four-Way FIN Handshake

TCP connections are **full-duplex**: data flows in both directions independently. Closing a
connection requires each side to close its own direction.

```
Client                                  Server
  │                                       │
  │  ── FIN (seq=u) ──────────────────►  │   Client: "I'm done sending"
  │  ◄── ACK (ack=u+1) ────────────────  │   Server: "Got your FIN"
  │                                       │   [Server may still send data]
  │  ◄── FIN (seq=v) ──────────────────  │   Server: "I'm done sending too"
  │  ── ACK (ack=v+1) ─────────────────► │   Client: "Got your FIN"
  │                                       │
  │         [Connection CLOSED]           │
```

In practice, the server's ACK and FIN are often combined into a single SYN-ACK-like packet,
making it look like a three-way close.

#### 4.2 Abrupt Reset — RST

A RST packet says: **"Stop. Forget this connection existed. Now."** No acknowledgement, no
graceful teardown. RST is used when:

- A packet arrives for a port that has no listener (the OS sends RST).
- A firewall rejects a connection and sends RST (a "reject" rule, not a "drop" rule).
- An application detects an error and aborts.
- An attacker injects a RST to terminate a live connection (RST injection).

**RST vs no-response:**

| Scenario | What the sender gets back |
|----------|--------------------------|
| Port is open, service is listening | SYN-ACK |
| Port is closed, no firewall | RST-ACK |
| Port is firewalled (DROP rule) | Nothing (timeout) |
| Port is firewalled (REJECT rule) | RST-ACK (or ICMP port unreachable) |

This difference — RST vs silence — is exactly what nmap uses to distinguish `closed` from
`filtered`.

---

### 5. The TCP State Machine

TCP tracks connection progress through a set of named states. You will see these in `ss -tn` or
`netstat -tn` output on any Linux or Windows host.

```
                         ┌─────────────────┐
                         │     CLOSED      │
                         └────────┬────────┘
                    passive open  │  active open (SYN sent)
                                  │
               ┌──────────────────▼──────────────────┐
               │             LISTEN                   │  ← server waiting
               └──────────────┬──────────────────────┘
                      SYN recv │
                               ▼
               ┌───────────────────────────────────────┐
               │           SYN_RECEIVED                │  ← server got SYN, sent SYN-ACK
               └──────────────┬──────────────────────┘
                      ACK recv │
                               ▼
               ┌───────────────────────────────────────┐
               │           ESTABLISHED                 │  ← data transfer
               └──────────────┬──────────────────────┘
                   FIN sent /  │  / FIN recv
                      ┌────────┴────────┐
                      ▼                 ▼
              ┌──────────────┐  ┌──────────────────┐
              │  FIN_WAIT_1  │  │   CLOSE_WAIT     │  ← remote side closed first
              └──────┬───────┘  └────────┬─────────┘
                     │                   │ (app sends FIN)
                     ▼                   ▼
              ┌──────────────┐  ┌──────────────────┐
              │  FIN_WAIT_2  │  │    LAST_ACK      │
              └──────┬───────┘  └────────┬─────────┘
                     │ FIN recv           │ ACK recv
                     ▼                   ▼
              ┌──────────────┐        CLOSED
              │  TIME_WAIT   │  ← waits 2×MSL before releasing port
              └──────┬───────┘
                     │ timer expires
                     ▼
                   CLOSED
```

**States you will see in practice:**

| State | What it means | Attacker relevance |
|-------|--------------|-------------------|
| `LISTEN` | Port is open, waiting for connections | Target for scanning |
| `SYN_RECEIVED` | Half-open connection — SYN received, SYN-ACK sent, waiting for ACK | SYN flood fills this table |
| `ESTABLISHED` | Active data connection | Session hijacking targets these |
| `TIME_WAIT` | Waiting 2×MSL after close (default: 60–120 seconds) | High TIME_WAIT count → resource exhaustion |
| `CLOSE_WAIT` | Remote closed; local app hasn't called close() | Leaked connections → app bugs |

---

### 6. Port States — What a Scanner Sees

When nmap sends a probe packet to a port, the response (or lack of one) tells it the port's state.

| nmap state | What happened at the TCP level | Meaning |
|------------|-------------------------------|---------|
| `open` | SYN-ACK received | Something is listening |
| `closed` | RST-ACK received | Port reachable, nothing listening |
| `filtered` | No response (timeout) or ICMP unreachable | Packet dropped/blocked by firewall |
| `open\|filtered` | No response on a UDP or stealth scan | Cannot tell if open or filtered |
| `unfiltered` | RST received on ACK scan | Port reachable but state unknown |

---

### 7. nmap Scan Types — What They Do at the TCP Level

This is where theory meets the tool. You need to understand what happens on the wire for each scan
type — not just which flag to pass.

#### 7.1 TCP Connect Scan (`-sT`) — Full Handshake

```
nmap -sT 10.10.10.1
```

```
Scanner                     Target
   │── SYN ───────────────►  │
   │◄── SYN-ACK ────────────  │   (port open: complete the handshake)
   │── ACK ───────────────►  │   ← connection established
   │── RST or FIN ─────────►  │   ← immediately tear down
```

- Uses the OS's `connect()` system call — the kernel does the handshake.
- **Logged by the target.** The connection reaches ESTABLISHED state; any application listening
  will see a connection and likely log it.
- No special privileges required — any user can run it.
- Slower and noisier than SYN scan.

#### 7.2 SYN Scan / Half-Open Scan (`-sS`) — The Default

```
nmap -sS 10.10.10.1   # requires root/administrator
```

```
Scanner                     Target (port open)
   │── SYN ───────────────►  │
   │◄── SYN-ACK ────────────  │
   │── RST ────────────────►  │   ← scanner sends RST before ACK; connection never established

Scanner                     Target (port closed)
   │── SYN ───────────────►  │
   │◄── RST-ACK ────────────  │   ← immediate reset
```

- The scanner **never completes the handshake** — it resets the connection after receiving
  SYN-ACK.
- The connection never reaches ESTABLISHED state; many applications never log it.
- Faster than connect scan; requires raw socket access (root/admin).
- Still detectable at the network level — a half-open connection to every port in sequence is a
  clear signature in firewall or IDS logs.

#### 7.3 NULL, FIN, and XMAS Scans — Firewall Evasion Attempts

These scans exploit an RFC 793 rule: **if a closed port receives a segment with no SYN/RST/ACK
flags set, it must respond with RST.** An open port should silently drop the packet.

```
NULL scan  (-sN):   No flags set       → Flags = 0x00
FIN scan   (-sF):   Only FIN set       → Flags = 0x01
XMAS scan  (-sX):   FIN + PSH + URG    → Flags = 0x29  (all the "Christmas lights")
```

| Response | Port state |
|----------|-----------|
| RST | Closed |
| No response | Open or filtered |

**Why they exist:** Old, stateless packet filters allowed these through because they only checked
for SYN packets. Stateful firewalls (which most modern ones are) track connection state and drop
these probes regardless.

**Ghost's note:** These scans only work against RFC-compliant TCP stacks. Windows does not follow
RFC 793 exactly — it sends RST for both open and closed ports on these probes, making the results
unreliable on Windows targets.

#### 7.4 ACK Scan (`-sA`) — Firewall Rule Mapping

```
nmap -sA 10.10.10.1
```

Sends an ACK packet (no SYN — not a connection attempt). The purpose is not to find open ports but
to **map firewall rules**:

- If RST is received → the port is **unfiltered** (the packet reached the host).
- If no response → the port is **filtered** (packet was dropped by a stateful firewall).

This tells you which ports are blocked by the firewall, which is different from which ports have
services running.

---

### 8. Attack Techniques Rooted in TCP

#### SYN Flood — CWE-400 / ATT&CK T1498.001

**What it is:**
A denial-of-service attack that exhausts the server's half-open connection table by sending
thousands of SYN packets and never completing the handshake.

**Why it works:**
When a server receives a SYN, it allocates memory for the half-open connection (SYN_RECEIVED
state), sends a SYN-ACK, and waits for the final ACK. The queue of half-open connections is finite.
If an attacker sends SYNs faster than the timeout clears them, the queue fills. Legitimate SYNs get
dropped because there is no room.

**How to spot it in the wild:**
Large number of connections in `SYN_RECEIVED` state in `ss -tn`. Spike in SYN packets without
corresponding ACKs in a packet capture or firewall log.

**Minimal exhibit:**
```bash
# What a SYN flood looks like in ss output on the target
ss -tn state syn-recv
# Thousands of rows, all from spoofed source IPs, none completing
```

**Real-world case:**
GitHub was hit with a 1.35 Tbps SYN flood in February 2018 — at the time the largest DDoS ever
recorded. Memcached amplification was layered on top. GitHub survived because Akamai Prolexic
absorbed the traffic.

**Fix:**
SYN cookies: when the SYN queue is full, the server encodes session state in the SYN-ACK sequence
number instead of storing it in memory. The ACK from the client carries enough information to
reconstruct the connection. Enable with: `sysctl -w net.ipv4.tcp_syncookies=1` on Linux.

---

#### TCP Session Hijacking — CWE-294 / ATT&CK T1557

**What it is:**
An attacker injects packets into an existing TCP connection by guessing or obtaining the correct
sequence numbers, impersonating one side of the session.

**Why it works:**
TCP validates packets using sequence numbers, not cryptographic authentication. If an attacker can
observe (or predict) the sequence numbers in use, they can craft a valid TCP segment that the
receiver accepts as legitimate.

**How to spot it in the wild:**
Sequence number anomalies in a packet capture — a packet in the middle of a stream with a sequence
number that does not continue where the last packet left off. Out-of-order delivery spikes on the
target.

**Real-world case:**
The Mitnick/Shimomura attack (1994). Mitnick observed TCP traffic to a trusted host, predicted the
ISN using the then-predictable algorithm, forged a connection from the trusted host's IP, and issued
commands to a shell without knowing the trusted host's private key.

**Fix:**
Encrypt the session (TLS/SSH). Randomised ISNs make prediction infeasible but do not prevent
hijacking if the attacker can observe traffic. Without encryption, the session content is visible
and sequence numbers can be read directly.

---

#### RST Injection — ATT&CK T1557

**What it is:**
An attacker sends a forged RST packet to one or both parties in an established TCP connection,
causing them to abort the session.

**Why it works:**
A RST packet is accepted if the sequence number falls within the receiver's acceptable window
(the receive window). An attacker who can observe traffic knows the sequence numbers and can forge
a valid RST. The connection is terminated immediately — no logging by the application in most
cases.

**How to spot it in the wild:**
Unexpected RSTs in a packet capture, especially mid-session (not at connection close). Pattern of
sessions being terminated before completion.

**Real-world case:**
The Great Firewall of China uses RST injection to terminate TCP connections to blocked content.
A connection to a blocked site gets interrupted by forged RST packets injected by network equipment
between the user and the server.

**Fix:**
Encrypted sessions (TLS) do not prevent the RST from aborting the TCP connection — RST operates
at Layer 4 below TLS — but they prevent the content from being read. More robust: QUIC (HTTP/3)
uses UDP and handles connection identity at the application layer, so it is not vulnerable to TCP
RST injection.

---

### 9. TCP in the Attacker's Workflow

```
Stage            Tool/Technique                 What TCP knowledge enables
─────────────────────────────────────────────────────────────────────────────────
Recon            nmap -sS -p- 10.10.10.1        Find every open port via SYN scan
                 nmap -sA 10.10.10.1             Map firewall rules
                 nmap -sV 10.10.10.1             Banner grab: SYN→ACK→send probe→read banner

Post-exploit     ss -tnp                         See all open/established connections + PID
                 ss -tn state established        What connections are active right now?
                 ss -tn state listen             What ports is this host serving?

DoS              hping3 --syn -p 80 --flood      SYN flood a target port
                 [spoofed source IPs]            Makes SYN cookies the only mitigation

Evasion          nmap -sF / -sN / -sX            Bypass stateless ACL rules
                 nmap --source-port 53           Use a trusted source port to bypass filters

Lateral move     Connect through pivot host      TCP connection through a compromised host
                 socat TCP-LISTEN:4444 ...       Port forward over TCP tunnels
```

**Reading a TCP connection table on a compromised host:**

```bash
# Show all TCP connections with process names
ss -tnp

# Look for ESTABLISHED connections to unusual destinations
ss -tn state established

# Check what is listening (open ports you might be able to tunnel to)
ss -tnlp

# On Windows
netstat -ano        # -a all, -n no DNS, -o show PID
```

The output of `ss -tnp` is a map of the host's active network relationships: what it is talking
to, which process owns each connection, and which ports you can pivot through.

---

## Key Takeaways

1. TCP's reliability guarantee requires **state**. State costs memory. The SYN_RECEIVED table is
   finite — exhaust it and the host stops accepting new connections. That is a SYN flood.

2. The **four key flags** are SYN, ACK, FIN, RST. Every port scanner, every session attack, every
   firewall rule is ultimately making decisions based on these four bits.

3. `nmap -sS` sends SYN, waits for SYN-ACK (open) or RST (closed) or nothing (filtered), then
   resets without completing the handshake. It is faster and quieter than a full connect scan but
   still detectable at the network layer.

4. **RST means stop immediately; FIN means I am done sending.** A closed port sends RST. A
   firewall `DROP` rule sends nothing. This distinction is how you tell a closed port from a
   filtered port without needing to know the firewall rules.

5. **Sequence numbers are the only thing preventing TCP injection.** Without TLS, any on-path
   attacker who can observe the sequence numbers owns the session.

6. `ss -tnp` on a compromised host tells you the entire network relationship map of that machine —
   what it is connected to, what it is listening on, and which process owns each socket.

---

## Exercises

### Exercise 1 — Flag Reading

For each TCP packet description, state what it means and what the receiver should do:

1. `Flags: SYN` — sent to port 443 on a server with no service on that port.
2. `Flags: SYN-ACK` — received by a client after sending a SYN.
3. `Flags: RST-ACK` — received by a client that sent a SYN to port 22 on a remote host.
4. `Flags: FIN-ACK` — received in the middle of a file download.
5. `Flags: PSH-ACK` — received after the three-way handshake is complete.
6. `Flags: 0x00` (NULL) — sent to a port with no SYN, RST, or ACK set.

---

### Exercise 2 — Scan Type Identification

For each nmap command, answer: what flag(s) are sent in the probe packet, what response indicates
an open port, and what response indicates a closed port?

1. `nmap -sT 10.0.0.1`
2. `nmap -sS 10.0.0.1`
3. `nmap -sF 10.0.0.1`
4. `nmap -sN 10.0.0.1`
5. `nmap -sA 10.0.0.1`

---

### Exercise 3 — State Machine Trace

Trace the TCP state machine for the following scenarios. Write the sequence of states each side
passes through.

**Scenario A:** A client connects to a web server, downloads a page, and the server closes the
connection first.

**Scenario B:** A client sends a SYN to a port with no service listening. What state does the
server reach and what does it send back?

**Scenario C:** A client connects to a server. Midway through the transfer, the server crashes.
The client sends the next data segment. What does the server's OS send back, and from which state?

---

### Exercise 4 — Attacker Thinking

1. You run `nmap -sS 192.168.1.50` and get:

   ```
   PORT     STATE    SERVICE
   22/tcp   open     ssh
   80/tcp   open     http
   443/tcp  filtered https
   8080/tcp closed   http-proxy
   ```

   For each port state, describe exactly what TCP response nmap received. What does `filtered`
   tell you about the network architecture?

2. You are on a compromised Linux host. You run `ss -tnp` and see a connection from the host to
   `10.0.5.12:5432` in ESTABLISHED state. What have you found, and what is your next action?

3. A SYN flood is in progress against a web server. The server admin enables SYN cookies. Explain
   in one paragraph exactly what SYN cookies do and why they stop the attack without blocking
   legitimate traffic.

4. You intercept TCP traffic between two hosts that are not using TLS. The current segment shows
   `seq=4200, ack=8800`. You want to inject a command into this session. What two values must
   your forged packet carry, and why?

---

### Lab Prep — Coming in Day 013

In the Wireshark lab you will open a packet capture and trace a complete TCP three-way handshake,
data exchange, and teardown. Before that lab, you should be able to identify a SYN packet by
its flags in Wireshark's packet detail panel, follow a TCP stream (`Follow → TCP Stream`), and
explain what the sequence numbers mean at each step. Practice that mental model now — it will make
the lab fast instead of confusing.

---

## Questions

<!-- Ghost's note: use this section to log your questions as you study.
     Ask Ghost to answer them, or write your own answer and ask for a review.
     Each question gets a Global ID (format: Q<day>.<sequence>).
     Follow-up questions are Q<day>.<sequence>.<sub-sequence>. -->

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous lesson: [Day 002 — IP Addressing and Subnetting](DAY-0002-IP-Addressing-and-Subnetting.md)*
*Next lesson: [Day 004 — UDP and ICMP](DAY-0004-UDP-and-ICMP.md)*
