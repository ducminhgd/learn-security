---
title: "IP Addressing, Subnetting and TCP State Machine"
tags: [foundation, networking, ip, ipv4, ipv6, cidr, tcp, three-way-handshake, attacker-mindset]
module: 01-Foundation-01
day: 2
related_topics:
  - OSI Model (Layer 3 and Layer 4)
  - nmap and port scanning
  - Network reconnaissance
  - Firewall evasion
---

# Day 002 — IP Addressing, Subnetting and TCP State Machine

## Goals

By the end of this lesson you will be able to:

1. Convert between dotted-decimal, binary, and CIDR notation for IPv4.
2. Calculate the network address, broadcast address, and usable host range for any CIDR block.
3. Identify reserved and special-purpose IPv4 ranges from memory.
4. Describe the structure of an IPv6 address and its major address types.
5. Explain the TCP three-way handshake step-by-step, including all six TCP flags.
6. Describe the TCP state machine and what each state looks like to a port scanner.
7. Explain how SYN scans work and why they leave a half-open connection.
8. Describe three ways that knowledge of IP and TCP directly enables offensive actions.

---

## Prerequisites

- [Day 001 — OSI Model and TCP/IP Stack](DAY-0001-OSI-Model-and-TCP-IP-Stack.md): understand
  that IP is Layer 3 and TCP is Layer 4. Today builds directly on that.

---

## Main Content — Part 1: IP Addressing and Subnetting

### 1. Why IP Addressing Matters to an Attacker

An IP address is a map coordinate. When you land on a machine, `ip addr` (Linux) or
`ipconfig /all` (Windows) immediately tells you:

1. **Where you are** — your position in the address space relative to other hosts.
2. **Who else is nearby** — the subnet defines who you can reach without routing.
3. **The blast radius** — compromising a host in a /24 means 253 potential pivot targets
   accessible at Layer 2 without going through a firewall.

The subnet mask is not just a network detail — it is an attack surface boundary.

---

### 2. IPv4 Addressing

An IPv4 address is 32 bits, written as four octets in dotted-decimal notation:

```
192.168.1.100  =  11000000.10101000.00000001.01100100
```

Every IP address has two parts:
- **Network portion** — identifies which subnet the host belongs to.
- **Host portion** — identifies the specific host within that subnet.

The subnet mask defines the boundary:

```
IP address:   192.168.1.100   =  11000000.10101000.00000001.01100100
Subnet mask:  255.255.255.0   =  11111111.11111111.11111111.00000000
                                  ──────── network ────────  ─ host ─
```

**CIDR notation** (Classless Inter-Domain Routing) expresses the mask as a prefix length:
`192.168.1.0/24` means the first 24 bits are the network portion.

---

### 3. Subnet Arithmetic

For any CIDR block, you need to quickly calculate:

| Value | How to get it |
|---|---|
| Network address | Host bits all zeroed |
| Broadcast address | Host bits all set to 1 |
| Usable hosts | 2^(host bits) − 2 |
| First usable host | Network address + 1 |
| Last usable host | Broadcast address − 1 |

**Example: 10.0.5.0/25**

```
/25 = 25 network bits, 7 host bits
Network address:    10.0.5.0   (host bits = 0000000)
Broadcast address:  10.0.5.127 (host bits = 1111111)
Usable hosts:       2^7 − 2 = 126
Range:              10.0.5.1 – 10.0.5.126
```

**Attacker shortcut:** `/24` = 254 hosts, `/23` = 510 hosts, `/16` = 65,534 hosts.
A single compromised machine in a /16 has over 65,000 potential neighbours.

---

### 4. Special and Reserved IPv4 Ranges

These are critical for recon and attack planning. Memorise them.

| Range | Purpose | Attacker relevance |
|---|---|---|
| `10.0.0.0/8` | Private (RFC 1918) | Internal network; lateral movement targets |
| `172.16.0.0/12` | Private (RFC 1918) | Internal network |
| `192.168.0.0/16` | Private (RFC 1918) | Home/office internal network |
| `127.0.0.0/8` | Loopback | SSRF target: `127.0.0.1`, `localhost` |
| `169.254.0.0/16` | Link-local (APIPA) | Cloud metadata: `169.254.169.254` (AWS) |
| `100.64.0.0/10` | Shared address space | ISP CGN; not reachable externally |
| `0.0.0.0/8` | "This" network | Source in DHCP discover; SSRF bypass |
| `224.0.0.0/4` | Multicast | mDNS poisoning targets (224.0.0.251) |
| `255.255.255.255/32` | Limited broadcast | Layer 2 broadcast; DHCP |

`169.254.169.254` is the **AWS Instance Metadata Service (IMDS)** endpoint. If you can make a
server-side request to it (SSRF), you can extract IAM credentials. This address appears in more
bug bounty P1s than almost any other.

---

### 5. IPv6 Addressing

IPv6 addresses are 128 bits, written as eight 16-bit groups in hexadecimal:

```
2001:0db8:85a3:0000:0000:8a2e:0370:7334
```

Rules for shortening:
- Leading zeros in each group can be omitted: `0db8` → `db8`
- One consecutive run of all-zero groups can be replaced with `::`:
  `2001:db8:0:0:0:0:0:1` → `2001:db8::1`

**Key IPv6 address types:**

| Prefix | Type | Notes |
|---|---|---|
| `::1/128` | Loopback | Equivalent to 127.0.0.1 |
| `fe80::/10` | Link-local | Not routable; auto-assigned on every interface |
| `fc00::/7` | Unique local | Private equivalent of RFC 1918 |
| `ff00::/8` | Multicast | All nodes: `ff02::1`; all routers: `ff02::2` |
| `2001:db8::/32` | Documentation | Example addresses only; never in prod |

**Attacker relevance:** Many organisations enable IPv6 without monitoring it. SLAAC
(Stateless Address Autoconfiguration) auto-assigns addresses. If you can spoof a router
advertisement, every host on the link reconfigures its default gateway to you.

---

## Main Content — Part 2: TCP State Machine

### 6. TCP Headers and Flags

The TCP header contains these critical fields for attackers:

| Field | Size | Purpose |
|---|---|---|
| Source port | 16 bits | Ephemeral port of sender |
| Destination port | 16 bits | Service port (e.g. 80, 443, 22) |
| Sequence number | 32 bits | Position of this segment in the data stream |
| Acknowledgement number | 32 bits | Next expected sequence number from the other side |
| Flags | 9 bits | Control bits (see below) |
| Window size | 16 bits | Flow control — how much data receiver can accept |

**The six classic TCP flags:**

| Flag | Bit | Meaning |
|---|---|---|
| **SYN** | `0x02` | Synchronise — initiate connection |
| **ACK** | `0x10` | Acknowledgement — confirms received data |
| **FIN** | `0x01` | Finish — graceful connection close |
| **RST** | `0x04` | Reset — abrupt connection termination |
| **PSH** | `0x08` | Push — deliver data to application immediately |
| **URG** | `0x20` | Urgent — rarely used; prioritise data |

A SYN packet has only the SYN flag set. A SYN-ACK has both SYN and ACK set. An RST tears
down the connection immediately — this is what a closed port returns to a SYN scan.

---

### 7. The Three-Way Handshake

Before any TCP data exchange, both sides must agree on initial sequence numbers:

```
Client                          Server
  │                               │
  │──── SYN (seq=x) ────────────►│   Step 1: Client proposes ISN x
  │                               │
  │◄─── SYN-ACK (seq=y, ack=x+1)─│   Step 2: Server proposes ISN y, ACKs x
  │                               │
  │──── ACK (ack=y+1) ──────────►│   Step 3: Client ACKs y
  │                               │
  │═══════ Data flows ════════════│
```

**Why sequence numbers matter to an attacker:**
- Old systems with predictable ISNs were vulnerable to **blind TCP injection** — an attacker
  could forge packets without being on the path (no longer practical on modern kernels with
  random ISNs, but understanding the mechanic matters).
- Sequence number prediction is how **idle scan** (`nmap -sI`) works — using a zombie host
  with predictable IPID values to scan a target invisibly.

---

### 8. Connection Termination

A graceful close uses four steps (FIN-ACK exchange):

```
Client          Server
  │──── FIN ──►│    Client done sending
  │◄─── ACK ───│    Server ACKs
  │◄─── FIN ───│    Server done sending
  │──── ACK ──►│    Client ACKs
  └────────────┘    Connection closed
```

An **RST** (reset) closes the connection immediately with no cleanup. Port scanners rely on RSTs
to identify closed ports.

---

### 9. The TCP State Machine — What Scanners See

The TCP state machine defines every valid state a connection can be in:

```
CLOSED → (SYN sent) → SYN_SENT → (SYN-ACK received) → ESTABLISHED
LISTEN → (SYN received) → SYN_RECEIVED → (ACK received) → ESTABLISHED
ESTABLISHED → (FIN sent) → FIN_WAIT_1 → ... → TIME_WAIT → CLOSED
```

**Key states for port scanners:**

| Port state | What scanner sends | What it receives | Meaning |
|---|---|---|---|
| **Open** | SYN | SYN-ACK | A service is listening |
| **Closed** | SYN | RST-ACK | Nothing listening, host is up |
| **Filtered** | SYN | Nothing (timeout) | Firewall dropping packets |
| **Open/filtered** | UDP probe | Nothing | No response (open or filtered) |

---

### 10. The SYN Scan — How nmap -sS Works

A SYN scan (half-open scan) is the default nmap scan type. It sends a SYN but never
completes the handshake:

```
Scanner                         Target
  │──── SYN ──────────────────►│
  │                             │
  │  If port is OPEN:           │
  │◄─── SYN-ACK ───────────────│
  │──── RST ──────────────────►│  ← Scanner resets, never completes
  │
  │  If port is CLOSED:
  │◄─── RST-ACK ───────────────│
  │
  │  If port is FILTERED:
  │  (timeout — no response)
```

**Why SYN scan over a full connect scan?**

1. **Faster:** No TIME_WAIT delay; thousands of ports per second.
2. **Stealthier:** Many older application logs only record fully established connections.
   A SYN scan never completes the handshake, so it may not appear in application logs
   (though it will appear in firewall and IDS logs).

**Requires root/administrator privileges** — the scanner must craft raw packets directly,
bypassing the OS TCP stack.

---

### 11. TCP Attack Techniques — Quick Reference

| Attack | Technique | Layer |
|---|---|---|
| **SYN flood** | Send millions of SYNs; exhaust server's half-open connection table | 4 |
| **RST injection** | Forge RST with correct sequence number → terminate existing connection | 4 |
| **TCP session hijacking** | Predict sequence numbers → inject data into session | 4 |
| **Idle scan** | Use IPID of zombie host to infer port state without sending packets yourself | 3/4 |
| **SYN scan** | Half-open scan → discover open ports while minimising application logging | 4 |

---

## Key Takeaways

1. The subnet mask defines your **lateral movement radius**. Know it the moment you land on
   a host. `/24` = 254 neighbours. `/16` = 65,534. These are not abstract numbers.
2. `169.254.169.254` is a critical SSRF target — it is the AWS IMDS endpoint. If you can
   make a server-side request to it, you are extracting cloud credentials.
3. IPv6 is enabled by default on most modern systems. Organisations that do not monitor it
   have a blind spot. SLAAC attacks exploit this.
4. The TCP three-way handshake exists to synchronise sequence numbers. Sequence numbers
   are what prevent injection and forgery — historically when they were predictable,
   so were attacks.
5. A **SYN scan** works by never completing the handshake. The server's response to your SYN
   (SYN-ACK = open, RST = closed, silence = filtered) tells you port state.
6. **Open ≠ vulnerable.** Port is open means a service is listening. Whether that service
   is exploitable is a different question — but you have to find it first.

---

## Exercises

### Exercise 1 — Subnet Arithmetic

Calculate the following without a tool:

1. For `10.10.20.0/27`: network address, broadcast, first usable, last usable, host count.
2. For `172.16.0.0/12`: what is the last IP in this range?
3. You are on `192.168.5.147/26`. Can you reach `192.168.5.200` without a router?
4. How many /24 subnets fit inside a /20?
5. What is the subnet for the IP `10.200.100.50/22`?

---

### Exercise 2 — TCP Flag Analysis

You capture these packets in Wireshark. For each, state what is happening:

1. `SYN` only, destination port 22.
2. `RST, ACK` received after sending a `SYN` to port 8080.
3. `SYN, ACK` received after sending `SYN` to port 443.
4. No response after 3 seconds following a `SYN` to port 3306.
5. `FIN, ACK` during an established HTTPS session.

---

### Exercise 3 — Practical Mental Model

Answer these without looking anything up. If you cannot, note what to revisit:

1. You land on a Linux host with IP `10.0.3.45/23`. List the full subnet range and how
   many other hosts are potentially reachable without going through a router.
2. An SSRF vulnerability lets you make HTTP requests from a server inside AWS. What IP
   would you target first? What would you expect to get back?
3. Why does nmap's default SYN scan require root/sudo on Linux?
4. What does a firewalled port look like to nmap compared to a closed port? What is the
   operational difference for an attacker?

---

## Questions

<!-- Log questions here. Ask Ghost to answer them, or write your answer for review.
     Format: Q-002.1 Question → Answer → Q-002.1.1 Follow-up -->

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 001 — OSI Model and TCP/IP Stack](DAY-0001-OSI-Model-and-TCP-IP-Stack.md)*
*Next: [Day 003 — UDP, ICMP and DNS Deep Dive](DAY-0003-UDP-ICMP-and-DNS-Deep-Dive.md)*
