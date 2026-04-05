---
title: "IP Addressing and Subnetting — IPv4, IPv6, CIDR, and Broadcast Domains"
tags: [foundation, networking, ip, ipv4, ipv6, cidr, subnetting, attacker-mindset]
module: 01-Foundation-01
day: 2
related_topics:
  - OSI Model (Layer 3)
  - TCP three-way handshake
  - ARP and Layer 2
  - nmap and port scanning
  - Network reconnaissance
---

# Day 002 — IP Addressing and Subnetting

## Goals

By the end of this lesson you will be able to:

1. Explain what an IP address is and why it exists at Layer 3.
2. Convert between dotted-decimal, binary, and CIDR notation for IPv4.
3. Calculate the network address, broadcast address, and usable host range for any CIDR block.
4. Identify reserved and special-purpose IPv4 ranges by memory.
5. Describe the structure of an IPv6 address and name its major address types.
6. Explain what a broadcast domain is and why it matters to an attacker.
7. State three ways that IP addressing knowledge directly enables an offensive or defensive action.

---

## Prerequisites

- [Day 001 — OSI Model](DAY-0001-OSI-Model-and-Why-It-Matters.md): You need to know that IP lives at
  Layer 3 and that its job is logical addressing and routing. Everything in this lesson builds on that.

---

## Main Content

### 1. Why IP Addressing Matters to an Attacker

An IP address is a map coordinate. When you own one host on a network, that address tells you three
things:

1. **Where you are** — your position in the address space relative to other hosts.
2. **Who else is nearby** — the subnet defines the blast radius of a compromise.
3. **What you can reach directly** — hosts in the same subnet can be reached without going through a
   router, making lateral movement faster and quieter.

> **Ghost's rule:** The first thing you do when you land on a new machine is `ip addr` (Linux) or
> `ipconfig /all` (Windows). The IP address and subnet mask tell you the size of the network you are
> standing in and how many other targets you can reach without crossing a router.

---

### 2. IPv4 Addressing

#### 2.1 Structure

An IPv4 address is a **32-bit number**, written as four decimal octets separated by dots:

```
192    .    168    .    1    .    100
11000000  10101000  00000001  01100100
```

Each octet is 8 bits, ranging from 0 to 255. The full address space is 2³² = **4,294,967,296**
possible addresses — which is why we ran out and built IPv6.

#### 2.2 Binary Conversion — A Skill You Need

Subnet calculations are done in binary. You do not need to be fast at this, but you need to be
correct. The bit weights for one octet:

```
Bit position:   7    6    5    4    3    2    1    0
Bit weight:   128   64   32   16    8    4    2    1
```

**Example:** Convert `192` to binary.

```
192 - 128 = 64  → bit 7 is 1
 64 -  64 = 0   → bit 6 is 1
  0          → bits 5-0 are 0

Result: 11000000
```

**Example:** Convert `168` to binary.

```
168 - 128 = 40  → bit 7 is 1
 40 -  32 = 8   → bit 5 is 1
  8 -   8 = 0   → bit 3 is 1

Result: 10101000
```

You will use this constantly when checking whether two hosts are in the same subnet.

---

### 3. Subnet Masks and CIDR

#### 3.1 The Subnet Mask

Every IPv4 address is paired with a **subnet mask** that splits the address into two parts:

- **Network portion** — identifies which network this host is on (all mask bits that are `1`).
- **Host portion** — identifies this specific host within that network (all mask bits that are `0`).

```
IP:       192.168.1.100   →   11000000.10101000.00000001.01100100
Mask:     255.255.255.0   →   11111111.11111111.11111111.00000000
                               ────────────────────────  ────────
                               Network portion (24 bits) Host (8 bits)
```

The network address is what you get when you AND the IP address with the subnet mask:

```
  11000000.10101000.00000001.01100100  (192.168.1.100)
& 11111111.11111111.11111111.00000000  (255.255.255.0)
= 11000000.10101000.00000001.00000000  (192.168.1.0)   ← network address
```

#### 3.2 CIDR Notation

Classless Inter-Domain Routing (CIDR) notation replaces the mask with a **prefix length** — the
number of `1` bits in the subnet mask. `255.255.255.0` has 24 consecutive ones, so it becomes `/24`.

```
192.168.1.100/24   ≡   IP: 192.168.1.100,  Mask: 255.255.255.0
10.0.0.0/8         ≡   IP: 10.0.0.0,       Mask: 255.0.0.0
172.16.50.0/20     ≡   IP: 172.16.50.0,    Mask: 255.255.240.0
```

CIDR is what you will see everywhere: cloud dashboards, firewall rules, nmap targets, route tables.

#### 3.3 Key CIDR Math — The Four Numbers You Always Calculate

For any CIDR block you need to know:

| Number | How to calculate | Example for `192.168.1.0/24` |
|--------|-----------------|------------------------------|
| **Network address** | Host bits all zero | `192.168.1.0` |
| **Broadcast address** | Host bits all one | `192.168.1.255` |
| **Usable host range** | Network+1 to Broadcast-1 | `192.168.1.1` – `192.168.1.254` |
| **Number of hosts** | 2^(host bits) - 2 | 2^8 - 2 = **254** |

The `-2` removes the network address and broadcast address, neither of which can be assigned to a host.

**Another example — a smaller subnet, `10.10.20.64/26`:**

The prefix is `/26`, so the host portion is 32 - 26 = **6 bits**.

```
IP in binary:   00001010.00001010.00010100.01|000000
Mask:           11111111.11111111.11111111.11|000000

Network:        00001010.00001010.00010100.01 000000  =  10.10.20.64
Broadcast:      00001010.00001010.00010100.01 111111  =  10.10.20.127
Host range:     10.10.20.65  –  10.10.20.126
Usable hosts:   2^6 - 2 = 62
```

The `|` shows where the network/host boundary is. Everything to the left is fixed; everything to the
right you flip.

#### 3.4 Common CIDR Blocks — Memorise These

| CIDR | Mask | Usable Hosts | Typical use |
|------|------|-------------|-------------|
| `/8`  | 255.0.0.0 | 16,777,214 | Large private range (10.0.0.0/8) |
| `/16` | 255.255.0.0 | 65,534 | Medium private range (172.16.0.0/16) |
| `/24` | 255.255.255.0 | 254 | Standard office LAN |
| `/25` | 255.255.255.128 | 126 | Split a /24 in two |
| `/26` | 255.255.255.192 | 62 | Small server segment |
| `/27` | 255.255.255.224 | 30 | DMZ or small VLAN |
| `/28` | 255.255.255.240 | 14 | Tiny infrastructure VLAN |
| `/30` | 255.255.255.252 | 2 | Point-to-point router links |
| `/32` | 255.255.255.255 | 1 (host route) | Single host, loopback, firewall rule |

**Attacker use:** When you run `nmap 10.10.10.0/24`, you are telling nmap to scan 254 hosts.
When you see `10.0.0.0/8` in a routing table, you know there are potentially 16 million addresses
on the other side of that route — a large internal network worth enumerating.

---

### 4. Special-Purpose IPv4 Ranges

Memorise these. You will encounter them on every engagement.

| Range | Purpose | Why it matters |
|-------|---------|----------------|
| `10.0.0.0/8` | RFC 1918 private | Internal corporate networks |
| `172.16.0.0/12` | RFC 1918 private | 172.16.x.x – 172.31.x.x |
| `192.168.0.0/16` | RFC 1918 private | Home/small office LANs |
| `127.0.0.0/8` | Loopback | `127.0.0.1` — the host talking to itself |
| `169.254.0.0/16` | APIPA / link-local | Auto-assigned when DHCP fails; sign of misconfiguration |
| `0.0.0.0/0` | Default route | "Match everything" — the route of last resort |
| `0.0.0.0` | Unspecified | Bind to all interfaces; "no address yet" |
| `255.255.255.255` | Limited broadcast | Sent to all hosts on local segment (not routed) |
| `100.64.0.0/10` | Carrier-grade NAT | ISP-level NAT (RFC 6598) |
| `224.0.0.0/4` | Multicast | One-to-many; `224.0.0.1` = all hosts, `224.0.0.2` = all routers |

**Why RFC 1918 matters for attackers:**

- When you see a `10.x.x.x` or `172.16-31.x.x` address in an HTTP header (`X-Forwarded-For`,
  `Via`, error messages), you have learned something about the internal network topology — a
  classic information disclosure vulnerability.
- RFC 1918 addresses are not routed on the internet. If a web server's error page reveals its
  internal IP is `10.0.3.47`, you now know the subnet it lives in.
- SSRF (Server-Side Request Forgery) attacks typically target RFC 1918 addresses to reach internal
  services that are firewalled from the internet.

---

### 5. Broadcast Domains

A **broadcast domain** is the set of hosts that will receive a Layer 2 broadcast sent by any member
of the group. Broadcasts are forwarded by switches but **blocked by routers**. One subnet = one
broadcast domain (in a flat network without VLANs).

```
[Host A]─┐                           ┌─[Host C]
          ├── [Switch] ─── [Router] ──┤
[Host B]─┘                           └─[Host D]

Left side: one broadcast domain (A, B, and the router's left interface)
Right side: another broadcast domain (C, D, and the router's right interface)
```

**Why this matters for attackers:**

1. **ARP only works within a broadcast domain.** ARP poisoning (Day 017) requires you to be in the
   same broadcast domain as your target. If your target is on a different subnet, ARP does not
   reach them — you need to be on a router between you, or pivot through a host in their segment.

2. **DHCP spoofing is broadcast-domain-scoped.** A rogue DHCP server can only serve hosts in its
   broadcast domain.

3. **Lateral movement planning.** When you compromise a host, you check its subnet. Every other
   host in that subnet is reachable at Layer 2 — no router hop, no firewall between you (unless
   there is a host-based firewall). Hosts in other subnets require routing — and routing means
   potentially firewalls.

4. **Broadcast traffic leaks information.** Running `tcpdump` or Wireshark on a compromised host
   inside a broadcast domain reveals ARP requests, LLMNR/NBT-NS queries, and mDNS traffic from
   every other host on the segment — free host discovery without sending a single packet.

---

### 6. IPv6 Addressing

#### 6.1 Why IPv6 Exists

IPv4's 4.3 billion addresses ran out. IANA allocated the last blocks to RIRs in 2011. IPv6 uses
**128-bit addresses** — 2¹²⁸ ≈ 3.4 × 10³⁸ addresses. Every grain of sand on earth could have its
own subnet.

#### 6.2 Structure and Notation

IPv6 addresses are written as **eight groups of four hexadecimal digits**, separated by colons:

```
2001:0db8:85a3:0000:0000:8a2e:0370:7334
```

**Abbreviation rules (both can be combined):**

1. Leading zeros within a group can be omitted: `0db8` → `db8`, `0000` → `0`.
2. One contiguous sequence of all-zero groups can be replaced with `::` (only once per address).

```
2001:0db8:0000:0000:0000:0000:0000:0001
→ 2001:db8:0:0:0:0:0:1       (drop leading zeros)
→ 2001:db8::1                (collapse zero groups with ::)
```

#### 6.3 IPv6 Address Types

| Type | Prefix | Example | Purpose |
|------|--------|---------|---------|
| **Global Unicast** | `2000::/3` | `2001:db8::1` | Globally routable (like public IPv4) |
| **Link-Local** | `fe80::/10` | `fe80::1` | Auto-configured, stays on the local link |
| **Unique Local** | `fc00::/7` | `fd00::1` | Like RFC 1918 — private, not globally routed |
| **Loopback** | `::1/128` | `::1` | Same as `127.0.0.1` |
| **Unspecified** | `::/128` | `::` | "No address" — like `0.0.0.0` |
| **Multicast** | `ff00::/8` | `ff02::1` | All-nodes on link (`ff02::1`), all-routers (`ff02::2`) |

#### 6.4 SLAAC — Why Every IPv6 Host Has a Link-Local Address

Stateless Address Autoconfiguration (SLAAC) means every IPv6-capable interface automatically
generates a **link-local address** in the `fe80::/10` range, derived from the MAC address (EUI-64)
or a random value. This happens without any DHCPv6 server.

```
Interface eth0:
  inet6 fe80::a1b2:c3d4:e5f6:7890/64  scope link
```

**Attacker relevance of IPv6:**

1. **IPv6 is often forgotten.** Organisations that locked down their IPv4 environment may have left
   IPv6 entirely open — no firewall rules, no monitoring, no IDS signatures. IPv6 can be the
   path of least resistance into an otherwise hardened environment.

2. **Dual-stack systems have two addresses.** A firewall rule that blocks the IPv4 address does
   not block the IPv6 address. Many tools (nmap, curl) need to be explicitly told to scan IPv6
   (`-6` flag for nmap, `nmap -6 <target>`).

3. **IPv6 link-local enables neighbour discovery attacks.** IPv6 replaces ARP with ICMPv6
   Neighbour Discovery Protocol (NDP). An attacker can send fake Router Advertisement (RA) packets
   (`ff02::1` multicast) to redirect all traffic through their machine — the IPv6 equivalent of
   ARP poisoning.

4. **Multicast leaks host information.** `ff02::1` (all-nodes multicast) pings every IPv6 host on
   the link. `ping6 ff02::1%eth0` discovers all dual-stack hosts in the broadcast domain — even
   those that do not respond to IPv4 pings.

---

### 7. IP Addressing in the Attacker's Workflow

Here is how everything in this lesson maps to real attacker actions:

```
Stage           Action                        What IP knowledge enables
──────────────────────────────────────────────────────────────────────────────
Reconnaissance  nmap 10.10.10.0/24 -sn       Ping sweep of the entire subnet
                nmap 172.16.0.0/12            Scan entire RFC 1918 /12 range
                ping6 ff02::1%eth0            Discover all IPv6 hosts on link

Exploitation    curl http://169.254.169.254/  SSRF to cloud metadata endpoint
                SSRF → http://10.0.0.1/       Reach internal services
                ARP poison 192.168.1.0/24     Must be in same broadcast domain

Post-exploit    ip addr; ip route show        Understand network position
                ip neigh show                 ARP cache = live hosts on segment
                cat /etc/hosts                Internal DNS mappings

Lateral move    nmap -sV 10.10.10.0/24        Scan the local subnet for pivots
                ssh via compromised host       Move to other segments via pivot
```

The most important post-exploitation command for network orientation:

```bash
# Linux
ip addr show          # All interfaces and their IP/subnet
ip route show         # Routing table — what networks can this host reach?
ip neigh show         # ARP cache — who has this host talked to recently?

# Windows
ipconfig /all         # All interfaces, masks, gateway, DNS
route print           # Routing table
arp -a                # ARP cache
```

---

## Key Takeaways

1. An IPv4 address is a **32-bit number** split into network and host portions by the subnet mask.
   CIDR notation (`/24`) expresses the mask as a bit count — learn to convert both ways.

2. **Four numbers define any subnet:** network address, broadcast address, first usable host, last
   usable host. From any CIDR block you must be able to derive all four in your head.

3. **RFC 1918 ranges** (`10/8`, `172.16/12`, `192.168/16`) are private and non-routable. Seeing
   them in HTTP headers or error messages is an information disclosure vulnerability.

4. A **broadcast domain** is a Layer 2 boundary. ARP poisoning, DHCP spoofing, and passive host
   discovery are all broadcast-domain-scoped. When you land on a host, you own the whole segment
   for passive reconnaissance.

5. **IPv6 is real, it is deployed, and it is often unmonitored.** Every dual-stack host has at least
   one link-local IPv6 address. Forget it and you leave a door open.

6. The first thing after landing on a host: `ip addr; ip route show; ip neigh show`. The subnet
   mask tells you the blast radius. The ARP cache tells you who is already talking.

---

## Exercises

### Exercise 1 — Binary Conversion (No calculator)

Convert the following to binary, then verify with a calculator:

1. `192`
2. `255`
3. `128`
4. `10`
5. `172`

---

### Exercise 2 — Subnet Calculation

For each CIDR block, calculate **without a tool**: network address, broadcast address, usable host
range, and number of usable hosts. Then verify with an online subnet calculator.

1. `192.168.10.0/24`
2. `10.0.0.0/8`
3. `172.16.100.0/22`
4. `192.168.1.128/26`
5. `10.10.0.64/27`

For problem 3 and 5, show your binary working.

---

### Exercise 3 — Address Type Identification

Classify each address as: Public IPv4, RFC 1918 Private, Loopback, Link-local (APIPA), Multicast,
IPv6 Global Unicast, IPv6 Link-Local, or IPv6 Loopback.

1. `8.8.8.8`
2. `10.0.4.22`
3. `127.0.0.1`
4. `169.254.100.5`
5. `172.31.255.255`
6. `192.168.0.1`
7. `224.0.0.251`
8. `::1`
9. `fe80::1`
10. `2001:db8::cafe`
11. `fd12:3456:789a::1`

---

### Exercise 4 — Attacker Thinking

Answer the following based on the lesson content only. No tools.

1. You have compromised a host. Running `ip addr` shows: `inet 10.20.30.50/23`. How many other
   hosts could potentially be in the same broadcast domain? What is the usable host range?

2. A web application's 500 error page includes this stack trace line:
   `Connection refused to 172.28.5.12:5432`. What have you learned, and how would you use it?

3. You are on a penetration test. Your nmap scan of `192.168.1.0/24` returns 12 hosts. You are
   running from `192.168.1.100/24`. You want to ARP-poison the host at `192.168.1.1`.
   Is this possible without additional tools? Why?

4. A client tells you their infrastructure is protected by a firewall and they "don't use IPv6."
   What is the first thing you check on any endpoint you gain access to, and what command
   would you run?

---

### Lab Prep — Coming in Day 013

In the Wireshark lab (Day 013), you will capture live traffic and identify IP addresses, subnets,
and which hosts are in the same broadcast domain from the packet capture alone. Make sure you can
look at an IP address and its mask and immediately derive the network and broadcast addresses.
That mental subnetting must be fluent before the lab — looking it up mid-capture slows you down.

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

*Previous lesson: [Day 001 — OSI Model](DAY-0001-OSI-Model-and-Why-It-Matters.md)*
*Next lesson: [Day 003 — TCP Three-Way Handshake](DAY-0003-TCP-Three-Way-Handshake.md)*
