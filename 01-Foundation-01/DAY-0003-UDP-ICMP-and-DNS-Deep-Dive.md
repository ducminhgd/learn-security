---
title: "UDP, ICMP and DNS Deep Dive"
tags: [foundation, networking, udp, icmp, dns, ping, traceroute, amplification, zone-transfer]
module: 01-Foundation-01
day: 3
related_topics:
  - TCP Three-Way Handshake
  - DNS as Attack Surface (Day 004)
  - nmap UDP scanning
  - DDoS amplification attacks
---

# Day 003 — UDP, ICMP and DNS Deep Dive

## Goals

By the end of this lesson you will be able to:

1. Explain why UDP exists alongside TCP and name five protocols that choose UDP over TCP.
2. Describe the UDP header fields and explain what the absence of a handshake means for an attacker.
3. Name the eight most important ICMP message types and explain their attacker relevance.
4. Explain how `ping` and `traceroute` work at the packet level — exactly what is sent and received.
5. Describe UDP amplification DDoS — mechanism, amplification factor, and mitigation.
6. Explain why UDP scanning in nmap is slow and how to interpret unreliable results.
7. Trace a full DNS resolution from browser to authoritative server, including every step.
8. Name all critical DNS record types and explain how each is used offensively.
9. Explain what a DNS zone transfer is and why it is a high-value recon finding.

---

## Prerequisites

- [Day 001 — OSI Model](DAY-0001-OSI-Model-and-TCP-IP-Stack.md)
- [Day 002 — IP Addressing and TCP](DAY-0002-IP-Subnetting-and-TCP-State-Machine.md)

---

## Main Content — Part 1: UDP

### 1. Why UDP Exists

TCP is reliable but heavyweight — it requires a handshake, maintains state, retransmits lost
segments, and enforces ordering. For many use cases, that overhead is unacceptable:

- **Real-time audio/video:** A retransmitted video frame that arrives 200ms late is worse than
  a dropped frame. Better to skip it.
- **DNS queries:** A single request-response. Setting up a full TCP connection for 60 bytes is
  absurd overhead.
- **Gaming:** Low latency beats reliability. A dropped position update is corrected by the next
  one anyway.
- **DHCP:** Must broadcast before the client has an IP — cannot use TCP (requires a known destination).

Protocols that choose UDP: DNS, DHCP, TFTP, NTP, SNMP, Syslog, VoIP (RTP), QUIC (wraps UDP).

---

### 2. UDP Header

The UDP header is brutally simple — 8 bytes total:

```
 0      7 8     15 16    23 24    31
┌────────┬─────────┬────────┬────────┐
│ Source │  Dest   │ Length │Checksum│
│  Port  │  Port   │        │        │
└────────┴─────────┴────────┴────────┘
```

- **Source port (16 bits):** Ephemeral port (or 0 if not needed for response).
- **Destination port (16 bits):** Service port (53 for DNS, 123 for NTP, 161 for SNMP).
- **Length (16 bits):** Header + data in bytes. Minimum 8.
- **Checksum (16 bits):** Optional in IPv4, mandatory in IPv6.

**No sequence numbers. No acknowledgements. No state.** The sender fires and forgets.

---

### 3. UDP for Attackers

**No connection = no state = no authentication at the transport layer.**

This creates several attack opportunities:

1. **Spoofing source IP is trivial:** Without a handshake verifying both sides can send and
   receive, you can forge any source IP in a UDP packet. This is the foundation of all
   reflection/amplification attacks.

2. **UDP amplification DDoS:**
   - Attacker sends small UDP request with source IP spoofed to victim's IP.
   - Amplifier (DNS, NTP, memcached, SSDP) sends a much larger response to the victim.
   - **Amplification factor** = response size ÷ request size.
   - DNS: ~28x. NTP (`monlist`): ~556x. Memcached: up to **51,000x** (CVE-2018-1000115).
   - Result: massive volumetric DDoS with minimal attacker bandwidth.

3. **UDP scanning limitations:**
   - No SYN-SYN-ACK-ACK to confirm a port is open.
   - Open UDP port: service may not respond at all to a non-protocol probe.
   - Closed UDP port: OS returns ICMP port unreachable (Type 3, Code 3).
   - Filtered: silence (same as open).
   - `nmap -sU` sends a payload appropriate for common services (DNS query to port 53,
     NTP request to port 123). Without a valid probe, open ports look closed.
   - Rate-limited by ICMP unreachable generation — Linux kernels limit ICMP to 1/sec by
     default, making UDP scans 1000x slower than TCP scans.

---

## Main Content — Part 2: ICMP

### 4. ICMP — The Network's Diagnostic Layer

ICMP (Internet Control Message Protocol) lives at Layer 3. It is used by network devices to
send error messages and operational information. Every IP implementation must handle it.

**Structure:** ICMP messages have a Type, Code, and optional data field.

**Critical ICMP types for attackers:**

| Type | Name | Attacker use |
|---|---|---|
| 0 | Echo Reply | Ping response — confirms host is alive |
| 3 | Destination Unreachable | Code 3 = port closed (UDP scan) |
| 5 | Redirect | Historically used to redirect routing (network attack) |
| 8 | Echo Request | Ping — host discovery |
| 11 | Time Exceeded | TTL expired — traceroute response |
| 13 | Timestamp Request | OS fingerprinting via timestamp behaviour |
| 30 | Traceroute | Deprecated info request |

**Type 3 sub-codes (Destination Unreachable):**

| Code | Meaning |
|---|---|
| 0 | Network unreachable |
| 1 | Host unreachable |
| 2 | Protocol unreachable |
| 3 | **Port unreachable** — closed UDP port |
| 4 | Fragmentation needed (PMTUD) |
| 13 | Communication administratively prohibited (firewall) |

Code 13 from a firewall tells you which direction the filter is applied. Code 3 tells you
the port is closed. Silence tells you packets are being dropped.

---

### 5. How Ping Works

```
$ ping 192.168.1.1

Client sends:   ICMP Type 8 (Echo Request), identifier=PID, sequence=1
Target replies: ICMP Type 0 (Echo Reply), identifier=PID, sequence=1

RTT = time between sending Echo Request and receiving Echo Reply
```

**What ping tells you:**
- Host is reachable at Layer 3 (IP routing works).
- RTT gives you network latency.
- TTL in the reply hints at OS (Linux defaults to 64, Windows to 128, Cisco to 255).

**What ping does not tell you:**
- Whether any service is running.
- Whether a firewall is between you and the host.
- Whether the host will respond to other probes (ICMP may be selectively allowed).

**Ping sweep for host discovery:**
```bash
# nmap ping sweep (ICMP + TCP SYN to port 443)
nmap -sn 10.0.0.0/24

# Pure ICMP ping sweep (less reliable due to ICMP filtering)
fping -a -g 10.0.0.0/24 2>/dev/null
```

---

### 6. How Traceroute Works

Traceroute maps the path packets take from source to destination by exploiting TTL:

```
Round 1: Send probe with TTL=1
         → First router decrements TTL to 0, discards packet, sends ICMP Type 11 back
         → We record the router's IP and RTT

Round 2: Send probe with TTL=2
         → Second router sends ICMP Type 11 back

Round N: Send probe with TTL=N
         → Destination receives it; TTL still > 0
         → Destination sends ICMP Type 3 (UDP) or ICMP Type 0 (ICMP traceroute) back
         → We know we've reached the destination
```

- **Linux `traceroute`:** Uses UDP probes by default (high-numbered ports).
- **Windows `tracert`:** Uses ICMP echo requests.
- **`nmap --traceroute`:** Uses TCP SYN probes — more firewall-friendly.

**Attacker use:** Traceroute reveals the network topology between you and a target. Hop IP
addresses are infrastructure assets. TTL values help identify filtering points.

---

## Main Content — Part 3: DNS Deep Dive

### 7. Why DNS Is Critical to Attackers

DNS (Domain Name System) translates human-readable names to IP addresses. Every internet
connection starts with a DNS query. If you control DNS, you control traffic routing.

DNS is also:
- A rich source of **reconnaissance data** (subdomains, mail servers, name servers, IPv6 addresses).
- A **covert channel** for exfiltration and C2 (DNS tunnelling bypasses most firewalls).
- An **attack surface** for poisoning, takeover, and amplification.

---

### 8. The DNS Resolution Chain

When your browser needs to resolve `www.example.com`:

```
Browser
  │ 1. Check local cache (OS, browser)
  │ 2. If not cached → ask Recursive Resolver (e.g. 8.8.8.8)
  ▼
Recursive Resolver
  │ 3. Check its cache
  │ 4. If not cached → ask Root Name Server (.)
  │         Root says: ".com NS is a.gtld-servers.net"
  │ 5. Ask .com TLD server
  │         TLD says: "example.com NS is ns1.example.com"
  │ 6. Ask example.com's authoritative name server
  │         Auth says: "www.example.com A is 93.184.216.34"
  │ 7. Cache the result (respecting TTL)
  │ 8. Return answer to browser
  ▼
Browser connects to 93.184.216.34
```

**Key facts:**
- The stub resolver (your OS) trusts the recursive resolver completely.
- Recursive resolvers cache responses for the duration of the TTL.
- Authoritative servers hold the actual zone data.
- Root servers answer only with referrals to TLD servers.

---

### 9. DNS Record Types — Attacker Reference

| Record | Purpose | Attacker relevance |
|---|---|---|
| **A** | IPv4 address for a hostname | Primary resolution target; reveals infrastructure IPs |
| **AAAA** | IPv6 address | IPv6 infrastructure often less monitored |
| **CNAME** | Canonical name (alias) | Dangling CNAME to deleted resource = subdomain takeover |
| **MX** | Mail exchange server | Reveals email infrastructure; target for phishing infra |
| **NS** | Authoritative name server | NS records in-scope for zone transfer attempts |
| **TXT** | Arbitrary text | SPF, DKIM, DMARC, verification tokens, API keys (mistakes) |
| **SOA** | Start of Authority | Zone admin, serial number, timing values |
| **SRV** | Service location | Reveals internal service locations (LDAP, Kerberos, SIP) |
| **PTR** | Reverse DNS (IP→name) | Maps IPs to hostnames; reveals internal naming conventions |
| **CAA** | CA Authorisation | Which CAs can issue certs for this domain |

**Why TXT records matter:** Developers sometimes commit verification tokens or API keys to
DNS TXT records by mistake. SPF records reveal which mail servers are authorised — useful
for building phishing infrastructure that bypasses SPF checks.

---

### 10. Zone Transfers (AXFR)

A zone transfer allows a secondary DNS server to replicate the entire zone database from the
primary. If misconfigured to allow transfers from any IP, an attacker can dump every DNS
record in a zone in one query:

```bash
# Attempt zone transfer for example.com
dig axfr example.com @ns1.example.com

# What you get if successful:
# Every subdomain, every IP, every mail server
# Internal hostnames that were never meant to be public
# Network topology revealed in naming conventions (e.g. core-router-01.internal.example.com)
```

**Real-world impact:** Zone transfers have exposed thousands of internal hostnames, partner
integration endpoints, and staging environment IPs that become direct attack targets.

**Detection:** Any DNS query type AXFR from a non-authorised IP. Immediate alert.

**Fix:** Restrict zone transfers to authorised secondary server IPs via ACL in BIND/PowerDNS.

---

### 11. DNS Query Types and Tools

```bash
# A record
dig A example.com

# All records
dig ANY example.com @8.8.8.8

# Reverse lookup (PTR)
dig -x 93.184.216.34

# NS records (find authoritative servers)
dig NS example.com

# MX records
dig MX example.com

# TXT records (SPF, DKIM, verification tokens)
dig TXT example.com

# Trace the resolution chain step by step
dig +trace www.example.com

# Query a specific DNS server
dig A target.com @ns1.target.com
```

**Passive DNS databases:** Services like SecurityTrails, RiskIQ, and CIRCL's passive DNS
store historical DNS records. Even if a subdomain's DNS record has been deleted, passive
DNS may still show what it pointed to — revealing old infrastructure or dangling CNAMEs.

---

## Key Takeaways

1. **UDP has no state.** No handshake means no transport-layer authentication — source IPs
   can be spoofed freely, enabling reflection and amplification attacks.
2. **UDP scanning is unreliable.** Silence means open or filtered. You need protocol-specific
   probes to get useful results. Always slower than TCP scanning due to ICMP rate limiting.
3. **ICMP is a diagnostic layer.** Ping = echo request/reply (Type 8/0). Traceroute = TTL
   manipulation + Type 11 responses. ICMP Type 3 Code 3 = closed UDP port.
4. **DNS is the internet's phone book** — and attackers steal phone books. Every subdomain
   is a potential target. Zone transfers are a complete giveaway of infrastructure.
5. **DNS record types reveal intent.** MX = mail server. NS = authoritative resolver.
   SRV = internal services. CNAME = potential takeover target. TXT = sometimes secrets.
6. **TTL in DNS** controls caching. Low TTL = quick changes; high TTL = attacker has time
   to cache-poison a record before it expires.
7. **`169.254.169.254` is critical.** The AWS IMDS lives here. Any application that makes
   HTTP requests to attacker-controlled URLs is a candidate for SSRF to this address.

---

## Exercises

### Exercise 1 — UDP Concepts

Answer without tools:

1. Why can't DHCP use TCP? What specific constraint prevents it?
2. An attacker sends 100-byte UDP packets to open DNS resolvers with source IP spoofed to
   a victim's IP. Each resolver sends back a 3,000-byte response. What is the amplification
   factor? If the attacker controls 1 Gbps of bandwidth, what is the effective attack volume?
3. You run `nmap -sU -p 53,123,161 10.0.0.1` and get "open|filtered" for port 161 (SNMP).
   What does this tell you? What would "closed" tell you?
4. What is the Linux kernel's default ICMP rate limit and why does it make UDP scanning slow?

---

### Exercise 2 — ICMP Analysis

You capture these ICMP packets. For each, state what happened:

1. ICMP Type 8 sent to `10.0.0.5`, no response after 5 seconds.
2. ICMP Type 0 received from `10.0.0.5` with TTL=63.
3. ICMP Type 3, Code 3 received from `10.0.0.1` after UDP probe to `10.0.0.5:161`.
4. ICMP Type 11 received from `10.0.0.1` after sending a probe with TTL=1.
5. ICMP Type 3, Code 13 received from `10.0.0.1` after SYN to `10.0.0.5:22`.

---

### Exercise 3 — DNS Reconnaissance

Using `dig` against a real target (use `example.com` if no lab target is available):

1. Find all A records for `example.com`.
2. Find the NS records. What are the authoritative servers?
3. Find the MX records. What mail infrastructure does this org use?
4. Find TXT records. What SPF record is configured? What does it tell you about their
   email sending infrastructure?
5. Attempt a zone transfer: `dig axfr example.com @ns1.example.com`. What happened? Why?
6. Trace the full resolution chain with `dig +trace www.example.com`. Identify each hop.

---

## Questions

<!-- Log questions here. Ask Ghost to answer them, or write your answer for review. -->

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 002 — IP Addressing and TCP](DAY-0002-IP-Subnetting-and-TCP-State-Machine.md)*
*Next: [Day 004 — DNS Attacks and HTTP Fundamentals](DAY-0004-DNS-Attacks-and-HTTP-Fundamentals.md)*
