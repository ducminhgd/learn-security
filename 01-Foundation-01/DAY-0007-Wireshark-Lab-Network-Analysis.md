---
title: "Wireshark Lab — Network Traffic Analysis"
tags: [foundation, networking, wireshark, packet-capture, traffic-analysis, lab,
       http, dns, tls, tcp]
module: 01-Foundation-01
day: 7
related_topics:
  - OSI Model (Day 001)
  - TCP State Machine (Day 002)
  - DNS (Day 003)
  - HTTP (Day 004)
  - TLS (Day 005)
---

# Day 007 — Wireshark Lab: Network Traffic Analysis

## Goals

By the end of this lesson you will be able to:

1. Install and configure Wireshark for capture on your machine.
2. Write capture filters to limit what is recorded.
3. Write display filters to isolate specific traffic in a captured file.
4. Dissect a complete HTTP request-response exchange at every protocol layer.
5. Identify the TLS handshake messages in a capture and describe each.
6. Reconstruct a DNS resolution chain from captured packets.
7. Follow a TCP stream and extract the application-layer data.
8. Explain what Wireshark reveals that an attacker on the same network segment would see.

---

## Prerequisites

- [Day 001 — OSI Model](DAY-0001-OSI-Model-and-TCP-IP-Stack.md) through
  [Day 006 — TLS Attacks and Proxies](DAY-0006-TLS-Attacks-HTTP2-and-Proxies.md).
  Today is the practical synthesis of everything from Days 1–6.

**Required tool:** Wireshark installed on your system.
```bash
# Debian/Ubuntu
sudo apt install wireshark

# macOS (Homebrew)
brew install --cask wireshark

# Windows
# Download installer from wireshark.org
```

---

## Lab Setup

### What You Need

- Wireshark installed.
- A test HTTP site to capture against (HTTP, not HTTPS — you need plaintext to see the content).
  - Use `http://httpbin.org/get` for HTTP captures.
  - Use `http://neverssl.com` as a reliable HTTP-only site.
  - OR: run a local HTTP server: `python3 -m http.server 8080`
- A terminal to generate DNS queries.

**Note on TLS:** Wireshark cannot decrypt TLS traffic by default. To see decrypted HTTPS
traffic, you either need the session keys (exportable from browsers) or use an HTTP proxy
instead. The TLS section of this lab shows you the encrypted handshake structure — you will
see the certificates, not the plaintext.

---

## Main Content — Wireshark Fundamentals

### 1. Capture Interface Selection

When you open Wireshark, you see a list of network interfaces. The wavy line indicates
traffic is flowing. Select the appropriate interface:
- **eth0 / enp3s0:** Wired ethernet.
- **wlan0 / en0:** Wi-Fi.
- **lo:** Loopback (127.0.0.1 traffic only).
- **any:** Captures on all interfaces (Linux only).

**Important:** On Linux, you need either root privileges or to be in the `wireshark` group
to capture on real interfaces. Add yourself: `sudo usermod -aG wireshark $USER` then
log out and back in.

---

### 2. Capture Filters (BPF Syntax)

Capture filters run in the kernel (via libpcap/WinPcap) — they restrict what gets saved.
Use these when you want to capture a large amount of traffic efficiently.

**Syntax:** Berkeley Packet Filter (BPF)

| Filter | Captures |
|---|---|
| `host 93.184.216.34` | Traffic to/from this IP |
| `net 10.0.0.0/24` | Traffic within this subnet |
| `port 80` | TCP/UDP port 80 |
| `tcp port 443` | TCP port 443 (HTTPS) |
| `not port 22` | Everything except SSH |
| `tcp and host 10.0.0.1` | TCP traffic to/from a specific host |
| `udp port 53` | DNS (UDP) |
| `icmp` | All ICMP |

Enter capture filters in the filter bar before starting capture.

---

### 3. Display Filters (Wireshark Filter Language)

Display filters run after capture — they filter what you see in the packet list.
More powerful than BPF; use the Wireshark-specific syntax.

| Filter | Shows |
|---|---|
| `http` | HTTP traffic |
| `http.request.method == "POST"` | Only POST requests |
| `http.response.code == 200` | Only 200 responses |
| `dns` | All DNS |
| `dns.qry.name contains "example"` | DNS queries containing "example" |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | TCP SYN packets only |
| `tcp.flags.rst == 1` | TCP RST packets |
| `tls.handshake.type == 1` | TLS ClientHello messages |
| `tls.handshake.type == 2` | TLS ServerHello messages |
| `ip.addr == 93.184.216.34` | Any packet involving this IP |
| `ip.src == 192.168.1.0/24` | Packets sourced from this subnet |
| `frame contains "password"` | Any frame with the ASCII string "password" |
| `tcp.stream eq 5` | Only packets in TCP stream #5 |

---

### 4. Useful Wireshark Features

**Follow TCP Stream:** Right-click any packet in a stream → "Follow" → "TCP Stream". Wireshark
reconstructs the full application-layer exchange as text. For HTTP, you see the complete
request and response. For encrypted traffic, you see ciphertext.

**Statistics → Conversations:** Shows all TCP/UDP conversations with byte counts and duration.
Good for identifying which hosts are talking the most.

**Statistics → Protocol Hierarchy:** Shows breakdown of protocols in the capture by packet and
byte count. Reveals unexpected protocols.

**Export Objects:** File → Export Objects → HTTP. Extracts all HTTP objects (HTML, JS, images,
files) from the capture. An attacker on a network can reconstruct everything a victim
downloaded over unencrypted HTTP.

**Colorisation:** Wireshark colour-codes packets by protocol by default. Black background =
TCP errors or resets. Red = bad TCP checksums. Green = TCP.

---

## Lab Exercises

### Lab 1 — Capturing and Dissecting HTTP Traffic

**Goal:** See a complete HTTP request-response cycle at every OSI layer.

**Steps:**

1. Start Wireshark. Set capture filter: `tcp port 80`.
2. Start capture on your primary interface.
3. In a terminal: `curl -v http://neverssl.com`
4. Stop the capture after the response is received.
5. Apply display filter: `http`

**What to find and document:**

a) **Ethernet frame (Layer 2):** Click the first HTTP packet. In the packet details panel,
   expand "Ethernet II". Record:
   - Source MAC address
   - Destination MAC address (should be your gateway)

b) **IP header (Layer 3):** Expand "Internet Protocol Version 4". Record:
   - Source IP (your machine)
   - Destination IP (neverssl.com's server)
   - TTL value
   - Protocol field (should be 6 = TCP)

c) **TCP segment (Layer 4):** Expand "Transmission Control Protocol". Record:
   - Source port (ephemeral)
   - Destination port (80)
   - Sequence number
   - Flags set (should be PSH + ACK for the HTTP request)

d) **HTTP request (Layer 7):** Expand "Hypertext Transfer Protocol". Record:
   - Request method and URI
   - Host header value
   - User-Agent header value
   - All request headers present

e) **Find the HTTP response:** Apply filter `http.response`. Record:
   - Status code and reason phrase
   - Content-Type header
   - Content-Length header
   - Server header (what does this reveal about the server technology?)

f) **Follow the TCP stream:** Right-click any HTTP packet → Follow → TCP Stream. You now see
   the complete HTTP conversation as the client and server see it. Compare what you see here
   to the individual headers you noted above.

---

### Lab 2 — TCP Three-Way Handshake and Teardown

**Goal:** Observe the TCP state machine in action.

**Steps:**

1. Clear previous capture. Start new capture on the same interface.
2. Apply capture filter: `host neverssl.com`
3. Run: `curl http://neverssl.com`
4. Stop capture.
5. Apply display filter: `tcp`

**What to find:**

a) Find the SYN packet (flags: SYN=1, ACK=0). Record the initial sequence number (ISN).

b) Find the SYN-ACK packet. Record:
   - Server's ISN
   - Acknowledgement number (should be client's ISN + 1)

c) Find the ACK that completes the handshake. Note the acknowledgement number.

d) At the end of the capture, find the FIN or RST packets. Trace the connection teardown.
   Is it a graceful FIN-FIN teardown or an abrupt RST?

e) How many round trips happened before the first byte of HTTP data was sent?

---

### Lab 3 — DNS Resolution Trace

**Goal:** Observe a complete DNS resolution chain.

**Steps:**

1. Clear cache: `sudo systemd-resolve --flush-caches` (Linux) or `ipconfig /flushdns` (Windows).
2. Start capture with filter: `udp port 53`
3. In terminal: `dig +trace www.wikipedia.org`
4. Stop capture.
5. Display filter: `dns`

**What to find:**

a) Find the first DNS query. What record type is being requested? What is the destination IP?
   (Hint: it should be your configured recursive resolver.)

b) Find the DNS response. What is the TTL? What IP address is returned?

c) If using `dig +trace`, you see queries going directly to root servers, TLD servers, and
   authoritative servers. In the capture, find queries to each level. What IP addresses are
   the root servers?

d) Find any CNAME records in the responses. What do they point to?

e) How long did the full resolution take (from first query to final answer)?

---

### Lab 4 — TLS Handshake Observation

**Goal:** See the TLS handshake structure in a capture.

**Steps:**

1. Clear capture. Filter: `tcp port 443 and host example.com`
2. Start capture.
3. Run: `curl https://example.com`
4. Stop capture.
5. Display filter: `tls`

**What to find:**

a) Find the `Client Hello` (TLS handshake type 1). Expand it and note:
   - TLS version in the Client Hello
   - The list of cipher suites offered by the client
   - The SNI (Server Name Indication) extension — what hostname is the client requesting?

b) Find the `Server Hello` (handshake type 2). Note:
   - The cipher suite the server chose
   - TLS version in the Server Hello

c) Find the `Certificate` message. Expand it. You can see the certificate details
   (issuer, validity, SANs) even though the connection is encrypted — because certificates
   are transmitted before the encrypted channel is established in TLS 1.2.
   In TLS 1.3, this message should be encrypted. What version did you capture?

d) Find the `Application Data` records. What do you see? (You should see only the byte count
   and ciphertext — the payload is encrypted.) Confirm that Wireshark shows the raw bytes
   without being able to decrypt the content.

e) Compare: if you captured TLS 1.2 vs TLS 1.3, how many round trips did each require?
   You can count the number of messages before `Application Data` appears.

---

### Lab 5 — Finding Sensitive Data in Plaintext Traffic

**Goal:** Demonstrate why HTTPS is not optional.

**Steps:**

1. Start a local HTTP server that serves a fake login form:
   ```bash
   mkdir /tmp/fakesite && cd /tmp/fakesite
   cat > index.html << 'EOF'
   <form method="POST" action="/login">
     <input name="username" type="text">
     <input name="password" type="password">
     <button type="submit">Login</button>
   </form>
   EOF
   python3 -m http.server 8080
   ```

2. Start Wireshark, filter: `tcp port 8080`

3. In a browser, go to `http://localhost:8080`, fill in username/password, submit.

4. In Wireshark, display filter: `http.request.method == "POST"`

5. Find the POST request. Follow the TCP stream.

**What to find:**
- The username and password you submitted are visible in plaintext in the POST body.
- A network observer (Wireshark = passive MITM) can see them with zero effort.

This is what attackers see when HTTP (not HTTPS) credentials are transmitted over any
network they can observe.

---

## Key Takeaways

1. **Wireshark shows every layer.** The same packet reveals Layer 2 (MAC addresses),
   Layer 3 (IP), Layer 4 (TCP/UDP), and Layer 7 (HTTP/DNS/TLS) simultaneously.
2. **TCP streams are conversations.** "Follow TCP Stream" reconstructs the full application
   exchange. This is how you extract credentials from a PCAP in a forensics or MITM scenario.
3. **DNS is plaintext by default.** Every query and response is visible to any network observer.
   This is why DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) exist.
4. **TLS hides content but not metadata.** You can see IP addresses, ports, TLS SNI (the
   target hostname), certificate details, and traffic patterns — just not the plaintext.
5. **Unencrypted HTTP exposes everything.** Username, password, session token, all HTTP
   headers — readable by any passive observer on the network.
6. **Capture filters save performance; display filters save sanity.** Learn both syntaxes.
   You will use them constantly in network forensics and MITM exercises.

---

## Reference — Display Filter Cheat Sheet

```
# Application protocols
http                          All HTTP
http.request                  Only requests
http.response                 Only responses
http.request.method == "GET"  GET requests
http.request.method == "POST" POST requests
http.response.code == 302     302 redirects
http.host contains "target"   Requests to a specific host

# DNS
dns                           All DNS
dns.flags.response == 0       DNS queries only
dns.flags.response == 1       DNS responses only
dns.qry.name == "example.com" Specific query

# TLS
tls                           All TLS
tls.handshake.type == 1       ClientHello
tls.handshake.type == 2       ServerHello
tls.handshake.type == 11      Certificate
tls.record.content_type == 23 Application data (encrypted)

# TCP
tcp.flags.syn == 1 && tcp.flags.ack == 0   SYN only (new connections)
tcp.flags.rst == 1                          RST packets
tcp.analysis.retransmission                 Retransmissions
tcp.stream eq N                             All packets in stream N

# ICMP
icmp                          All ICMP
icmp.type == 8                Echo requests (ping)
icmp.type == 0                Echo replies
icmp.type == 11               TTL exceeded (traceroute)
icmp.type == 3                Destination unreachable

# Useful combinations
http.request and ip.src == 192.168.1.5    HTTP requests from specific IP
not (arp or dns or icmp)                   Remove noise, focus on data flows
```

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 006 — TLS Attacks, HTTP/2 and Proxies](DAY-0006-TLS-Attacks-HTTP2-and-Proxies.md)*
*Next: [Day 008 — ARP, Routing, NAT and Network Foundation Check](DAY-0008-ARP-Routing-NAT-and-Network-Check.md)*
