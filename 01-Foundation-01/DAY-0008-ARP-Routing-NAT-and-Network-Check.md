---
title: "ARP, Layer 2 Attacks, Routing, NAT and Network Foundation Check"
tags: [foundation, networking, arp, layer2, mac, vlan, routing, nat, ipv6, nd,
       arp-poisoning, mitm, network-check]
module: 01-Foundation-01
day: 8
related_topics:
  - OSI Model Layer 2 and 3 (Day 001)
  - IP Addressing (Day 002)
  - MITM attacks (Day 231 — Broader Surface)
  - Wireshark Lab (Day 007)
---

# Day 008 — ARP, Routing, NAT and Network Foundation Check

## Goals

By the end of this lesson you will be able to:

1. Explain how ARP works — the request/reply cycle and the ARP cache.
2. Describe ARP poisoning and explain exactly how it creates a MITM position.
3. Explain how switches learn MAC addresses and describe MAC table overflow (flooding) attacks.
4. Describe VLAN fundamentals and 802.1Q double-tagging hopping attacks.
5. Explain how IP routing works — the routing table lookup process, longest prefix match.
6. Describe NAT — how it works and the attacker implications (return traffic, port reuse).
7. Explain IPv6 Neighbour Discovery and why SLAAC creates an attack surface.
8. Self-assess your mastery of all Day 001–008 concepts.

---

## Prerequisites

- [Day 001](DAY-0001-OSI-Model-and-TCP-IP-Stack.md) through
  [Day 007](DAY-0007-Wireshark-Lab-Network-Analysis.md)

---

## Main Content — Part 1: ARP and Layer 2 Attacks

### 1. ARP — Address Resolution Protocol

ARP (RFC 826) solves a critical problem: you know a host's IP address, but you need its MAC
address to send an Ethernet frame directly to it on the same network segment.

**ARP Request (broadcast):**
```
Who has 192.168.1.1? Tell 192.168.1.100
Sender: MAC aa:bb:cc:dd:ee:01, IP 192.168.1.100
Target: MAC 00:00:00:00:00:00, IP 192.168.1.1
```

Sent to the broadcast MAC `ff:ff:ff:ff:ff:ff` — every host on the segment receives it.

**ARP Reply (unicast):**
```
192.168.1.1 is at de:ad:be:ef:00:01
Sender: MAC de:ad:be:ef:00:01, IP 192.168.1.1
Target: MAC aa:bb:cc:dd:ee:01, IP 192.168.1.100
```

The requesting host stores this in its **ARP cache** (a temporary IP→MAC mapping table).

**View ARP cache:**
```bash
arp -a            # macOS/Linux/Windows (show cached entries)
ip neigh show     # Linux (more detailed)
```

**The critical flaw:** ARP has no authentication. Hosts accept ARP replies without verifying
that they asked for one. Any host on the segment can send an unsolicited ARP reply claiming
any IP→MAC mapping. This is a **gratuitous ARP** — and it is the foundation of ARP poisoning.

---

### 2. ARP Poisoning / Spoofing

**The attack:**

Target network: `192.168.1.0/24`
- Gateway: `192.168.1.1` (MAC: `de:ad:00:00:00:01`)
- Victim: `192.168.1.100` (MAC: `aa:bb:00:00:00:01`)
- Attacker: `192.168.1.200` (MAC: `at:ta:ck:er:00:01`)

Attacker sends:
1. To victim `192.168.1.100`: "192.168.1.1 is at `at:ta:ck:er:00:01`" (ARP reply)
2. To gateway `192.168.1.1`: "192.168.1.100 is at `at:ta:ck:er:00:01`" (ARP reply)

Now:
- Victim's ARP cache: gateway IP → attacker MAC
- Gateway's ARP cache: victim IP → attacker MAC

All traffic between victim and gateway passes through the attacker (with IP forwarding
enabled on the attacker's machine, the victim notices nothing).

```
Victim → [Attacker forwards] → Gateway → Internet
```

**Tools:**
```bash
# ARP spoof (must be on the same subnet)
sudo arpspoof -i eth0 -t 192.168.1.100 -r 192.168.1.1

# Or use Bettercap
sudo bettercap -eval "net.probe on; arp.spoof.targets 192.168.1.100; arp.spoof on"
```

**After gaining MITM:**
- Capture all HTTP credentials in plaintext.
- SSL strip HTTPS connections (if HSTS not deployed).
- Inject JavaScript into HTTP responses.
- Capture NTLMv2 hashes (for relay to SMB with Responder).

**Detection:**
- `arpwatch` alerts on ARP table changes.
- Dynamic ARP Inspection (DAI) on managed switches validates ARP against DHCP snooping DB.
- Wireshark: duplicate IP with different MACs indicates poisoning.

---

### 3. MAC Flooding — CAM Table Overflow

A switch maintains a **Content Addressable Memory (CAM) table** mapping MAC addresses to
ports. When a frame arrives, the switch looks up the destination MAC:
- **Match found:** Forward only to the port with that MAC.
- **No match:** Flood to all ports (unknown unicast flooding).

**CAM table is finite** (typically 8,000–64,000 entries). A MAC flooding attack sends frames
with thousands of fake source MACs, filling the CAM table until it overflows. Once full,
the switch degrades to hub behaviour — broadcasting all frames to all ports.

```bash
# macof — generates thousands of random source MACs
sudo macof -i eth0
```

**Result:** Every host on the segment sees every frame — same as being on a hub. Passive
eavesdrop becomes trivial.

**Mitigation:** Port security (limit MACs per port), 802.1X authentication per port.

---

### 4. VLAN and 802.1Q Double-Tagging

VLANs (Virtual LANs) logically segment a physical network. Hosts in VLAN 10 cannot directly
communicate with hosts in VLAN 20 without routing through a Layer 3 device.

**802.1Q tag:** A 4-byte tag inserted in the Ethernet frame header:
```
[Destination MAC][Source MAC][802.1Q Tag: VLAN ID][Ethertype][Payload][FCS]
                               ▲
                               Tag Protocol ID (0x8100) + VLAN ID (12 bits = 4094 VLANs)
```

**VLAN hopping via double-tagging:**

If an attacker is on the native VLAN (the untagged VLAN on trunk ports), they can craft
frames with two 802.1Q tags:
- **Outer tag:** Native VLAN (removed by first switch).
- **Inner tag:** Target VLAN (forwarded by second switch).

The first switch strips the outer tag and sends the frame to all trunk ports. The second
switch sees the inner tag and forwards to VLAN target. The attacker can reach VLAN target
without authorisation — in one direction only (return traffic is blocked).

**Mitigation:** Never use the native VLAN for real traffic. Change the native VLAN to an
unused VLAN ID (e.g. VLAN 999) on all trunk ports.

---

## Main Content — Part 2: Routing and NAT

### 5. IP Routing — How Packets Traverse Networks

When a host sends a packet to a destination IP, it checks its routing table:

```bash
# Linux
ip route show

# Output example:
default via 192.168.1.1 dev eth0    ← Default gateway (where unknown traffic goes)
192.168.1.0/24 dev eth0 proto kernel scope link   ← Direct subnet (send via ARP)
10.8.0.0/24 via 10.8.0.1 dev tun0   ← VPN route (go through 10.8.0.1)
```

**Longest prefix match:** The router selects the most specific route:
- Packet to `192.168.1.50` → matches `192.168.1.0/24` (more specific than `0.0.0.0/0`).
- Packet to `8.8.8.8` → matches `0.0.0.0/0` (default gateway, least specific).

**Router processing:**
1. Receive packet on ingress interface.
2. Decrement TTL. If TTL = 0, drop and send ICMP Time Exceeded.
3. Look up destination IP in routing table (longest prefix match).
4. ARP for the next hop's MAC address.
5. Forward packet on egress interface.

**Attacker relevance:**
- When you land on a compromised host, `ip route` shows what networks are reachable through
  that host. A dual-homed host (two network interfaces on different subnets) is a pivot
  point for reaching otherwise isolated networks.
- Adding a host route (`ip route add 10.100.0.0/24 via 10.0.0.1`) lets you route your
  attack traffic through a compromised host into an internal network.

---

### 6. NAT — Network Address Translation

NAT translates private IP addresses (RFC 1918) to a single public IP for internet access.
Most home routers and enterprise firewalls perform NAT.

**How outbound NAT works:**
```
Internal host: 192.168.1.100:52431 → 8.8.8.8:53
After NAT:     203.0.113.5:41234   → 8.8.8.8:53

NAT table entry:
192.168.1.100:52431 ↔ 203.0.113.5:41234 (for 8.8.8.8:53)
```

When the reply arrives at `203.0.113.5:41234`, the NAT device translates back:
`203.0.113.5:41234 → 192.168.1.100:52431`

**Attacker implications:**
- From the internet, internal hosts are not directly reachable — NAT provides a barrier
  (not a firewall, but a practical one).
- **Port reuse attacks:** Two internal hosts connecting to the same external server may have
  their source ports reuse on the external side, allowing port guessing attacks on NAT state.
- **Hairpin NAT:** An internal host connects to the external IP of its own NAT gateway — some
  NAT implementations handle this incorrectly, creating routing anomalies.
- **NAT traversal:** Attackers and malware use STUN, ICE, and similar protocols to punch
  through NAT for outbound C2 connectivity without requiring inbound ports to be open.

---

## Main Content — Part 3: IPv6 Neighbour Discovery

### 7. IPv6 NDP — The ARP Replacement (and New Attack Surface)

IPv6 replaces ARP with **Neighbour Discovery Protocol (NDP)**, implemented via ICMPv6.

**Key NDP message types:**

| Type | ICMPv6 type | Purpose |
|---|---|---|
| Router Solicitation (RS) | 133 | Host asks "any routers here?" |
| Router Advertisement (RA) | 134 | Router announces itself + prefix |
| Neighbour Solicitation (NS) | 135 | "Who has IPv6 address X?" (ARP equivalent) |
| Neighbour Advertisement (NA) | 136 | "I have IPv6 address X" (ARP reply equivalent) |
| Redirect | 137 | Router tells host to use better next hop |

**SLAAC — Stateless Address Autoconfiguration:**

When a host connects to an IPv6 network:
1. Sends RS to `ff02::2` (all routers multicast).
2. Router sends RA with network prefix (e.g. `2001:db8::/64`).
3. Host generates its own IPv6 address by appending its interface identifier.
4. Host now has a globally routable IPv6 address — no DHCP needed.

**The attack:** **Fake Router Advertisement (rogue RA):**

An attacker sends RA messages on the link. Every host that receives it will:
- Configure a new IPv6 address with the attacker's prefix.
- Set the attacker as their default IPv6 gateway.

If the victim's applications prefer IPv6 (which many do in dual-stack networks), all their
traffic is redirected through the attacker's machine — without touching IPv4 at all.

```bash
# Tool: fake_router6 from the THC-IPv6 toolkit
sudo fake_router6 eth0 2001:db8::/64
```

**Why this matters:** Most organisations monitor IPv4 traffic carefully. IPv6 monitoring
is often an afterthought. MITM6 (a modern tool) exploits this by injecting rogue RAs
to redirect dual-stack hosts and capture NTLM authentication challenges.

---

## Foundation Check — Days 001–008 Self-Assessment

This is your first competency checkpoint. You should be able to answer all of these from
memory. Mark any you cannot — those are your gaps to close before moving forward.

### Networking (Days 001–003)

- [ ] Name the seven OSI layers bottom-to-top and give one protocol for each.
- [ ] What does a `/25` subnet contain? (network, broadcast, host count, range)
- [ ] Describe the TCP three-way handshake and what each packet achieves.
- [ ] What flag combination does nmap's SYN scan send? What response means open?
- [ ] What is `169.254.169.254` and why does it matter to attackers?
- [ ] Name three common UDP-based protocols and explain why they use UDP over TCP.
- [ ] Explain how traceroute uses TTL to map network hops.
- [ ] Describe a DNS zone transfer: how to attempt it, what it reveals, how to detect it.

### HTTP and Web Protocols (Days 004–006)

- [ ] What are the five HTTP status code classes? Give two examples from each.
- [ ] Explain what `SameSite=Strict` on a cookie prevents and why.
- [ ] What does `HttpOnly` on a cookie do? What attack does it prevent?
- [ ] Describe the TLS 1.3 handshake in four steps.
- [ ] What is HSTS and what is its key weakness?
- [ ] Explain CDN origin IP discovery — three techniques to find the real server.
- [ ] What does `X-Forwarded-For` do and how is it abused?
- [ ] What is POODLE and which TLS/SSL version does it target?

### Layer 2 and Routing (Day 008)

- [ ] Explain ARP poisoning: what you send, to whom, and what you achieve.
- [ ] How does MAC flooding turn a switch into a hub?
- [ ] What is 802.1Q double-tagging and what does it bypass?
- [ ] What does `ip route show` tell you when you land on a compromised Linux host?
- [ ] What is SLAAC and how does a rogue RA attack exploit it?

### Wireshark (Day 007)

- [ ] What display filter shows only HTTP POST requests?
- [ ] What does "Follow TCP Stream" reconstruct?
- [ ] What can Wireshark show about a TLS connection? What can it not show by default?
- [ ] What display filter isolates only TCP SYN packets (no ACK)?

---

## Key Takeaways

1. **ARP has no authentication.** Gratuitous ARP lets any host claim any IP→MAC mapping.
   ARP poisoning is the foundation of local network MITM — and it still works on most
   enterprise networks because DAI and 802.1X are rarely deployed everywhere.
2. **Switches learn MACs but can be overwhelmed.** MAC flooding degrades a switch to a hub.
   Port security limits MACs per port and mitigates this.
3. **VLANs provide logical isolation, not physical.** Double-tagging exploits the native
   VLAN handling on trunk ports to cross VLAN boundaries.
4. **Routing tables are your lateral movement map.** After compromising a host, the routing
   table tells you what other networks are reachable through it.
5. **NAT provides obscurity, not security.** It prevents direct inbound connections but
   does not stop outbound malware, C2 beaconing, or SSRF.
6. **IPv6 is often unmonitored.** Rogue RA attacks redirect dual-stack traffic without
   touching IPv4 at all. MITM6 exploits this systematically.

---

## Exercises

### Exercise 1 — ARP Attack Analysis

1. What command would you run to view the ARP cache on your Linux machine? Run it and
   document what you see. What does each entry represent?
2. In Wireshark, start a capture and filter for `arp`. On your local network, ping your
   gateway. Find the ARP request and reply. Note the source/destination MACs and IPs.
3. Describe exactly what an attacker needs to perform ARP poisoning: network position,
   tools, and what they enable after achieving MITM.
4. What is a gratuitous ARP and why is it a security weakness?

---

### Exercise 2 — Routing Table Analysis

On your Linux machine:

```bash
ip route show
```

1. Identify the default gateway. What happens to traffic sent to an IP not in any specific
   route?
2. Identify any directly connected subnets (proto kernel routes). How large is each subnet?
   How many hosts are on each?
3. If you were to pivot through this machine to a `10.0.0.0/8` network, what route command
   would you add?

---

### Exercise 3 — Foundation Check

Work through the self-assessment checklist above. For every checkbox you cannot confidently
tick, go back to the relevant day's material and re-read the key sections. Document your
gaps here as questions for Ghost.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 007 — Wireshark Lab](DAY-0007-Wireshark-Lab-Network-Analysis.md)*
*Next: [Day 009 — Linux Filesystem, Permissions and Users](../01-Foundation-02/DAY-0009-Linux-Filesystem-Permissions-and-Users.md)*
