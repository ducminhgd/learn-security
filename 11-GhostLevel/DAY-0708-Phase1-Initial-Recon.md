---
title: "Phase 1 — Initial Recon and Attack Surface Mapping"
tags: [ghost-level, recon, nmap, service-enumeration, attack-surface, module-11-ghost-level]
module: 11-GhostLevel
day: 708
prerequisites:
  - Day 707 — Ghost Level Lab Briefing
  - Day 52 — Active Recon Fundamentals
related_topics:
  - Day 709 — Phase 2: Web Application Recon
  - Day 729 — Ghost Level Debrief
---

# Day 708 — Phase 1: Initial Recon and Attack Surface Mapping

> "Your first 3 hours determine the quality of your next 45. An attacker
> who skips recon and goes straight for the web app will miss the network
> service. An attacker who spends 10 hours on recon has no time left to
> exploit. Three hours. Know every open port. Know every service version.
> Build the map. Then attack the map."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | Findings so far: _______

---

## Goals

Complete a full network scan of the 10.0.1.0/24 SABLE lab network. Identify
all running services, version numbers, and operating systems. Build the attack
surface map. Record all findings before moving to Phase 2.

**Target time:** ≤ 3 hours.

---

## 1 — Network Discovery

```bash
# ─── STEP 1: Host discovery (2 min) ──────────────────────────────────
# ARP sweep (fastest — only works on same L2 segment)
arp-scan 10.0.1.0/24

# Or ICMP sweep
nmap -sn 10.0.1.0/24 --open -oN recon/host_discovery.txt
# Save all output to recon/ from the start — every command

# Expected hosts (from briefing):
# 10.0.1.1  (gateway)
# 10.0.1.10 (sable-web)
# 10.0.1.20 (sable-svc)
# 10.0.1.30 (sable-dc)
# 10.0.1.40 (sable-iot)
# 10.0.1.50 (sable-store)  ← may not respond to ICMP
```

```
HOST DISCOVERY RESULTS

Hosts responding:
  10.0.1.1   [ ] up
  10.0.1.10  [ ] up
  10.0.1.20  [ ] up
  10.0.1.30  [ ] up
  10.0.1.40  [ ] up
  10.0.1.50  [ ] up / [ ] no response (expected — requires pivot)
  Other hosts found (unexpected): ________________________________
```

---

## 2 — Port Scanning

```bash
# ─── STEP 2: Full port scan — all 65535 ports (10–15 min) ────────────
# Run this in background while you do banner grabbing on known ports
nmap -p- --open -T4 --min-rate=1000 \
    -oA recon/full_portscan \
    10.0.1.10 10.0.1.20 10.0.1.30 10.0.1.40 &

# ─── STEP 3: Targeted service scan on likely ports (5 min) ───────────
# While the full scan runs, scan the expected ports
nmap -sV -sC -O \
    -p 21,22,25,53,80,88,135,139,389,443,445,636,\
1433,1521,3268,3269,3389,5985,5986,8080,8443,9000 \
    -oA recon/service_scan \
    10.0.1.10 10.0.1.20 10.0.1.30 10.0.1.40

# ─── STEP 4: UDP scan on critical ports (background) ─────────────────
sudo nmap -sU --open \
    -p 53,67,68,69,123,161,162,500,4500 \
    -oA recon/udp_scan \
    10.0.1.10 10.0.1.20 10.0.1.30 10.0.1.40 &
```

---

## 3 — Service Enumeration

### sable-web — 10.0.1.10

```bash
# Web server technology fingerprint
whatweb http://10.0.1.10 http://10.0.1.10:8080 https://10.0.1.10
curl -sI http://10.0.1.10 | grep -E "Server:|X-Powered-By:|Content-Type:"
curl -sI https://10.0.1.10 | grep -E "Server:|Strict-Transport|X-Frame"

# Directory discovery
feroxbuster -u http://10.0.1.10 \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -x js,json,php,html,txt,conf,bak \
    -o recon/web_dirs.txt &

# TLS certificate information (version, SAN, issuer)
echo | openssl s_client -connect 10.0.1.10:443 2>/dev/null | \
    openssl x509 -noout -text | grep -E "Subject:|Issuer:|DNS:|Not After"

# Check for common paths immediately
for path in /api /api/v1 /admin /swagger /graphql /robots.txt \
            /.well-known /healthz /metrics /actuator /debug; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "http://10.0.1.10${path}")
    echo "$code  http://10.0.1.10${path}"
done
```

```
sable-web ENUMERATION

Open ports: ____________________________________________________
Server header: _________________________________________________
X-Powered-By: _________________________________________________
TLS certificate CN: ___________________________________________
TLS certificate SAN: __________________________________________

Interesting paths found:
  /admin:  _____ (status code)
  /api:    _____ (status code)
  /api/v1: _____ (status code)
  /docs:   _____ (status code)
  Other:   ___________________________________________________

Technology stack (from whatweb): _____________________________
Dev port 8080 running: Y / N  Technology: ____________________
```

### sable-svc — 10.0.1.20

```bash
# TCP banner grab on port 9000
nc -nv 10.0.1.20 9000
# Send a null byte and see the response:
printf '\x00' | nc -nv -q2 10.0.1.20 9000 | xxd | head -5

# Try the ping operation (0x01):
# Protocol TLV: [type:1byte][length:2byte_BE][value:Nbytes]
printf '\x01\x00\x00' | nc -nv -q2 10.0.1.20 9000 | xxd

# Check if the binary is available for download (HTTP on another port?)
nmap -p 80,8080,21,22 10.0.1.20

# Get the binary if HTTP is available (or use a known path)
curl -s http://10.0.1.20/sable_broker -o binaries/sable_broker 2>/dev/null || \
    echo "Binary not served via HTTP — need another method"
```

```
sable-svc ENUMERATION

Port 9000 response to null byte:
  First 16 bytes: _______________________________________________
  (hex): ________________________________________________________

Response to \x01\x00\x00 (ping):
  Response: _____________________________________________________

Other open ports on sable-svc:
  Port: _____  Service: _________________________________________
  Port: _____  Service: _________________________________________

Binary obtained: Y / N  Method: _______________________________
Binary size: _________ bytes
file ./sable_broker: ___________________________________________
```

### sable-dc — 10.0.1.30

```bash
# Domain enumeration (no credentials yet)
# SMB null session
smbclient -N -L //10.0.1.30

# Enumerate domain info via LDAP (anonymous)
ldapsearch -x -H ldap://10.0.1.30 -b "" -s base \
    namingContexts defaultNamingContext 2>/dev/null

# DNS enumeration
dig @10.0.1.30 sable.local axfr 2>/dev/null || \
    dig @10.0.1.30 sable.local NS

# SMB signing status (relevant for relay attacks later)
crackmapexec smb 10.0.1.30 --gen-relay-list /tmp/no_signing.txt

# RPC enumeration (unauthenticated)
rpcclient -U "" -N 10.0.1.30 -c "enumdomains" 2>/dev/null
rpcclient -U "" -N 10.0.1.30 -c "enumdomusers" 2>/dev/null

# Check Kerberos (pre-auth required or not)
GetNPUsers.py SABLE.LOCAL/ -no-pass -dc-ip 10.0.1.30 \
    -usersfile /usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

```
sable-dc ENUMERATION

Domain name: ___________________________________________________
LDAP base DN: __________________________________________________

SMB null session: works / denied
Shares visible (if any): _______________________________________

DNS zone transfer: success / denied
DNS records found: _____________________________________________

Domain users found (anonymous): ________________________________
SMB signing required: Y / N  (if N: relay attack possible)

Kerberos AS-REP roastable users: _______________________________
```

### sable-iot — 10.0.1.40

```bash
# Web admin panel
whatweb http://10.0.1.40/
curl -sI http://10.0.1.40/ | grep -E "Server:|X-Powered-By:|Set-Cookie:"

# Check common IoT paths
for path in /admin /cgi-bin /login /api /system /config /firmware; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "http://10.0.1.40${path}")
    echo "$code  http://10.0.1.40${path}"
done

# Try default credentials
curl -sk -u admin:admin http://10.0.1.40/admin
curl -sk -u root:root http://10.0.1.40/admin
curl -sk -d "username=admin&password=admin" http://10.0.1.40/login
```

```
sable-iot ENUMERATION

Server: ________________________________________________________
Open ports: ____________________________________________________
Interesting paths:
  /admin: _____ /login: _____ /api: _____ /firmware: _____

Default credential attempt:
  admin:admin → response: _______________________________________
  Other combos tried: ___________________________________________
```

---

## 4 — Attack Surface Map

Complete this before starting Phase 2.

```
ATTACK SURFACE MAP — SABLE NETWORK

Target         Port(s)   Service/Tech       Initial Attack Vector
────────────────────────────────────────────────────────────────
sable-web      80/443    ________________   ________________________
               8080      ________________   ________________________
               _____     ________________   ________________________

sable-svc      9000      Custom TLV daemon  Binary + protocol reversing
               _____     ________________   ________________________

sable-dc       445/389   AD / SABLE.LOCAL   Kerberoasting, AS-REP, relay
               88        Kerberos           ________________________

sable-iot      80        IoT web panel      Default creds, UART shell
               _____     ________________   ________________________

sable-store    [pivot]   File server        Accessible after pivot only

────────────────────────────────────────────────────────────────
PRIORITY ORDER (update based on recon findings):
  1st target for Phase 2: ______________ because: ______________
  2nd target:             ______________
  3rd target:             ______________

Phase 1 complete: Y / N
Time taken: _______ hours (target: ≤ 3)
Unexpected findings from recon: __________________________________
```

---

## Navigation

← Previous: [Day 707 — Ghost Level Lab Briefing](DAY-0707-Ghost-Level-Lab-Briefing.md)
→ Next: [Day 709 — Phase 2: Web Application Recon and Exploitation](DAY-0709-Phase2-Web-App-Exploitation.md)
