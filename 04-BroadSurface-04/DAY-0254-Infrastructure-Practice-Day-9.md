---
title: "Infrastructure Practice Day 9 — Full Infrastructure Kill Chain"
tags: [practice, kill-chain, network, privilege-escalation, post-exploitation,
       C2, lateral-movement, end-to-end, timed, T1557, T1548, T1021, ATT&CK]
module: 04-BroadSurface-04
day: 254
related_topics:
  - MITM and ARP Spoofing (Day 231)
  - Linux PrivEsc Enumeration (Day 234)
  - Post-Exploitation Basics (Day 241)
  - C2 Concepts and Sliver Lab (Day 242)
  - Infrastructure Practice Day 8 (Day 253)
---

# Day 254 — Infrastructure Practice Day 9: Full Infrastructure Kill Chain

> "Every attack has a story: how did you get in, how did you get higher,
> and how far did you get? Today you tell that story start to finish —
> from network eavesdropping to a second compromised host. No pre-positioned
> tools. No notes. Just the lab network and the techniques you know."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Executed a full infrastructure kill chain from MITM to multi-host compromise.
2. Completed all phases in under 60 minutes on the second attempt.
3. Generated and read your attack timeline from system logs.

**Time budget:** 6 hours (2 runs + analysis).

---

## Kill Chain Reference (Read Once — Then Cover It)

```
Phase 1 — MITM and Credential Capture (< 10 min)
  ARP spoof victim-a ↔ victim-b
  Capture plaintext protocol credentials
  Trigger LLMNR query from victim-b

Phase 2 — LLMNR Relay or Hash Crack (< 10 min)
  Relay NTLMv2 to a relay-vulnerable host
  OR crack hash and use credentials directly

Phase 3 — Foothold and Enumeration (< 15 min)
  SSH / SMB / WinRM into compromised host
  Run enumeration (LinPEAS or manual checklist)
  Identify escalation path

Phase 4 — Privilege Escalation (< 10 min)
  Execute identified path
  Confirm SYSTEM/root

Phase 5 — Post-Exploitation (< 10 min)
  Dump credentials (SAM / /etc/shadow)
  Plant persistence
  Lateral movement to second host

Phase 6 — Establish C2 (< 5 min)
  Deliver Sliver beacon to the compromised host
  Confirm check-in
  Execute one post-exploitation command via C2
```

---

## Run 1 — Notes Permitted

```bash
# Reset lab
cd 04-BroadSurface-04/samples/full-kill-chain-lab/
docker compose down && docker compose up -d

# Start timer when lab is up
```

```
Phase 1 complete: ___ min
Phase 2 complete: ___ min
Phase 3 complete: ___ min
Phase 4 complete: ___ min
Phase 5 complete: ___ min
Phase 6 complete: ___ min
Total: ___ min
```

---

## Run 2 — No Notes (Target: < 60 min)

```bash
docker compose down && docker compose up -d
history -c
# START TIMER
```

```
Phase 1: ___ min
Phase 2: ___ min
Phase 3: ___ min
Phase 4: ___ min
Phase 5: ___ min
Phase 6: ___ min
Total: ___ min  (target: < 60 min)
```

---

## Attack Timeline Reconstruction

After Run 2, reconstruct your attack timeline from logs:

```bash
# Linux host: auth.log
grep "$(date '+%b %d')" /var/log/auth.log | tail -50

# Wireshark: filter for the attack phases
tshark -r /tmp/full-chain.pcap \
  -Y "arp.opcode == 2 or ntlmssp or ssh" \
  -T fields -e frame.time -e _ws.col.Protocol -e ip.src -e ip.dst

# Answer:
# 1. At what timestamp did the MITM start? ___
# 2. At what timestamp did you get a shell? ___
# 3. At what timestamp did the C2 check in? ___
# 4. How many minutes elapsed from start to persistence? ___
```

---

## Self-Assessment

| Phase | Executed without notes | Time |
|---|---|---|
| ARP spoofing + credential capture | Y / N | ___ |
| LLMNR relay or crack | Y / N | ___ |
| Enumeration | Y / N | ___ |
| PrivEsc | Y / N | ___ |
| Post-exploitation + persistence | Y / N | ___ |
| C2 delivery | Y / N | ___ |

**Which phase needed notes?** ___  
**What is your target for Run 3 (Day 257)?** ___

---

## Questions

> Add your questions here. Each question gets a Global ID (Q254.1, Q254.2 …).

---

## Navigation

← Previous: [Day 253 — Infrastructure Practice Day 8](DAY-0253-Infrastructure-Practice-Day-8.md)
→ Next: [Day 255 — Infrastructure Practice Day 10](DAY-0255-Infrastructure-Practice-Day-10.md)
