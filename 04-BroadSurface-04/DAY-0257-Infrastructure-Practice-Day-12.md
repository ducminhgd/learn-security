---
title: "Infrastructure Practice Day 12 — Full Kill Chain Speed Run (Under 45 min)"
tags: [practice, kill-chain, speed-run, timed, network, privilege-escalation,
       C2, muscle-memory, ATT&CK]
module: 04-BroadSurface-04
day: 257
related_topics:
  - Infrastructure Practice Day 9 (Day 254)
  - Infrastructure Practice Day 11 (Day 256)
  - Infrastructure Practice Day 13 (Day 258)
  - BroadSurface Competency Check (Day 260)
---

# Day 257 — Infrastructure Practice Day 12: Full Kill Chain Speed Run

> "You ran the kill chain on Day 254. You wrote detection rules on Day 256.
> Today you run it again — faster. The target is 45 minutes, start to C2
> check-in. If you are under 45: you are kill-chain ready for the gate.
> If you are over: identify the bottleneck and fix it today, not next week."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Executed the full infrastructure kill chain in under 45 minutes without notes.
2. Compared your time to Day 254's Run 2.
3. Identified and drilled the slowest phase in isolation.
4. Confirmed you can explain — not just execute — every step.

**Time budget:** 5 hours.

---

## Pre-Run Preparation (10 min)

```bash
# Reset and verify the lab:
cd 04-BroadSurface-04/samples/full-kill-chain-lab/
docker compose down && docker compose up -d

# Confirm all services running:
docker ps

# Clear history:
history -c

# Sliver server already running? Confirm:
sliver-client  # should connect to running server
jobs           # HTTPS listener should be active
exit

# Ready.
```

---

## The Run (No notes, no history, timer started)

```bash
# START TIMER NOW
```

### Phase checkpoints (mark timestamps as you go):

```
T+00:00 — Lab reset complete
T+_____ — MITM established (ARP poison running)
T+_____ — First credential captured
T+_____ — LLMNR hash captured OR relay succeeded
T+_____ — Shell on first host
T+_____ — PrivEsc complete (root/SYSTEM)
T+_____ — Credentials dumped
T+_____ — Persistence planted
T+_____ — C2 beacon delivered and checking in
T+_____ — STOP TIMER
```

**Total time: ___ min**

---

## Phase-by-Phase Analysis

Compare to Day 254 Run 2:

| Phase | Day 254 Time | Today | Improvement |
|---|---|---|---|
| MITM setup | ___ | ___ | ___ |
| Credential capture | ___ | ___ | ___ |
| Shell obtained | ___ | ___ | ___ |
| PrivEsc | ___ | ___ | ___ |
| Post-exploitation | ___ | ___ | ___ |
| C2 check-in | ___ | ___ | ___ |
| **Total** | ___ | ___ | ___ |

**Slowest phase today:** ___

---

## Isolation Drill (if any phase took > 10 min)

For the slowest phase: do it 3 more times in isolation, timed.

```
Isolated drill: ___
Run 1: ___ min
Run 2: ___ min
Run 3: ___ min
Improvement: ___
```

---

## Explain-the-Path Check

Without notes, explain to yourself (or write below) the answer to:

1. Why does ARP spoofing work even against a modern managed switch?  
   Answer: ___

2. Why does LLMNR poisoning not require any access to the victim's machine?  
   Answer: ___

3. Why does SeImpersonatePrivilege lead to SYSTEM and not just administrative access?  
   Answer: ___

4. Why does the Sliver beacon use jitter?  
   Answer: ___

If you cannot answer any of these without notes: that is the gap the gate will expose.

---

## Gate Readiness Check

| Criterion | Status |
|---|---|
| Full kill chain in < 45 min | Y / N |
| All phases executed without notes | Y / N |
| Can explain why each technique works | Y / N |
| Have written at least 3 detection rules | Y / N |

If all Yes: you are ready for the gate (Day 260).  
If any No: return to the relevant day and practice until the answer changes.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q257.1, Q257.2 …).

---

## Navigation

← Previous: [Day 256 — Infrastructure Practice Day 11](DAY-0256-Infrastructure-Practice-Day-11.md)
→ Next: [Day 258 — Infrastructure Practice Day 13](DAY-0258-Infrastructure-Practice-Day-13.md)
