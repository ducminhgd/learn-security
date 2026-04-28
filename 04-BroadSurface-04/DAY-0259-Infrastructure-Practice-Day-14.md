---
title: "Infrastructure Practice Day 14 — Module Review and Gate Preparation"
tags: [practice, review, gate-preparation, self-assessment, methodology,
       network-exploitation, privilege-escalation, C2, detection, ATT&CK]
module: 04-BroadSurface-04
day: 259
related_topics:
  - All Days 231–258
  - BroadSurface Competency Check (Day 260)
---

# Day 259 — Infrastructure Practice Day 14: Module Review and Gate Preparation

> "Tomorrow is the gate. Today is not for learning new things — it is for
> consolidating everything you have. Fill the gaps. Sharpen the weak spots.
> Go into the gate knowing exactly where your ceiling is. Then push through it."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Reviewed every topic from Days 231–244 and confirmed understanding.
2. Written or polished your personal enumeration reference cards.
3. Drilled the one or two techniques you are least confident in.
4. Confirmed gate readiness against the Day 260 criteria.

**Time budget:** 5–6 hours.

---

## Block 1 — Module Self-Review (90 min)

For each topic: can you explain it AND execute it without notes?

| Topic | Explain? | Execute? |
|---|---|---|
| ARP spoofing — why it works on a switch | Y / N | Y / N |
| ARP spoofing — arpspoof commands | Y / N | Y / N |
| LLMNR poisoning — what triggers a broadcast | Y / N | Y / N |
| Responder — command and config change needed for relay | Y / N | Y / N |
| ntlmrelayx — command for SAM dump | Y / N | Y / N |
| NTLMv2 hash format — hashcat mode number | Y / N | Y / N |
| tshark — extract FTP credentials from PCAP | Y / N | Y / N |
| Linux enum — top 5 checks in order | Y / N | Y / N |
| SUID — cap_setuid Python3 exploit | Y / N | Y / N |
| SUID — vim shell escape | Y / N | Y / N |
| Cron — wildcard injection with tar | Y / N | Y / N |
| Cron — PATH injection | Y / N | Y / N |
| PwnKit — what it exploits, affected versions | Y / N | Y / N |
| Windows enum — whoami /priv output to look for | Y / N | Y / N |
| GodPotato — command and OS version range | Y / N | Y / N |
| Unquoted service path — how Windows parses it | Y / N | Y / N |
| Container escape — cgroup release_agent steps | Y / N | Y / N |
| Container escape — Docker socket API call | Y / N | Y / N |
| Pass-the-hash — psexec.py command format | Y / N | Y / N |
| Sliver — generate beacon command | Y / N | Y / N |
| LOLBins — certutil download, regsvr32 Squiblydoo | Y / N | Y / N |
| Detection — Event ID for new local user (Windows) | Y / N | Y / N |
| Detection — auditd key for SUID execution | Y / N | Y / N |

Mark every N. Spend 20 minutes on each N before moving to Block 2.

---

## Block 2 — Gap Drilling (90 min)

For each N from Block 1, do one of:

**If you missed SUID commands:**
```bash
# Write these from memory — no GTFOBins:
python3 -c '___'       # cap_setuid
vim -c '___'            # shell escape
find . -exec ___ \;     # find SUID
awk 'BEGIN {___}'       # awk SUID
```

**If you missed cron exploitation:**
```bash
# Write the tar wildcard injection sequence from scratch:
cd /writable/dir
touch -- '___'
touch -- '___'
cat > revshell.sh << 'EOF'
___
EOF
```

**If you missed ntlmrelayx setup:**
```bash
# Write the exact sequence from memory:
sed -i '___'  # disable Responder SMB
sed -i '___'  # disable Responder HTTP
responder ___  # start command
ntlmrelayx.py ___  # start relay
```

---

## Block 3 — Reference Card Polish (60 min)

Produce your final personal reference cards for the gate:

### Card 1 — Linux PrivEsc (10 commands you run in order, every time)

```
1. ___
2. ___
3. ___
4. ___
5. ___
6. ___
7. ___
8. ___
9. ___
10. ___
```

### Card 2 — Windows PrivEsc (10 checks in order)

```
1. ___
2. ___
3. ___
4. ___
5. ___
6. ___
7. ___
8. ___
9. ___
10. ___
```

### Card 3 — Network Attack Sequence

```
MITM:
  1. ___
  2. ___
  3. ___

LLMNR + Relay:
  1. ___
  2. ___
  3. ___
  4. ___
```

---

## Gate Readiness Checklist

| Criterion | Gate requirement | Ready? |
|---|---|---|
| Conceptual questions | ≥ 8/10 without notes | Y / N |
| Linux PrivEsc sprint | Root in ≤ 20 min, no notes | Y / N |
| Windows PrivEsc sprint | SYSTEM in ≤ 20 min, no notes | Y / N |
| Network attack chain | MITM → hash in ≤ 20 min, no notes | Y / N |
| Detection query | Correct Sigma rule from memory | Y / N |
| Kill chain timing | Full chain ≤ 45 min | Y / N |

Any N: spend the remaining time on that specific gap. Do not move on without addressing it.

---

## Final Statement

Write in one paragraph: what have you learned in this module that you did not know before?

```
___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q259.1, Q259.2 …).

---

## Navigation

← Previous: [Day 258 — Infrastructure Practice Day 13](DAY-0258-Infrastructure-Practice-Day-13.md)
→ Next: [Day 260 — BroadSurface Competency Check](DAY-0260-BroadSurface-Competency-Check.md)
