---
title: "Phase 5 — OPSEC Review and Engagement Log Audit"
tags: [ghost-level, opsec, log-analysis, detection, evasion,
  blue-team-perspective, module-11-ghost-level]
module: 11-GhostLevel
day: 722
prerequisites:
  - Day 721 — Phase 5: Persistence and C2
  - Day 530 — OPSEC Fundamentals for Red Teams
related_topics:
  - Day 723 — Phase 6: Timeline Reconstruction
---

# Day 722 — Phase 5: OPSEC Review and Engagement Log Analysis

> "Before you write the report, review the logs — not as the attacker
> who put those entries there, but as the defender who has to find them.
> If you can reconstruct your own timeline from the logs alone, you
> understand the attack. More importantly, you know what would have
> stopped you."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | Persistence deployed: Y / N

---

## Goals

Step into the blue team role. Review the logs from each compromised host and
identify which of your actions were detectable and which were invisible.
This dual perspective is what separates a red teamer from a security engineer.
Use this analysis directly in the report's detection section.

**Target time:** 2 hours.

---

## 1 — What Did You Leave Behind?

```
OPSEC ASSESSMENT — ATTACKER SELF-REVIEW

For each action taken, answer: would a monitored environment have caught this?

ACTION                              DETECTABLE?   LOG SOURCE
─────────────────────────────────────────────────────────────────────
nmap port scan (sable-web)          Y / N         IDS/firewall
JWT alg:none attack attempt         Y / N         sable-web app log
SSRF to internal (sable-web)        Y / N         sable-web app log
sable-svc protocol probing          Y / N         sable-svc logs
sable-svc fuzzing (crash)           Y / N         syslog / crash dump
sable-svc exploit (RCE)             Y / N         syslog / TCP conn
SSH lateral move to pivot host      Y / N         /var/log/auth.log
BloodHound collection (LDAP)        Y / N         Windows Event 4662
Kerberoasting (TGS requests)        Y / N         Windows Event 4769
DCSync                              Y / N         Windows Event 4662
New scheduled task on DC            Y / N         Windows Event 4698
sable-iot CGI injection             Y / N         lighttpd/httpd log
sable-store SMB access              Y / N         Windows Event 5140

NOISIEST ACTIONS (ranked):
  1. _______________________________________________________________
  2. _______________________________________________________________
  3. _______________________________________________________________

STEALTHIEST ACTIONS:
  1. _______________________________________________________________
  2. _______________________________________________________________
```

---

## 2 — Log Review on Compromised Hosts

### 2.1 — sable-web Log Review

```bash
# On sable-web (via pivot or shell):
# ─── Apache / Nginx access log ────────────────────────────────────────
tail -200 /var/log/nginx/access.log 2>/dev/null | \
    grep -E "40[0-9]|50[0-9]|\.\.|curl|python|nmap" | head -30

tail -200 /var/log/apache2/access.log 2>/dev/null | head -30

# ─── Application log ─────────────────────────────────────────────────
find /var/www /opt /app -name "*.log" 2>/dev/null | xargs tail -50 2>/dev/null

# ─── Auth log ─────────────────────────────────────────────────────────
grep -E "Failed|Accepted|Invalid" /var/log/auth.log 2>/dev/null | tail -20

# ─── Syslog ───────────────────────────────────────────────────────────
tail -100 /var/log/syslog 2>/dev/null | grep -v "systemd\|CRON.*root" | head -20
```

```
SABLE-WEB LOG FINDINGS

Attacker IP visible in logs: Y / N  (if Y — OPSEC failure)
JWT exploit attempts logged: Y / N
  Log entry: _____________________________________________________
SSRF requests logged: Y / N
  Log entry: _____________________________________________________
Shell access visible in auth.log: Y / N
Cron persistence entry visible: Y / N

Would a SOC analyst find this in 24 hours? Y / N
  Why / why not: ________________________________________________
```

### 2.2 — sable-svc Log Review

```bash
# On sable-svc:
tail -100 /var/log/syslog 2>/dev/null | grep -i "sable\|crash\|segfault"
dmesg | tail -20 | grep -i "segfault\|killed\|oom" 2>/dev/null

# Check for core dump (crash artefact):
ls -lh /var/crash/ /tmp/*.core /core* 2>/dev/null
```

```
SABLE-SVC LOG FINDINGS

Crash logged (from fuzzing): Y / N
  syslog entry: _________________________________________________
Exploit connection logged (TCP): Y / N
  Would firewall log this: Y / N (port 9000 outbound)

Overall detectability: HIGH / MEDIUM / LOW
```

### 2.3 — Windows Event Log Review (sable-dc)

```bash
# Via proxychains using impacket or CrackMapExec:
# Retrieve specific event IDs:

# Event 4769 (Kerberos TGS) — Kerberoasting indicator
proxychains python3 /usr/share/doc/python3-impacket/examples/eventvwr.py \
    "SABLE.LOCAL/Administrator:<password>" \
    -dc-ip 10.0.1.30 2>/dev/null || true

# Alternative: use CrackMapExec to dump recent logs
proxychains crackmapexec smb 10.0.1.30 \
    -u Administrator -p "<password>" \
    --users 2>/dev/null | grep -i "logon\|failed"

# Get Security event log (EVTX) for offline analysis:
proxychains python3 /usr/share/doc/python3-impacket/examples/smbclient.py \
    "SABLE.LOCAL/Administrator:<password>" \
    -dc-ip 10.0.1.30 << 'EOF'
use C$
cd Windows\System32\winevt\Logs
get Security.evtx
EOF
```

```
WINDOWS EVENT LOG ANALYSIS (sable-dc)

Event 4769 (TGS Kerberoast indicator):
  Logged: Y / N  Count: _______
  Source account visible: Y / N

Event 4662 (DCSync indicator):
  Logged: Y / N
  Operation GUID matches GetChanges: Y / N

Event 4698 (Scheduled task created):
  Logged: Y / N
  Task name: _____________________________________________________

Event 4728 (Member added to DA group):
  Logged: Y / N  (if new account was created)

Event 4624/4625 (Logon events):
  Logon from attacker IP: Y / N
  Pass-the-Hash indicator (LogonType 3, NTLM): Y / N

DETECTION SUMMARY:
  A SIEM with baseline alerting WOULD have caught: ________________
  A SIEM with baseline alerting WOULD NOT have caught: ____________
  A threat hunter WOULD find (given 1 day): ______________________
```

---

## 3 — OPSEC Improvement Notes

Document what you would do differently in a real engagement to reduce the
noise floor. This goes directly into the engagement report executive summary.

```
OPSEC IMPROVEMENT NOTES

HIGH-NOISE ACTIONS (that would have triggered EDR/SIEM):
  1. _____________________________________________________________
     Better approach: ___________________________________________
  2. _____________________________________________________________
     Better approach: ___________________________________________
  3. _____________________________________________________________
     Better approach: ___________________________________________

WHAT WOULD HAVE STOPPED THIS ENGAGEMENT:
  Single control: _______________________________________________
  (e.g., "network segmentation preventing sable-web from reaching port 9000")

WHAT A MATURE SOC WOULD HAVE DONE AT EACH PHASE:
  Phase 1 (recon): _______________________________________________
  Phase 2 (web exploit): _________________________________________
  Phase 3 (binary exploit): ______________________________________
  Phase 4 (AD): __________________________________________________
  Phase 5 (IoT/store): ___________________________________________

RECOMMENDED DETECTION IMPROVEMENTS FOR THE REPORT:
  1. ____________________________________________________________
  2. ____________________________________________________________
  3. ____________________________________________________________
  4. ____________________________________________________________
  5. ____________________________________________________________
```

---

## 4 — Phase 5 Completion Check

```
PHASE 5 FINAL CHECKLIST

Exploitation:
  [ ] sable-web exploited — shell / admin access
  [ ] sable-svc binary exploited — shell obtained
  [ ] Domain Admin obtained on SABLE.LOCAL
  [ ] sable-iot shell obtained
  [ ] sable-store data accessed

Evidence:
  [ ] Every finding has a screenshot or log snippet
  [ ] All credentials documented in creds_register.txt
  [ ] Evidence package at engagement/evidence-package/

Persistence:
  [ ] One mechanism per host, documented
  [ ] ATT&CK TTPs mapped for each mechanism

OPSEC review:
  [ ] Log review performed on each host
  [ ] Detection gaps identified
  [ ] Improvement recommendations noted

Hours used: _______  (target: ≤ 38h for phases 1–5)
Hours remaining: _______ for reporting (target: ≥ 10h)

→ PROCEED TO PHASE 6: REPORTING
```

---

## Navigation

← Previous: [Day 721 — Phase 5: Persistence and C2](DAY-0721-Phase5-Persistence-C2.md)
→ Next: [Day 723 — Phase 6: Engagement Report — Timeline](DAY-0723-Phase6-Report-Timeline.md)
