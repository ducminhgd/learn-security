---
title: "Infrastructure Practice Day 10 — Mixed HTB Box (Network + PrivEsc)"
tags: [practice, HTB, HackTheBox, mixed, network, privilege-escalation,
       methodology, hands-on, medium, hard, ATT&CK]
module: 04-BroadSurface-04
day: 255
related_topics:
  - Linux PrivEsc Enumeration (Day 234)
  - Windows PrivEsc Enumeration (Day 238)
  - Infrastructure Practice Day 9 (Day 254)
  - Infrastructure Practice Day 11 (Day 256)
---

# Day 255 — Infrastructure Practice Day 10: Mixed HTB Box

> "This is an unsupported machine. No guide. No category label. You have a
> set of techniques. You have a methodology. Apply them. When something does
> not work, move to the next check. That is the job."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Completed a Medium or Hard-rated HackTheBox machine that involves both
   network-level exploitation and privilege escalation.
2. Documented the complete attack path from nmap to root/SYSTEM.
3. Written a one-page engagement summary.

**Time budget:** 7–8 hours.

---

## Target Selection

Pick a machine that requires both network access/exploitation AND privilege
escalation (not just a web app). Recommended retired Medium/Hard machines:

| Machine | OS | Techniques |
|---|---|---|
| **Kotarak** | Linux | SSRF → internal services → credential theft → PrivEsc |
| **Jail** | Linux | NFS misconfiguration + RPC → PrivEsc |
| **Tally** | Windows | SMB → MSSQL link → impersonation → SeImpersonate |
| **Forest** | Windows | AS-REP Roasting + DCSync → domain compromise |
| **Reel** | Windows | Phishing → credential capture → PowerShell PrivEsc |

---

## Structured Attack Methodology

### Step 1: Reconnaissance (30–60 min)

```bash
nmap -sCV -p- --min-rate 5000 <target-ip> | tee nmap-full.txt
nmap -sU --top-ports 20 <target-ip> | tee nmap-udp.txt

# Service-specific enumeration based on nmap results:
# SMB:
smbclient -L <target-ip> -N
crackmapexec smb <target-ip>
# NFS:
showmount -e <target-ip>
# LDAP:
ldapsearch -x -h <target-ip> -b "DC=domain,DC=local" 2>/dev/null
```

### Step 2: Initial Access

```
Service exploited: ___
CVE / technique: ___
User obtained: ___
```

### Step 3: Privilege Escalation

```
OS: Linux / Windows
Enumeration tool used: LinPEAS / WinPEAS / manual
Primary finding: ___
Escalation technique: ___
Root / SYSTEM obtained: Y / N
```

---

## Engagement Summary (write after completion)

```
Machine: ___                    OS: ___
Difficulty: ___                  Time: ___ hours

Attack Path:
  1. Initial recon: found ___
  2. Gained foothold via: ___
  3. User flag at: ___
  4. PrivEsc via: ___
  5. Root/System flag at: ___

Most interesting finding: ___
Longest stuck period: ___  (what was the blocker?)
What technique from this module did this reinforce? ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q255.1, Q255.2 …).

---

## Navigation

← Previous: [Day 254 — Infrastructure Practice Day 9](DAY-0254-Infrastructure-Practice-Day-9.md)
→ Next: [Day 256 — Infrastructure Practice Day 11](DAY-0256-Infrastructure-Practice-Day-11.md)
