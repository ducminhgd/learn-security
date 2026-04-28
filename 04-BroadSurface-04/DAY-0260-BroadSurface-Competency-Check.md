---
title: "BroadSurface Competency Check — Infrastructure, PrivEsc, Post-Exploitation"
tags: [competency-check, network-exploitation, privilege-escalation, post-exploitation,
       C2, detection, gate, self-assessment, Windows, Linux, ATT&CK]
module: 04-BroadSurface-04
day: 260
related_topics:
  - MITM and ARP Spoofing (Day 231)
  - Linux PrivEsc Enumeration (Day 234)
  - Windows PrivEsc Enumeration (Day 238)
  - Container Escape (Day 240)
  - C2 Concepts and Sliver Lab (Day 242)
  - Infrastructure Detection and Hardening (Day 244)
  - Module Review and Gate Preparation (Day 259)
  - Bug Bounty Platforms Overview (Day 261)
---

# Day 260 — BroadSurface Competency Check

> "This is the close of the broad surface module — four sub-modules, ninety
> days, from cloud to mobile to network to privilege escalation. Today you
> demonstrate that you can execute across all of it, not just the parts you
> practised most recently. A real engagement does not tell you which module
> to use. You decide."
>
> — Ghost

---

## Structure

| Section | Format | Time |
|---|---|---|
| Part 1: Conceptual Questions | Written, no notes | 40 min |
| Part 2: Linux PrivEsc Sprint | Hands-on lab | 30 min |
| Part 3: Network Attack Chain | Hands-on lab | 30 min |
| Part 4: Windows PrivEsc Sprint | Hands-on lab | 30 min |
| Part 5: Detection Query | Written, no notes | 20 min |
| **Total** | | **~2.5–3 hours** |

---

## Part 1 — Conceptual Questions (No Notes, No Browser)

Answer all 10. Write answers in the Questions section at the bottom.

**Q1.** Explain the ARP spoofing attack from first principles:

(a) What is a gratuitous ARP reply?  
(b) Why does a switch forward it without validation?  
(c) Why must IP forwarding be enabled on the attacker for stealth?  
(d) What is the switch-level control that prevents this attack, and how does it work?

---

**Q2.** You capture an NTLMv2 hash via Responder:

```
user1::WORKGROUP:aabbccdd11223344:abc...def:01010000...
```

(a) What is hashcat mode number for this hash type?  
(b) Is this hash replayable directly (pass-the-hash)? Why or why not?  
(c) What condition on the target network makes relay more valuable than cracking?  
(d) Write the ntlmrelayx.py command to relay this hash to `10.10.10.20`.

---

**Q3.** You run `getcap -r / 2>/dev/null` on a Linux box and get:

```
/usr/bin/python3.8 = cap_setuid+ep
```

(a) What does `cap_setuid` allow?  
(b) Write the exact command to escalate to root using this.  
(c) How would you detect this capability assignment? (What log entry or command
   would a defender run during a security audit?)

---

**Q4.** A root cron job runs every minute:

```
* * * * * root /usr/bin/tar -czf /backups/data.tar.gz /var/data/*
```

You have write access to `/var/data/`.

(a) Which exploitation technique applies?  
(b) Write the exact 4 commands/files you create to get a root shell.  
(c) Why does this work? (Explain the mechanism in one sentence.)

---

**Q5.** `whoami /priv` on a Windows host shows:

```
SeImpersonatePrivilege    Enabled
```

(a) What class of privilege escalation does this enable?  
(b) Name the tool you use and write the exact command to get a SYSTEM shell.  
(c) Why is this privilege available on IIS application pool accounts?  
(d) What is the Windows configuration change that removes this privilege from
   IIS application pools?

---

**Q6.** You are inside a Docker container. Running `cat /proc/1/status | grep CapEff`
returns `0000003fffffffff`.

(a) What does this tell you about the container's configuration?  
(b) Describe the cgroup release_agent escape technique in 5 steps.  
(c) Write the Falco rule that would fire when you write to the `release_agent` file.

---

**Q7.** You have SYSTEM access on a Windows machine and want to extract credential
hashes for lateral movement.

(a) Write the `reg save` commands to extract SAM, SYSTEM, and SECURITY hives.  
(b) Write the `secretsdump.py` command to parse the offline hives.  
(c) What does the output format `Administrator:500:LMhash:NThash` mean?  
(d) Write the `psexec.py` command for pass-the-hash lateral movement.

---

**Q8.** Explain the difference between beacon mode and session mode in Sliver:

(a) Which produces more network traffic? Why?  
(b) Which is stealthier against behavioural network detection? Why?  
(c) What is "jitter" and why is it important?  
(d) What is the JA3 hash and why do defenders use it to detect C2 frameworks?

---

**Q9.** Match each LOLBin to its abuse category:

| Binary | Abuse category |
|---|---|
| `certutil.exe -urlcache -split -f` | ? |
| `regsvr32.exe /s /n /u /i:http://...` | ? |
| `mshta.exe http://...` | ? |
| `fodhelper.exe` + registry manipulation | ? |
| `schtasks.exe /create` | ? |

Categories: File download, Code execution via HTA, Script execution via COM,
UAC bypass, Persistence.

---

**Q10.** A colleague tells you: "We deployed dynamic ARP inspection on all access
switches. Our network is now immune to MITM attacks."

Identify three scenarios where MITM attacks remain possible despite DAI:

1. ___
2. ___
3. ___

---

## Part 2 — Linux PrivEsc Sprint (30 min, no notes)

```bash
cd 04-BroadSurface-04/samples/competency-lab-linux/
docker compose up -d
docker exec -it -u labuser competency-linux bash
history -c
# START TIMER
```

Objectives:
```
[ ] Run full enumeration — document top 3 findings
[ ] Identify escalation path
[ ] Achieve root
[ ] Cat /root/flag.txt
```

Record:
- Escalation path found: ___
- Root obtained: Y / N
- Time taken: ___ min (pass threshold: ≤ 20 min)

---

## Part 3 — Network Attack Chain (30 min, no notes)

```bash
cd 04-BroadSurface-04/samples/competency-lab-network/
docker compose up -d
docker exec -it attacker bash
history -c
# START TIMER
```

Objectives:
```
[ ] ARP spoof between victim-a and victim-b
[ ] Capture at least one credential from plaintext protocol
[ ] Trigger LLMNR query and capture NTLMv2 hash
[ ] Document: user, hash format, hashcat mode number
```

Record:
- Credential captured: ___
- NTLMv2 hash captured: Y / N
- Time taken: ___ min (pass threshold: ≤ 20 min)

---

## Part 4 — Windows PrivEsc Sprint (30 min, no notes)

```
Connect to Windows lab VM:
evil-winrm -i 10.10.10.5 -u labuser -p 'Password123!'
history -c
# START TIMER
```

Objectives:
```
[ ] Run WinPEAS or manual checks
[ ] Identify top escalation path
[ ] Achieve SYSTEM
[ ] Run: whoami /all and paste output
```

Record:
- Escalation path: ___
- SYSTEM obtained: Y / N
- Time taken: ___ min (pass threshold: ≤ 20 min)

---

## Part 5 — Detection Query (20 min, no notes)

Write, from memory, a Sigma rule that detects:

**A Windows host where a non-SYSTEM process with SeImpersonatePrivilege enabled
spawns a child process with SYSTEM integrity level within 60 seconds.**

Requirements:
- Valid Sigma syntax
- Correct logsource (Windows Security log)
- At least one false positive listed
- ATT&CK tag included

Paste the rule in the Questions section.

---

## Competency Gate Criteria

| Criterion | Minimum bar |
|---|---|
| Conceptual questions | ≥ 8/10 correct without notes |
| Linux PrivEsc sprint | Root in ≤ 20 min, no notes |
| Network attack chain | Both credential types captured in ≤ 20 min |
| Windows PrivEsc sprint | SYSTEM in ≤ 20 min, no notes |
| Detection query | Syntactically valid, correct detection logic |

**If you do not pass:**

| Failed section | Return to |
|---|---|
| Q1–Q2 (network layer) | Day 231–232 |
| Q3–Q5 (PrivEsc) | Days 234–235, 238–239 |
| Q6 (container) | Day 240 |
| Q7–Q8 (post-exploitation, C2) | Days 241–242 |
| Q9–Q10 (LOLBins, defences) | Days 243–244 |
| Linux sprint > 20 min | Days 249, 257 (drills) |
| Network chain > 20 min | Days 245–246 (drills) |
| Windows sprint > 20 min | Day 251 (drill) |
| Detection query invalid | Day 244, 256 |

---

## What Comes Next

Module 04-BroadSurface is complete. The full broad attack surface has been
covered:
- Cloud security (Days 181–210)
- Mobile security (Days 211–230)
- Network exploitation and privilege escalation (Days 231–260)

The next module is **Bug Bounty Operations** (Days 261–365) — taking everything
you have built and applying it on real public programmes. The Year 1 goal:
an accepted report before Day 365.

---

## Questions and Competency Check Answers

> Part 1 — Write your answers below. Label Q1 through Q10.

> Part 2 — Paste your Linux sprint results (enumeration findings + flag).

> Part 3 — Paste your network attack results (credential + hash).

> Part 4 — Paste your Windows sprint results (whoami /all output).

> Part 5 — Paste your Sigma detection rule.

> General questions use numbering Q260.1, Q260.2 …

---

## Navigation

← Previous: [Day 259 — Module Review and Gate Preparation](DAY-0259-Infrastructure-Practice-Day-14.md)
→ Next: [Day 261 — Bug Bounty Platforms Overview](../05-BugBountyOps-01/DAY-0261-Bug-Bounty-Platforms-Overview.md)
