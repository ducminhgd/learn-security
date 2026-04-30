---
title: "Practice Engagement Checkpoint — Days 511–519 Consolidation"
tags: [red-team, checkpoint, practice, ADCS, RBCD, AS-REP, SID-history, LOLAD,
  evasion, consolidation, ATT&CK]
module: 08-RedTeam-03
day: 520
related_topics:
  - Advanced Evasion and AV Bypass (Day 519)
  - ADCS Attack Surface (Day 511)
  - RBCD Attack (Day 514)
  - AS-REP Roasting and Password Spraying (Day 515)
  - SID History and Inter-Forest Trust Attacks (Day 516)
  - AdminSDHolder and DCShadow (Day 517)
  - Living-Off-The-Land in AD (Day 518)
  - Milestone 500 Days (Day 500)
---

# Day 520 — Practice Engagement Checkpoint

> "This is not a test. A test has a pass/fail line. This is a mirror.
> You look at what you can do — not what you remember reading — and you fix
> the gap between the two. If you cannot execute a technique in a lab under
> time pressure, you do not own it. You have read about it. There is a
> difference. Close that difference today."
>
> — Ghost

---

## Goals

Consolidate techniques from Days 511–519 under time pressure.
Identify which techniques you can execute versus which you only recognise.
Produce an honest gap analysis and a concrete re-lab plan.
Run at least one full technique chain from foothold to DA-equivalent without
referring to notes.

**Prerequisites:** Days 511–519. A running AD lab (two domains preferred for trust
attack practice).
**Time budget:** 6 hours total. Structured below.

---

## Part 1 — Self-Assessment Before the Lab

Rate each technique **before** you open the lab. Be honest.

```
Rating scale (same as Day 500):
  1 — Cannot execute without step-by-step reference
  2 — Can execute with notes open; would miss steps independently
  3 — Can execute without notes; might miss cleanup or edge cases
  4 — Can execute, explain the mechanism, detect it, and remediate it

TECHNIQUE                               | RATING (1–4) | LAST EXECUTED
-------------------------------------   | ------------ | ----------------
ADCS: Identify ESC1 with Certipy find   |              |
ADCS ESC1: req + auth → TGT + NT hash  |              |
ADCS ESC8: PetitPotam + relay chain     |              |
RBCD: addcomputer + write + getST       |              |
RBCD: cleanup (delete + flush)          |              |
AS-REP: GetNPUsers.py unauthenticated  |              |
AS-REP: hashcat -m 18200               |              |
Password spray: calibrate to policy     |              |
Password spray: kerbrute + timing       |              |
SID History: child-to-parent Gold Tick  |              |
SID History: secretsdump via ccache     |              |
AdminSDHolder: Add-DomainObjectAcl      |              |
AdminSDHolder: force SDProp             |              |
AdminSDHolder: verify ACE propagated    |              |
DCShadow: two-terminal push             |              |
LOLAD: ADSI Kerberoastable enum         |              |
LOLAD: comsvcs.dll MiniDump            |              |
LOLAD: diskshadow + robocopy NTDS.dit  |              |
LOLAD: sc.exe remote lateral movement  |              |
LOLAD: netsh portproxy tunnel           |              |
Evasion: indirect syscall concept       |              |
Evasion: BYOVD — driver load + detect  |              |
Evasion: AMSI bypass (context corrupt)  |              |
Evasion: sleep obfuscation concept      |              |
```

Any technique rated 1 or 2 goes into your priority re-lab queue (Part 5).

---

## Part 2 — Timed Challenges (3 Hours)

Complete these challenges in order. Time limit per challenge is shown.
Do not skip — if you cannot complete one, note the sticking point and move on.

---

### Challenge 1 — ADCS Attack Chain (45 min)

**Target state:** DA-level TGT obtained via ADCS without password cracking.

```
Lab setup required:
  → Enterprise CA installed on a Windows Server
  → A certificate template with ENROLLEE_SUPPLIES_SUBJECT flag enabled
    and Client Authentication EKU present
  → A low-privilege user (jsmith) with Enroll rights on the template

Your mission:
  1. Run Certipy find to identify the vulnerable template.
  2. Request a certificate for Administrator using ESC1.
  3. Authenticate with the certificate → obtain TGT + NT hash.
  4. Verify: secretsdump.py using the TGT.

Time: 45 minutes.

Sticking point log:
  → Step where you got stuck:
  → Error message (copy/paste):
  → What you tried:
  → Resolution:
```

---

### Challenge 2 — RBCD Without Notes (30 min)

**Target state:** Shell as Administrator on a workstation via RBCD.

```
Lab setup required:
  → Domain-joined workstation (TARGET$)
  → jsmith has GenericWrite on TARGET$'s computer object in AD
  → ms-DS-MachineAccountQuota ≥ 1 on the domain

Your mission (from memory — no notes):
  1. Create a machine account (ATTACKER$) using Impacket.
  2. Write ATTACKER$'s SID into TARGET$'s RBCD attribute.
  3. Request a TGS via S4U impersonating Administrator to TARGET.
  4. secretsdump.py using the ccache.
  5. Clean up: delete ATTACKER$, flush the RBCD attribute.

Time: 30 minutes.
Penalty: if you open notes, add 15 minutes to your time.

Sticking point log:
  → Step where you got stuck:
  → Exact addcomputer.py / rbcd.py / getST.py flags missed:
  → Resolution:
```

---

### Challenge 3 — AS-REP Roasting + Password Spraying (30 min)

**Target state:** At least one plaintext credential obtained via offline attack
or spraying.

```
Lab setup required:
  → One account with DoesNotRequirePreAuth = True (vpn_service / Summer2024!)
  → Three additional domain accounts
  → AD lockout policy: threshold 5, window 30 min

Your mission:
  Part A — AS-REP:
    1. Run GetNPUsers.py unauthenticated with a username list.
    2. Crack the returned hash with hashcat -m 18200.
    3. Verify the recovered password by authenticating with it.

  Part B — Spray:
    1. Query the lockout policy: net accounts /domain.
    2. Spray 'Summer2024!' with Kerbrute against all lab accounts.
    3. Identify: which Windows event fires for Kerbrute vs crackmapexec?
       Write the event ID here: __________

Time: 30 minutes.

Sticking point log:
  → Missed flags or command syntax:
  → Event ID answer (no peeking): Event 4771 (Kerberos) vs Event 4625 (NTLM)
```

---

### Challenge 4 — SID History Child-to-Parent (45 min)

**Target state:** Full secretsdump of the root domain DC using a Golden Ticket
with an Extra SID, starting only with child domain DA access.

```
Lab setup required:
  → Two-domain forest: child.corp.local and corp.local
  → DA access to child.corp.local (child krbtgt hash available)
  → Forest root Enterprise Admins SID known

Your mission:
  1. Identify the forest root Enterprise Admins SID.
  2. Use ticketer.py to forge a TGT for child.corp.local with -extra-sid.
  3. Export KRB5CCNAME and run secretsdump.py against the root DC.
  4. Verify: you can read NTDS hashes from corp.local.

  Bonus: repeat using Mimikatz kerberos::golden /sids= on Windows.

Time: 45 minutes.

Sticking point log:
  → Correct ticketer.py flags (write them from memory first, then verify):
    -nthash [  ] -domain-sid [  ] -domain [  ] -extra-sid [  ]
  → Step where auth failed:
  → Root cause:
```

---

### Challenge 5 — LOLAD Kill-Chain (45 min)

**Target state:** Full kill-chain using ONLY native Windows tools:
enumerate → credential access → lateral movement → persistence.

```
Constraint: no Mimikatz, no Rubeus, no SharpHound, no external binaries.
Allowed: anything pre-installed on a standard Windows Server 2019/2022.

Your mission:
  1. Enumerate Kerberoastable accounts using PowerShell ADSI ([ADSISearcher]).
  2. Enumerate domain admins using net.exe commands only.
  3. Dump LSASS via rundll32 comsvcs.dll MiniDump.
  4. Extract NTDS.dit via diskshadow + robocopy.
  5. Create a remote scheduled task on a second lab host using native schtasks.
  6. Add a registry Run key persistence for the current user using reg.exe.

Time: 45 minutes.
Scoring: 1 point per step completed. Goal = 6/6.

Score: ___/6

Sticking point log:
  → Which ADSI LDAP filter did you use for Kerberoastable accounts?
    Write it here: (&(objectCategory=user)(servicePrincipalName=*))
  → diskshadow script content (write from memory):
  → schtasks /create flags for remote execution:
```

---

## Part 3 — Blind Detection Exercise (30 min)

Read the following Sysmon log excerpt and answer the questions without looking
up the answers. Write your answers first, then verify.

```xml
<!-- Log A -->
<Event>
  <EventID>1</EventID>
  <Image>C:\Windows\System32\rundll32.exe</Image>
  <CommandLine>rundll32.exe C:\Windows\System32\comsvcs.dll,
      MiniDump 636 C:\Windows\Temp\ls.dmp full</CommandLine>
  <ParentImage>C:\Windows\System32\cmd.exe</ParentImage>
</Event>

<!-- Log B -->
<Event>
  <EventID>3</EventID>
  <Image>C:\Windows\System32\certutil.exe</Image>
  <DestinationIp>185.220.101.42</DestinationIp>
  <DestinationPort>80</DestinationPort>
</Event>

<!-- Log C -->
<Event>
  <EventID>6</EventID>
  <ImageLoaded>C:\Windows\Temp\RTCore64.sys</ImageLoaded>
  <Hashes>SHA256=2B41D77CF2CAB373D70DBC43E3DB9B8C...</Hashes>
</Event>

<!-- Log D -->
<Event>
  <EventID>13</EventID>
  <TargetObject>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WinDefHelper</TargetObject>
  <Details>C:\Users\jsmith\AppData\Roaming\wdh.exe</Details>
</Event>
```

**Questions (answer without notes):**

```
1. Log A — What technique is being performed?
   Your answer: ______________________________________
   ATT&CK ID:  ______________________________________
   What would a Sigma rule detect here?
   Your answer: ______________________________________

2. Log B — What technique does this indicate?
   Your answer: ______________________________________
   Is certutil.exe making outbound HTTP normal?
   Your answer: ______________________________________
   Why is this notable even without a URL match?
   Your answer: ______________________________________

3. Log C — What attack category does this belong to?
   Your answer: ______________________________________
   What single defensive control would have prevented this from loading?
   Your answer: ______________________________________

4. Log D — What persistence mechanism is this?
   Your answer: ______________________________________
   ATT&CK ID:  ______________________________________
   How would you distinguish legitimate Run key entries from malicious ones?
   Your answer: ______________________________________
```

**Answers (check after writing yours):**

```
1. LSASS dump via comsvcs.dll MiniDump (T1003.001).
   Sigma: EventID=1, Image ends with rundll32.exe, CommandLine contains
   "comsvcs.dll" AND "MiniDump".

2. LOLBin file download / certutil abuse (T1105).
   Certutil.exe making outbound HTTP is not normal — it has no legitimate
   reason to contact non-Microsoft IPs on port 80.
   Notable because: certutil is a signed Windows binary; many proxies pass it
   through; this is a known LOLBin for payload staging.

3. BYOVD (Bring Your Own Vulnerable Driver). The hash matches RTCore64.sys
   (MSI Afterburner / EDRSandblast).
   Single control: HVCI (Memory Integrity / Hypervisor-Protected Code Integrity)
   with the Microsoft Vulnerable Driver Blocklist enabled.

4. Registry Run key persistence (T1547.001).
   Distinguish: baseline all expected Run key entries per user/machine at
   deployment. Alert on new entries not in the allowlist. Check the binary
   path — legitimate software installs to Program Files, not AppData\Roaming.
```

---

## Part 4 — Written Output (30 min)

Write a one-page executive summary as if this checkpoint were a real 4-hour
mini-engagement. Audience: the CISO of a fictional company.

```
Required elements (do not skip any):
  1. What was tested and when (2 sentences)
  2. What the attacker could have achieved (1 sentence — worst case)
  3. Top 3 findings in order of severity (title + 1-line impact each)
  4. The single most impactful remediation to act on first
  5. Time to full domain compromise if these vulnerabilities are unaddressed
     (estimate with rationale)

Format: plain prose. Maximum 400 words.
Time: 30 minutes. Stop at 30 minutes regardless of whether you are finished.
Write it here or in a separate file referenced from this document.
```

---

## Part 5 — Gap Analysis and Re-Lab Plan

Complete after finishing Parts 2–4.

### Gap Classification

```
For each technique rated 1 or 2 in Part 1, or any challenge step missed in
Part 2, classify the gap:

GAP CLASSIFICATION TABLE:

Technique | Rating | Gap type | Re-lab action
--------- | ------ | -------- | -------------
          |        | A/B/C/D  |

Gap types:
  A — Missing lab execution: never actually ran it; only read it
  B — Command syntax gaps: understand the concept, miss flags/options
  C — Conceptual gap: do not understand why the technique works
  D — Prerequisite gap: missing a dependency concept from an earlier day

Re-lab action per type:
  A — Execute the technique end-to-end in the lab (no notes allowed after pass 1)
  B — Write the commands from memory; verify; repeat until syntax is automatic
  C — Return to the relevant lesson; rebuild the explanation in your own words
  D — Identify the prerequisite lesson; complete it before re-attempting
```

### Re-Lab Schedule

```
For each technique in the gap table:
  Priority 1 (this week):
    → Techniques rated 1 — cannot leave these at 1
  Priority 2 (this month):
    → Techniques rated 2 with type-A gap
  Priority 3 (next milestone):
    → Techniques with type-C or type-D gaps (requires more learning, not just
      repetition)

SCHEDULE:
  This week:    ________________________________________
  This month:   ________________________________________
  By Day 550:   ________________________________________
```

---

## Key Takeaways

1. The gap between reading a technique and owning it is always larger than it
   feels when reading. Time-boxed labs under pressure are the only accurate
   measurement. A technique you can execute in 30 minutes without notes is a
   technique you own.
2. ADCS attacks (Days 511–513) are the highest-value return on investment in
   this block. ESC1 and ESC8 are present in a majority of real AD environments
   and produce DA-level access in under 10 minutes with no password cracking.
   If you cannot execute these from memory, they are the first re-lab priority.
3. LOLAD techniques (Day 518) have the worst recall-to-execution ratio because
   the commands are verbose and tool-free. The comsvcs.dll MiniDump command
   and the diskshadow script are the two most commonly forgotten. Memorise those
   two specifically.
4. Evasion concepts (Day 519) are the least likely to be fully retained from
   a single reading pass. That is expected — evasion requires lab implementation
   to cement. The conceptual understanding (indirect syscalls, BYOVD, sleep
   obfuscation) is the minimum. Implementation is a long-term project.
5. Detection knowledge is part of the grade. For every technique you can execute,
   you should be able to name the Sysmon event ID or Windows Security event that
   catches it. If you can execute but not detect, you have half of what the job
   requires.

---

## Exercises

1. For any technique rated 1 after this checkpoint: execute it end-to-end in
   the lab without opening notes. If you cannot, identify the exact step where
   you fail and return to that day's lesson. Repeat until you rate yourself a 3.
2. Write a two-domain lab "engagement brief" for a hypothetical red team
   engagement: scope, excluded systems, techniques you will use, and expected
   detection events. Use it as the briefing document before your re-lab sessions.
3. Export an ATT&CK Navigator JSON layer covering all techniques from Days 511–
   519. Colour-code by your self-assessed confidence (red = 1, orange = 2,
   yellow = 3, green = 4). Screenshot it. Revisit in 30 days — update ratings
   after additional lab time.
4. Pick one technique you rated 4 in Part 1. Write a one-page detection playbook
   for a blue team analyst: what to look for, which SIEM query to run, what
   evidence to collect for IR, and how to validate the technique was used.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q520.1, Q520.2 …).

---

## Navigation

← Previous: [Day 519 — Advanced Evasion and AV Bypass](DAY-0519-Advanced-Evasion-AV-Bypass.md)
→ Next: [Day 521 — C2 Infrastructure Design](DAY-0521-C2-Infrastructure-Design.md)
