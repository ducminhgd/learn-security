---
title: "Ghost Level Preparation — Tools, Methodology, and Mindset"
tags: [ghost-level, preparation, methodology, red-team, engagement, module-11-ghost-level]
module: 11-GhostLevel
day: 706
prerequisites:
  - Day 705 — Year 2 Review and Synthesis
  - All Year 2 modules (Days 366–700)
related_topics:
  - Day 707 — Ghost Level Lab Briefing
  - Day 730 — Ghost Level Competency Gate
---

# Day 706 — Ghost Level Preparation: Tools, Methodology, and Mindset

> "Tomorrow the clock starts. Before it does, I want you to understand what
> the next 48 hours actually are. This is not another module with a known
> answer at the end of the lesson file. The lab does not tell you where the
> vulnerability is. There is no progress indicator. There is no 'you found
> 2 of 5 flags.' There is a network, there are services, and there is a
> report due at the end. Everything else is up to you.
>
> If that sounds like a real engagement, that is because it is one."
>
> — Ghost

---

## Goals

Set up and verify the complete toolchain for the Ghost Level engagement.
Understand the engagement methodology and how to adapt it when things go
wrong. Internalise the documentation discipline that separates a professional
finding report from a collection of screenshots. Build the mental frame for
48 hours of sustained offensive work.

**Prerequisites:** Day 705 (Year 2 Review). All gates passed.
**Estimated study time:** 3 hours (setup and preparation — not hacking).

---

## 1 — The Ghost Level Engagement: What It Is

```
GHOST LEVEL ENGAGEMENT — STRUCTURE

Format:     48-hour timed solo engagement on an unknown lab environment
Start:      Day 707 (lab briefing + clock starts)
End:        Day 728 (48 hours complete)
Report due: Day 728 (end of engagement window)
Debrief:    Day 729
Gate:       Day 730

Target:     Multi-service lab environment ("Project SABLE")
            → Details revealed on Day 707
            → Treat it as a real client engagement

Deliverable: A professional penetration test report containing:
  1. Executive summary
  2. Technical findings (advisory-format for each vulnerability)
  3. Attack narrative (kill chain timeline)
  4. MITRE ATT&CK matrix mapping
  5. Evidence (screenshots, PoC inputs, log excerpts)
  6. Remediation recommendations

Assessment:
  Findings quality:     40%
  Report quality:       30%
  Methodology evidence: 20%
  OPSEC discipline:     10%
```

---

## 2 — Toolchain Verification

**Block 2 hours for this.** Fix every failure now. Tool failures on Day 707
cost you time you cannot afford.

```bash
# ─── NETWORK RECON ───────────────────────────────────────────────────
nmap --version           # Nmap 7.9x
masscan --version        # masscan 1.3.x
rustscan --version       # 3.x (optional, for speed)

# ─── WEB EXPLOITATION ────────────────────────────────────────────────
burpsuite &              # opens GUI — verify intercept works
curl --version           # 7.x
python3 -c "import requests; print('requests ok')"
python3 -c "import pyjwt; print('pyjwt ok')"
feroxbuster --version    # directory brute-forcer
ffuf -V                  # web fuzzer

# ─── BINARY EXPLOITATION ─────────────────────────────────────────────
python3 -c "import pwn; print(pwn.version)"  # pwntools
gdb --version && echo "source ~/.gdbinit" | gdb -q  # pwndbg loaded?
ROPgadget --version
patchelf --version

# ─── REVERSE ENGINEERING ─────────────────────────────────────────────
ghidra &                 # opens GUI
objdump --version
file /bin/ls             # basic sanity
strings /bin/ls | head -3

# ─── ACTIVE DIRECTORY ────────────────────────────────────────────────
python3 -c "import impacket; print(impacket.__version__)"
crackmapexec --version
bloodhound --version 2>/dev/null || echo "BloodHound not installed — check"
python3 -c "import ldap3; print('ldap3 ok')"

# ─── MALWARE ANALYSIS / FIRMWARE ─────────────────────────────────────
binwalk --version
vol.py --version         # Volatility3
yara --version
frida --version

# ─── C2 / POST-EXPLOITATION ──────────────────────────────────────────
msfconsole --version 2>/dev/null || echo "Metasploit — verify separately"
# Or: check your preferred C2 (Sliver, Havoc, Covenant) is running

# ─── PIVOTING ────────────────────────────────────────────────────────
proxychains4 -version
python3 -c "import paramiko; print('paramiko ok')"
socat -V

# ─── REPORTING ───────────────────────────────────────────────────────
# Ensure your note-taking tool is ready:
# Obsidian / CherryTree / Notion / plain Markdown — your choice
# Critical: you MUST be able to export to PDF or Markdown
```

```
TOOLCHAIN STATUS

Network recon:       OK / FAIL (fix: ___________________________)
Web exploitation:    OK / FAIL
Binary exploitation: OK / FAIL
Reverse engineering: OK / FAIL (Ghidra tested: Y / N)
Active Directory:    OK / FAIL
Malware/Firmware:    OK / FAIL
C2/Post-exploit:     OK / FAIL
Pivoting:            OK / FAIL

All tools working:   Y / N
Issues resolved:     Y / N
```

---

## 3 — Engagement Methodology Framework

The Ghost Level uses a phased methodology adapted from real APT simulation
engagements. Do not skip phases. Do not spend more than the allocated time
in any one phase before moving to the next.

```
GHOST LEVEL METHODOLOGY — TIME ALLOCATION

Phase 1: Initial Recon (Hours 0–3)           6% of time
  → Network sweep, port scan, service ID
  → Technology fingerprinting
  → Attack surface map (all services listed)
  → STOP at 3 hours even if incomplete — move on

Phase 2: Attack Surface Exploitation (Hours 3–18)  31%
  → Work through each service systematically
  → Web app: auth, API, injection, crypto
  → Network services: protocol analysis, binary service
  → Priority: widest coverage before deepest dive

Phase 3: Deep Exploitation (Hours 18–30)     25%
  → Binary reverse engineering and exploitation
  → AD / domain attacks
  → Firmware / IoT if present
  → Prioritise based on Phase 2 findings

Phase 4: Post-Exploitation (Hours 30–40)     21%
  → Lateral movement
  → Credential harvesting
  → Persistence
  → Data exfiltration (evidence capture)

Phase 5: Reporting (Hours 40–48)             17%
  → 8 hours is NOT enough if you have not taken notes all along
  → Timeline reconstruction from notes
  → Advisory drafts for each finding
  → ATT&CK mapping
  → NEVER sacrifice reporting time for one more exploit
```

### 3.1 The Note-Taking Discipline

This is the most commonly violated rule in student engagements:

```
NOTE-TAKING RULES

1. Every command you run: copy it into your notes before running it
   Template: ## [TIME] COMMAND\n```\n$ <command>\n```\n<output>\n

2. Every finding: immediately write the finding card
   Template: ## FINDING — [description]\n
   File: ___  Port/Service: ___  CWE: ___  Severity: ___\n
   Evidence: [paste crash/response]\n

3. Every screenshot: name it with timestamp and service
   naming: HHMMSS-service-action.png
   Example: 143022-web-jwt-bypass.png

4. Every credential found: log immediately to creds.txt
   Format: service:username:password:hash

RULE: If you cannot reconstruct the attack timeline from your notes
at Hour 47, the engagement failed — regardless of what you found.
The report is the deliverable. The finding without documentation
is worthless.
```

---

## 4 — OPSEC in Lab Engagements

Even in a lab, practise OPSEC discipline. It builds habits:

```
LAB OPSEC CHECKLIST

[ ] Use a dedicated attacker VM (not your host machine)
[ ] Route all attack traffic through the lab network, not the internet
[ ] Timestamp all commands in your notes
[ ] Do not leave crashed services — if you crash a target, note it
    and restart if possible (the blue team may detect the gap)
[ ] Clean up obvious traces before the engagement ends
    (shell histories, dropped payloads in /tmp)
[ ] Never log into services with your real identity
    — use the personas provided in the briefing

OPSEC is not just about not getting caught.
It is about maintaining access for the full 48 hours.
A noisy scanner at Hour 1 that crashes a service means
you might not reach it again until it is restarted.
```

---

## 5 — Mental Preparation

```
GHOST LEVEL — MENTAL PREPARATION

HOUR 0–12: Adrenaline phase
  You will be energetic. Do not rush. Slow is smooth. Smooth is fast.
  Methodical recon now prevents rabbit holes later.

HOUR 12–24: Grind phase
  Things will not work. Exploits will fail. Services will behave
  unexpectedly. This is normal. This is real work.
  What to do: step back, re-read your notes, form a new hypothesis.
  What not to do: try the same exploit 50 more times hoping it changes.

HOUR 24–36: Fatigue phase
  Sleep if you need it. A 4-hour sleep at hour 24 that resets your
  cognition is worth more than 4 more hours of degraded problem-solving.
  Your best ideas about that stubborn service will come after sleep.

HOUR 36–48: Push phase
  You know what you have found. You know what is left.
  Prioritise: report the confirmed findings; chase one more if time allows.
  At Hour 44: STOP hacking. Start writing.
  At Hour 47: The report is due. Incomplete is better than late.

WHAT SEPARATES PASS FROM FAIL:
  - Methodology: did you work systematically?
  - Documentation: is the report professional quality?
  - Findings: did you find the intended vulnerabilities?
  You can pass with 2 of 3. You cannot pass with 0 of 3.
```

---

## Key Takeaways

1. **The report is the product, not the exploit.** A working exploit that is
   not documented, reproduced, and written up in advisory format has no value
   in a professional engagement. Train yourself to document first, hack second.
2. **Phased methodology prevents tunnel vision.** Every student who has failed
   a Ghost Level did so by spending 30 hours on one service and missing three
   others. Move through phases. Come back for depth after breadth.
3. **Tool failures on Day 1 are unacceptable — so verify today.** There is
   no time on Day 707 to fix a broken `impacket` install or a Ghidra project
   that won't open. Every minute of toolchain fix is a minute stolen from the
   engagement.
4. **48 hours is enough.** It is enough to find 3–5 vulnerabilities, build PoCs
   for 2–3, and write a professional report — if you are disciplined about
   time. It is not enough to find everything. Accept that and prioritise.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q706.1, Q706.2 …).

---

## Navigation

← Previous: [Day 705 — Year 2 Review and Synthesis](DAY-0705-Year2-Review-Synthesis.md)
→ Next: [Day 707 — Ghost Level Lab Briefing](DAY-0707-Ghost-Level-Lab-Briefing.md)
