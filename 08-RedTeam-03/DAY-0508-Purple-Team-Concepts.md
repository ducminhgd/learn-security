---
title: "Purple Team Concepts — Red + Blue Collaboration, ATT&CK Emulation Plans"
tags: [purple-team, red-team, blue-team, ATT&CK, emulation-plan, detection-engineering,
  Atomic-Red-Team, ATT&CK-Navigator, T1 collaboration]
module: 08-RedTeam-03
day: 508
related_topics:
  - Full Kill-Chain Lab Day 2 (Day 507)
  - Atomic Red Team Lab (Day 509)
  - Red Team Reporting (Day 510)
  - Security Monitoring Architecture (Days 251–290)
---

# Day 508 — Purple Team Concepts

> "Red team and blue team are not adversaries. They are the same team running
> a drill. The goal is not for red to 'win' — the goal is for the organisation
> to be harder to breach next year than it is today. Purple team is the
> mechanism. The red team shows what is possible. The blue team shows what is
> visible. Together they answer the question: what do we need to build?"
>
> — Ghost

---

## Goals

Understand the purple team model and how it differs from a traditional red team
engagement.
Learn how to build an ATT&CK emulation plan.
Understand the purple team workflow: test → detect → tune → repeat.
Use ATT&CK Navigator to plan and track detection coverage.

**Prerequisites:** Day 507 (kill-chain lab), Days 251–290 (defensive monitoring),
ATT&CK framework familiarity.
**Time budget:** 4 hours.

---

## Part 1 — Red vs Blue vs Purple

```
Traditional red team engagement:
  Red team operates independently.
  Blue team tries to detect and respond.
  At the end: a report says what red team did.
  Blue team sees the findings for the first time post-engagement.
  Result: gaps documented, but remediation starts weeks later.

Traditional blue team:
  Blue team tunes rules and monitors.
  Does not know what to test against.
  Builds rules based on threat intel and vendor signatures.
  Gaps remain unknown until a real attacker finds them.

Purple team:
  Red and blue work together in a structured exercise.
  Red executes one technique at a time.
  Blue observes in real time: did the alert fire? What did it look like?
  Both teams tune detection rules immediately.
  Result: known detection coverage for every tested technique.
  Gaps are fixed during the exercise, not weeks later.
```

### When to Use Each Model

```
Red team (adversarial, independent):
  → Testing the organisation's ability to detect and respond under realistic
    conditions — no warning, no blue team knowledge
  → Validating security investments against realistic threat actors
  → Required for compliance frameworks (TIBER-EU, CBEST, CREST)

Purple team (collaborative):
  → Building detection coverage systematically
  → Training the blue team on specific techniques
  → Closing known gaps from a previous red team engagement
  → Prioritised when detection engineering maturity is low
```

---

## Part 2 — ATT&CK Emulation Plans

An emulation plan is a structured playbook for executing a specific threat
actor's TTPs in a controlled environment. MITRE publishes them; red teams
adapt them.

### MITRE's Emulation Plan Structure

```
1. Target threat actor: APT29, FIN7, Lazarus Group, etc.
   → Why this actor? Does the client face this threat? (sector, geography, assets)

2. Intelligence gathering:
   → ATT&CK actor page: https://attack.mitre.org/groups/GXXXX/
   → CTI reports (Mandiant, CrowdStrike, Microsoft MSTIC)
   → Mapped TTPs: which techniques does this actor use?

3. Technique selection:
   → Not all techniques in the actor's profile are relevant
   → Prioritise: techniques the actor uses most frequently
   → Exclude: techniques outside the engagement scope (hardware, OT)

4. Emulation steps:
   → For each technique: specific tool/method the actor uses
   → Actor-specific variations: Cobalt Strike vs custom loader, etc.
   → Sequence: does the actor chain techniques in a specific order?

5. Detection objectives:
   → For each technique: what should the SIEM alert on?
   → Expected log source: Windows Event, Sysmon, network, endpoint
   → Test pass criteria: alert fired within [X] minutes of technique execution

6. Cleanup:
   → After each technique: remove artefacts before proceeding
   → Snapshot-based environment: revert after each test run
```

### Example: APT29 (Cozy Bear) Emulation Plan Excerpt

```
Technique: T1566.001 — Phishing: Spearphishing Attachment
Actor method: Macro-enabled Word document with a custom loader
Emulation tool: Atomic Red Team T1566.001 or GoPhish with custom payload
Detection objective: Email gateway quarantines the attachment
  OR Sysmon Event 1 fires: WinWord.exe spawning PowerShell/cmd.exe
Test pass: Alert fires within 5 minutes of victim opening the document

Technique: T1055.012 — Process Hollowing
Actor method: Hollows a legitimate svchost.exe with a custom implant
Emulation tool: Custom process hollowing binary (Day 496)
Detection objective: Sysmon Event 25 (ProcessTampering) or
  memory scanner detects image mismatch
Test pass: Alert fires within 5 minutes of hollowing

Technique: T1003.001 — LSASS Memory
Actor method: comsvcs.dll MiniDump or custom LSASS reader
Detection objective: Sysmon Event 10 (ProcessAccess to lsass.exe)
  triggers an alert in the SIEM
Test pass: High-fidelity alert (not just a log event) fires within 5 minutes
```

---

## Part 3 — Purple Team Workflow

The standard purple team session follows a repeating loop per technique:

```
For each technique in the emulation plan:

1. BRIEF (5 min)
   Red explains what they are about to do.
   Blue confirms logging is active and baseline established.
   Both agree on success criteria (what counts as detection).

2. EXECUTE (5–15 min)
   Red executes the technique.
   Blue watches the SIEM/EDR in real time.

3. OBSERVE (10 min)
   Did the alert fire?
   If yes: review the alert quality (false positive rate, signal-to-noise).
   If no: identify which log source is missing.
         Is the log collected? Is the log parsed? Is there a rule?

4. TUNE (15–30 min)
   Write or modify the detection rule together.
   Re-execute the technique.
   Verify the rule fires.
   Check for false positives (run the technique with a legitimate variant).

5. DOCUMENT
   Record: technique, tool, detection rule, log source, pass/fail.
   Update ATT&CK Navigator with the tested technique (green = detect, red = miss).

6. RESET
   Revert the lab to a clean state.
   Proceed to the next technique.
```

### Purple Team Session Output

```
After a full-day purple team session on 10 techniques:
  → A list of tested techniques with detection pass/fail
  → A set of new or tuned Sigma rules (ready to deploy to production SIEM)
  → An updated ATT&CK Navigator heatmap showing coverage
  → A gap list: techniques with no detection capability, prioritised by risk
  → A re-test schedule: when to re-run this exercise
```

---

## Part 4 — ATT&CK Navigator

ATT&CK Navigator is a web-based tool for visualising technique coverage on the
ATT&CK matrix.

### Using ATT&CK Navigator

```
URL: https://mitre-attack.github.io/attack-navigator/
(or self-hosted for sensitive engagement data)

Workflow:
  1. Create a new layer: "CorpLab Purple Team — 2026-04"
  2. For each technique tested:
     → Click the technique cell
     → Assign a score or colour:
       Green (1): Detection confirmed — alert fires reliably
       Yellow (0.5): Partial detection — log exists but no alert
       Red (0): No detection — technique completely missed
  3. Export the layer as JSON → include in the engagement report as an appendix
  4. Share with the client: their current detection coverage visualised

Key views:
  Heatmap: shows coverage density by tactic
  Filter by group: show only APT29 techniques → current emulation coverage
  Layer comparison: before vs after the purple team exercise
```

### Building a Coverage Heatmap from the Kill-Chain Lab

```python
# Example: convert the Day 2 engagement log ATT&CK mapping to a Navigator layer

import json

techniques_tested = [
    {"techniqueID": "T1566.001", "color": "#ff6666", "comment": "No gateway alert"},
    {"techniqueID": "T1204.002", "color": "#ff6666", "comment": "LNK execution not detected"},
    {"techniqueID": "T1053.005", "color": "#ff6666", "comment": "Scheduled task not alerted"},
    {"techniqueID": "T1003.001", "color": "#ffff66", "comment": "Sysmon Event 10 logged, no alert"},
    {"techniqueID": "T1047",     "color": "#ff6666", "comment": "WMI lateral movement missed"},
    {"techniqueID": "T1550.002", "color": "#ffff66", "comment": "oPtH logged, no alert"},
    {"techniqueID": "T1003.006", "color": "#ff6666", "comment": "DCSync not alerted"},
    {"techniqueID": "T1558.001", "color": "#ff6666", "comment": "Golden Ticket not detected"},
]

layer = {
    "name": "CorpLab Kill-Chain Coverage 2026-04",
    "versions": {"attack": "14", "navigator": "4.9"},
    "techniques": techniques_tested
}

with open("coverage_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
# Import this JSON into ATT&CK Navigator → instant coverage heatmap
```

---

## Part 5 — Communication Protocols

Purple team requires structured communication between red and blue:

```
During the session:
  Dedicated voice channel (Slack, Teams, or physical room)
  Red announces: "Executing T1003.001 — LSASS dump via comsvcs.dll — NOW"
  Blue confirms receipt: "Watching for Sysmon Event 10 on WORKSTATION01"
  Blue reports: "Event 10 fired at 10:23:45 UTC — no SIEM alert triggered"
  Red: "Confirmed. Proceeding to analyse gap."

Between sessions:
  Written debrief after each session (what worked, what did not)
  Detection engineering backlog: prioritised list of gaps to close
  Re-test schedule: date when each gap will be re-validated after tuning

Escalation:
  If blue identifies a technique that is already being exploited (a real
  incident during the exercise): pause the purple team immediately
  Engage the IR process
  Resume the exercise only after the incident is resolved
```

---

## Key Takeaways

1. Purple team is not a "friendlier" red team — it is a different product.
   Red team tests the organisation's ability to detect and respond under
   realistic adversarial conditions. Purple team systematically builds that
   ability. Both are needed.
2. An ATT&CK emulation plan is not "run all the techniques" — it is a
   prioritised, threat-intelligence-driven subset. Map the emulation to the
   client's actual threat profile (sector, adversary groups, existing incidents).
3. The purple team loop (brief → execute → observe → tune → document) is the
   mechanism. Speed matters: one technique per loop, reset cleanly, move to
   the next. A session that does 10 techniques thoroughly beats one that covers
   30 superficially.
4. ATT&CK Navigator makes detection gaps visible to executives. A heatmap that
   is 80% red communicates risk more effectively than a 50-page gap report.
5. Detection is only complete when the rule fires AND the alert is actionable.
   A log event that no one acts on is not a detection. The pass criterion for
   purple team is: "an analyst would see this and know what to do."

---

## Exercises

1. Choose a MITRE ATT&CK group (e.g. APT29, FIN7) and download their profile
   from attack.mitre.org. List their top 10 most frequently used techniques.
   Build a simple emulation plan covering 5 of those techniques.
2. Open ATT&CK Navigator and create a layer for the Day 2 kill-chain lab.
   Colour each technique based on whether it was detected (yellow = log only,
   red = no detection). Export the layer as JSON.
3. Write a detection tuning brief for T1003.001 (LSASS dump via comsvcs.dll).
   Include: log source, specific field values, false positive rate estimate,
   and the tuned Sigma rule.
4. Design a one-day purple team session agenda for the CorpLab environment
   covering the most critical techniques from the Day 2 engagement. Include
   time allocations, test sequence, and pass/fail criteria.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q508.1, Q508.2 …).

---

## Navigation

← Previous: [Day 507 — Full Kill-Chain Lab Day 2](../08-RedTeam-02/DAY-0507-Full-Kill-Chain-Lab-Day-2.md)
→ Next: [Day 509 — Atomic Red Team Lab](DAY-0509-Atomic-Red-Team-Lab.md)
