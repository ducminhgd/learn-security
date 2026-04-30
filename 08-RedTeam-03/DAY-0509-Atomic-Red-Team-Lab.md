---
title: "Atomic Red Team Lab — Running Tests, Detecting with Sigma, Closing Gaps"
tags: [purple-team, Atomic-Red-Team, Invoke-AtomicRedTeam, Sigma, detection-engineering,
  SIEM, ATT&CK, gap-analysis]
module: 08-RedTeam-03
day: 509
related_topics:
  - Purple Team Concepts (Day 508)
  - Red Team Reporting (Day 510)
  - Security Monitoring Architecture (Days 251–290)
  - Threat Hunting (Days 291–310)
---

# Day 509 — Atomic Red Team Lab

> "Atomic Red Team is a library of smallest-possible implementations of
> ATT&CK techniques. Each test does exactly one thing. That is the point.
> You test one technique, you look for one detection, you write one rule.
> This is how you build coverage: technique by technique, gap by gap,
> until the heatmap stops being red."
>
> — Ghost

---

## Goals

Set up the Atomic Red Team framework and run tests for specific ATT&CK
techniques.
Correlate test execution with SIEM log events.
Identify detection gaps and write Sigma rules to close them.
Build a repeatable purple team test workflow.

**Prerequisites:** Day 508 (purple team concepts), SIEM/logging setup
(Days 251–290), Sigma fundamentals (Days 291–330).
**Time budget:** 5–6 hours.

---

## Part 1 — Atomic Red Team Setup

Atomic Red Team provides techniques as small, portable test scripts. The
`Invoke-AtomicRedTeam` PowerShell module automates execution and cleanup.

### Installation

```powershell
# On the lab Windows victim VM (with Sysmon and a SIEM agent running):

# Install Invoke-AtomicRedTeam PowerShell module:
IEX (New-Object Net.WebClient).DownloadString(
    'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'
)
Install-AtomicRedTeam -getAtomics

# Default installation path:
# C:\AtomicRedTeam\atomics\  → one folder per ATT&CK technique (T1003.001, etc.)

# Verify:
Invoke-AtomicTest T1003.001 -ShowDetails
# → Lists all test implementations for T1003.001 (LSASS memory)
```

### Lab Architecture

```
Lab components:
  Windows Victim VM:
    → Sysmon (SwiftOnSecurity config)
    → Winlogbeat (ships events to Elastic/SIEM)
    → Invoke-AtomicRedTeam installed
    → PowerShell logging enabled

  SIEM (Elastic or Splunk on a separate VM):
    → Receives Sysmon events from Winlogbeat
    → Sigma rules loaded as SIEM queries

  Attacker / Analyst VM:
    → Kali Linux
    → Sigma converter (sigmac or pySigma)
    → Watches SIEM dashboard during test execution
```

---

## Part 2 — Running Atomic Tests

### Basic Test Execution Workflow

```powershell
# List all tests for a technique:
Invoke-AtomicTest T1003.001 -ShowDetails

# Run test #1 (default test for the technique):
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Run all tests:
Invoke-AtomicTest T1003.001

# Run with a specific parameter override:
Invoke-AtomicTest T1003.001 -TestNumbers 2 -InputArgs @{"output_file"="C:\Windows\Temp\lsass_test.dmp"}

# Cleanup after test (remove artefacts):
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup

# Check prerequisites before running:
Invoke-AtomicTest T1047 -CheckPrereqs
# → tells you if WMI access, required tools, etc. are available
```

### Running a Technique Suite

```powershell
# Run all techniques from a specific ATT&CK tactic:
# Credential Access techniques:
$ca_techniques = @("T1003.001", "T1003.002", "T1003.003", "T1555.003",
                   "T1558.003", "T1110.001", "T1040")

foreach ($t in $ca_techniques) {
    Write-Host "Executing $t at $(Get-Date -Format 'HH:mm:ss')"
    Invoke-AtomicTest $t -TimeoutSeconds 60 -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 30   # Allow log ingestion time
    Invoke-AtomicTest $t -Cleanup -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 10
}
```

---

## Part 3 — Techniques to Test and Their Expected Signals

Run these five techniques in sequence. For each: observe the SIEM, record
what you see, and compare against the expected signal.

### T1003.001 — LSASS Memory Dump

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 2
# Test 2: comsvcs.dll MiniDump approach

# Expected Sysmon signals:
# Event 10 (ProcessAccess):
#   SourceImage: rundll32.exe
#   TargetImage: C:\Windows\System32\lsass.exe
#   GrantedAccess: 0x1fffff (PROCESS_ALL_ACCESS)

# SIEM query (Elastic KQL):
# event.code:10 AND winlog.event_data.TargetImage:*lsass.exe AND
# winlog.event_data.GrantedAccess:0x1fffff

# Sigma rule to write:
```

```yaml
title: LSASS Memory Access via rundll32 comsvcs.dll
status: test
logsource:
  product: windows
  category: process_access
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    SourceImage|endswith: '\rundll32.exe'
    GrantedAccess|contains: '1fffff'
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1003.001
```

### T1053.005 — Scheduled Task Creation

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
# Creates: schtasks /create /tn "T1053_005_1" /tr "cmd.exe /c echo ..."

# Expected signals:
# Sysmon Event 1: schtasks.exe process creation
# Windows Security Event 4698: A scheduled task was created
#   TaskName: T1053_005_1
#   SubjectUserName: (the test runner account)
# Sysmon Event 11: task XML written to C:\Windows\System32\Tasks\

# SIEM query (Splunk SPL):
# index=sysmon EventCode=1 Image="*schtasks.exe" CommandLine="*/create*"
# | table _time, ComputerName, User, CommandLine

# Sigma rule:
```

```yaml
title: Scheduled Task Creation via schtasks.exe
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  condition: selection
falsepositives:
  - Legitimate software installation or update processes
level: medium
tags:
  - attack.persistence
  - attack.t1053.005
```

### T1047 — WMI Remote Execution

```powershell
Invoke-AtomicTest T1047 -TestNumbers 1
# Executes: wmic process call create "notepad.exe"

# Expected signals:
# Sysmon Event 1: WmiPrvSE.exe spawning notepad.exe
# Windows Security Event 4688: process creation by WMI service
# Sysmon Event 3: optional — if command connects to remote host

# Tuned Sigma rule for WMI parent process:
```

```yaml
title: WmiPrvSE Spawning Suspicious Child Process
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|not_endswith:
      - '\WmiPrvSE.exe'
      - '\msiexec.exe'
      - '\svchost.exe'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1047
```

### T1546.003 — WMI Event Subscription

```powershell
Invoke-AtomicTest T1546.003 -TestNumbers 1
# Creates a WMI event subscription that runs a command

# Expected signals:
# Sysmon Events 19, 20, 21:
#   19: WmiEventFilter activity
#   20: WmiEventConsumer activity
#   21: WmiEventConsumerToFilter activity
# These three events together indicate a new WMI subscription

# Sigma rule for WMI persistence:
```

```yaml
title: WMI Event Subscription Created (Persistence)
status: test
logsource:
  product: windows
  category: wmi_event
detection:
  selection_filter:
    EventID: 19
  selection_consumer:
    EventID: 20
  condition: selection_filter or selection_consumer
level: high
tags:
  - attack.persistence
  - attack.t1546.003
```

### T1558.003 — Kerberoasting

```powershell
Invoke-AtomicTest T1558.003 -TestNumbers 1
# Requests TGS for all SPNs using PowerShell ADSI

# Expected signals:
# Windows Security Event 4769: Service Ticket Request
#   TicketEncryptionType: 0x17 (RC4-HMAC) — the downgrade signal
#   ServiceName: (any non-machine account SPN)

# Volume detection (multiple 4769 in a short window):
```

```yaml
title: Kerberoasting — High Volume TGS Requests with RC4
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|not_endswith: '$'
  timeframe: 5m
  condition: selection | count() > 5
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

---

## Part 4 — Building a Detection Gap Report

After running the five technique tests, document the results:

```
Detection Gap Report — CorpLab Purple Team Session

Date:       2026-05-01
Techniques: T1003.001, T1053.005, T1047, T1546.003, T1558.003
Environment: Windows 10 22H2, Sysmon (SwiftOnSecurity), Winlogbeat → Elastic

Results:

T1003.001 (LSASS Dump):
  Log generated: YES — Sysmon Event 10 present in Elastic
  Alert fired:   NO — no SIEM rule for lsass.exe target + rundll32 source
  Gap:           Rule needed (see Sigma rule above)
  Risk:          CRITICAL — LSASS dump enables all subsequent attacks

T1053.005 (Scheduled Task):
  Log generated: YES — Event 4698 and Sysmon Event 1 both present
  Alert fired:   PARTIAL — Event 4698 logged but no alert; Sysmon Event 1 not in SIEM
  Gap:           Sysmon Event 1 for schtasks.exe not ingested
  Risk:          HIGH — persistence mechanism invisible

T1047 (WMI Exec):
  Log generated: YES — Sysmon Event 1 shows WmiPrvSE.exe parent
  Alert fired:   NO — WmiPrvSE.exe parent rule not deployed
  Gap:           Rule needed
  Risk:          HIGH — primary lateral movement technique undetected

T1546.003 (WMI Subscription):
  Log generated: YES — Sysmon Events 19/20/21 present
  Alert fired:   YES — existing rule fires
  Status:        PASS
  Note:          Rule tuning needed — fires on legitimate Windows Events too

T1558.003 (Kerberoasting):
  Log generated: YES — Event 4769 on DC with EncryptionType 0x17
  Alert fired:   NO — no volume threshold rule deployed
  Gap:           Threshold-based rule needed
  Risk:          HIGH — enables credential access to service accounts
```

---

## Part 5 — Closing the Loop: Deploy Sigma Rules to SIEM

```bash
# Convert Sigma rules to SIEM query format:

# For Elastic (pySigma):
pip install pySigma pySigma-backend-elasticsearch
sigma convert -t elasticsearch -p ecs_windows lsass_dump.yml
# → Outputs an Elastic KQL or Lucene query

# For Splunk:
sigma convert -t splunk -p windows-sysmon lsass_dump.yml
# → Outputs Splunk SPL query

# For SIEM import:
# 1. Create a new detection rule in the SIEM
# 2. Paste the converted query
# 3. Set: severity=high, enabled=true, notify=SOC_team
# 4. Re-run the Atomic test
# 5. Verify the alert fires within 5 minutes
# 6. Check for false positives (wait 24 hours, review alert volume)
```

---

## Key Takeaways

1. Atomic Red Team tests are designed to be the smallest possible
   implementation of a technique. They generate the detection signal without
   the operational noise of a full attack chain. That isolation is what makes
   them useful for building rules.
2. Log generated ≠ alert fired. Many environments log Sysmon events without
   having rules that alert on them. The gap is in the rule layer, not the
   collection layer. Identify and close that gap.
3. Cleanup is mandatory. Leave Atomic tests running artefacts on a production-
   equivalent system and you introduce the exact risk you are trying to detect.
   Always run `Invoke-AtomicTest <technique> -Cleanup` after every test.
4. Sigma rules are the portable output. They can be converted to any SIEM
   platform. Write Sigma, not SIEM-specific queries. This makes your detection
   work reusable across environments.
5. The pass criterion is not "alert fired once." It is "alert fires consistently,
   with a false positive rate the SOC can manage." A rule that fires on every
   scheduled task is not useful. Tune it down to a meaningful signal.

---

## Exercises

1. Run all five techniques from Part 3 on the lab Windows VM. For each:
   record whether the log was generated, whether an alert fired, and the
   exact log fields that were present.
2. Write a Sigma rule for each technique that did not have an alert. Convert
   the rules to Elastic KQL using pySigma. Deploy them to the lab SIEM.
3. Re-run all five techniques after deploying the rules. Verify which alerts
   now fire. Note the time between technique execution and alert generation.
4. For T1546.003 (WMI subscription): the existing rule fires on legitimate
   events. Write a tuned version that excludes known-good event sources
   (Windows system accounts, specific management tools). Test that the tuned
   rule still catches Atomic test #1.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q509.1, Q509.2 …).

---

## Navigation

← Previous: [Day 508 — Purple Team Concepts](DAY-0508-Purple-Team-Concepts.md)
→ Next: [Day 510 — Red Team Reporting](DAY-0510-Red-Team-Reporting.md)
