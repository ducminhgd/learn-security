---
title: "Advanced Detection Engineering — Detection-as-Code, Sigma at Scale, Coverage Matrix"
tags: [detection-engineering, sigma, detection-as-code, siem, coverage-matrix, ci-cd,
  module-12-postghost]
module: 12-PostGhostLevel
day: 737
prerequisites:
  - Day 509 — Atomic Red Team Lab
  - Day 735 — Threat Intel Fundamentals
related_topics:
  - Day 738 — Purple Team Leadership
---

# Day 737 — Advanced Detection Engineering

> "Writing one Sigma rule is easy. Maintaining 300 Sigma rules, ensuring they
> work across three SIEM platforms, have low false-positive rates, and actually
> cover the TTPs your adversaries use — that is engineering. Detection is a
> product. Build it like one."
>
> — Ghost

---

## Goals

Understand Detection-as-Code (DaC) as a discipline. Build a detection coverage
matrix mapped to MITRE ATT&CK. Write production-quality Sigma rules with
validation pipelines. Understand how to test detections against simulated
attacker behaviour.

**Prerequisites:** Days 509, 735.
**Estimated study time:** 3.5 hours.

---

## 1 — Detection-as-Code (DaC)

```
DETECTION-AS-CODE PRINCIPLES

1. Detections are source code
   → Stored in Git (version controlled)
   → Code-reviewed before deployment
   → Tagged with ATT&CK technique, author, date, confidence

2. Detections are tested automatically
   → On every PR: syntax validation, unit test against known-true events
   → Nightly: replay against production log samples to catch false positives
   → Before deploy: impact test (how many events does this fire on?)

3. Detections are deployed automatically
   → CI/CD pipeline: PR merge → Sigma compile → SIEM deploy
   → No manual copy-paste of rules into a web UI
   → Sigma as the source-of-truth; compiled to Splunk/Elastic/Chronicle as needed

4. Detections are retired when obsolete
   → Low-firing rules with no confirmed true positives after 90 days
      are reviewed for retirement or tuning
   → Dead rules waste analyst attention budget

TOOLCHAIN:
  Sigma       Rule format (language-agnostic)
  sigma-cli   Official converter (sigma → Splunk SPL, Elastic EQL, etc.)
  pySigma     Python library for Sigma rule manipulation
  pytest      Unit tests for detection logic
  GitHub Actions or GitLab CI  Pipeline runner
```

---

## 2 — Production-Quality Sigma Rules

A Sigma rule from Day 509 worked in a lab. A production rule must survive
real-world data volumes and diverse environments.

### 2.1 Rule Fields That Matter in Production

```yaml
# PRODUCTION-QUALITY SIGMA RULE — annotated

title: Suspicious PowerShell Download Cradle via Net.WebClient
id: a7f3b891-2e3c-4d5e-8f9a-0b1c2d3e4f5a  # stable UUID
status: stable              # test → experimental → stable → deprecated
description: >
  Detects PowerShell commands using Net.WebClient.DownloadString or
  DownloadFile methods, a common living-off-the-land download cradle
  used by threat actors for stage-2 payload retrieval.
author: "Ghost Training Programme"
date: 2025-05-12
modified: 2025-05-12
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://lolbas-project.github.io/
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027

logsource:
  product: windows
  category: process_creation    # Sysmon Event ID 1 / Windows Security 4688

detection:
  selection:
    CommandLine|contains|all:
      - 'powershell'
      - 'Net.WebClient'
    CommandLine|contains:
      - '.DownloadString('
      - '.DownloadFile('
      - '.DownloadData('
  filter_legitimate:
    CommandLine|contains:
      - 'WindowsDefender'       # Defender uses similar patterns internally
      - 'WSUS'                  # Windows Update
  condition: selection and not filter_legitimate

falsepositives:
  - Legitimate software installers using PowerShell download
  - SCCM / Intune software deployment
  - Update mechanisms

level: high        # info, low, medium, high, critical
```

### 2.2 Detection Writing Checklist

```
BEFORE MERGING A SIGMA RULE

[ ] Rule fires on at least one true-positive log sample
[ ] Rule does NOT fire on 10 benign log samples from production
[ ] id: field is a stable UUID (generate once, never change)
[ ] status: experimental initially; promote to stable after 30 days in prod
[ ] falsepositives: section lists all known FP sources
[ ] filter: section suppresses known FP patterns
[ ] level: calibrated to actual attacker value of the TTP
[ ] references: links to ATT&CK and at least one documented example
[ ] tags: all relevant ATT&CK tags included
```

---

## 3 — Detection Coverage Matrix

A coverage matrix answers: "Of all the TTPs our likely adversaries use,
what percentage do we currently detect?"

```
COVERAGE MATRIX CONSTRUCTION

Step 1: Define adversary profile
  From your TI work (Day 735/736), list the threat actors most likely
  to target your organisation.
  For each actor, list their documented TTPs from ATT&CK.

Step 2: List your current detections
  Export all Sigma rules from your repo.
  For each rule, note its ATT&CK tag(s).

Step 3: Build the matrix

  ATT&CK Technique    | Adversary A | Adversary B | Detected? | Rule Name
  --------------------|-------------|-------------|-----------|----------
  T1059.001 PS Exec   |      ✓      |      ✓      |     ✓     | ps-download-cradle
  T1547.001 Run Keys  |      ✓      |             |     ✓     | reg-run-key-add
  T1055.001 DLL Inj   |      ✓      |      ✓      |     ✗     | MISSING
  T1003.001 LSASS     |             |      ✓      |     ✗     | MISSING
  T1078 Valid Accts   |      ✓      |      ✓      |    ~      | login-anomaly (low conf)
  ...

Step 4: Prioritise coverage gaps
  Missing + High adversary priority = write rule now
  Missing + Low adversary priority = backlog
  Low confidence + High priority = improve existing rule

Step 5: Express as a metric
  Coverage = (Detected TTPs) / (Total adversary TTPs) × 100
  Target: >60% for top-priority adversary
  Stretch: >80% with high-confidence rules
```

---

## 4 — Sigma Validation Pipeline

```bash
# Install sigma-cli
pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch

# Validate syntax for all rules in repo
sigma check rules/*.yml

# Convert to Splunk SPL
sigma convert -t splunk -p ecs_windows rules/ps-download-cradle.yml

# Convert to Elastic EQL
sigma convert -t elasticsearch -p ecs_windows rules/ps-download-cradle.yml

# Convert to Chronicle (YARA-L 2.0)
sigma convert -t chronicle rules/ps-download-cradle.yml
```

```yaml
# .github/workflows/sigma-validate.yml
# CI/CD pipeline: validate all Sigma rules on every PR

name: Sigma Validation
on: [pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install sigma-cli
        run: pip install sigma-cli
      - name: Validate all rules
        run: sigma check rules/**/*.yml
      - name: Convert to Splunk (smoke test)
        run: sigma convert -t splunk -p ecs_windows rules/**/*.yml > /dev/null
```

---

## 5 — Testing Detections Against Real Attacker Behaviour

```
ATOMIC RED TEAM TESTING PIPELINE

1. Install Invoke-AtomicRedTeam on a test endpoint
   (Windows VM, isolated from production)

2. For each Sigma rule you write, identify the matching Atomic test:
   T1059.001 → Atomic: T1059.001-1 (PowerShell via DownloadString)

3. Execute atomic:
   Invoke-AtomicTest T1059.001-1 -TestNumbers 1

4. Check SIEM for the alert:
   Does your Sigma rule fire? → True positive confirmed
   Does it fire with false detail? → Tune the detection
   Does it not fire? → Check log source, event ID, field mapping

5. Run cleanup:
   Invoke-AtomicTest T1059.001-1 -TestNumbers 1 -Cleanup

6. Document in rule metadata:
   # validation: passed against Atomic T1059.001-1 on 2025-05-12

CALDERA ALTERNATIVE:
  MITRE Caldera emulates multi-step operations automatically.
  Better for testing detection of sequences (initial access → lateral movement).
  Use for validating Sigma rule chains, not individual atomic rules.
```

---

## Key Takeaways

1. **Detection is an engineering discipline, not an art project.** Version
   control, tests, CI/CD, and performance metrics apply to detection code
   exactly as they apply to software.
2. **A coverage matrix makes invisible gaps visible.** Without it, you believe
   you are well-covered until an attacker uses an undetected TTP and no alert
   fires.
3. **False positives are not acceptable as a long-term state.** Every rule
   that fires on legitimate activity trains analysts to ignore alerts. That
   is how real attacks go unnoticed.
4. **Atomic Red Team and Caldera are the only reliable way to verify that a
   rule fires on real attacker behaviour.** Synthetic log injection does not
   capture what actually ends up in a SIEM.

---

## Exercises

1. Pick five of your own ATT&CK-mapped Sigma rules from Days 509/530. Run each
   through `sigma check` and fix any validation warnings.
2. Build a coverage matrix for the Ghost Level SABLE lab environment. How many
   of the techniques used in the engagement do your rules detect?
3. Write one new rule for a TTP that your coverage matrix shows as missing.
   Validate it against an Atomic Red Team test.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q737.1, Q737.2 …).

---

## Navigation

← Previous: [Day 736 — Threat Intel Lab: MISP Setup](DAY-0736-Threat-Intel-Lab-MISP.md)
→ Next: [Day 738 — Purple Team Leadership](DAY-0738-Purple-Team-Leadership.md)
