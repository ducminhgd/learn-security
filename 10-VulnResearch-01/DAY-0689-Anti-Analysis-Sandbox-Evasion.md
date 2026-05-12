---
title: "Anti-Analysis Techniques — Sandbox Evasion and Anti-Debug"
tags: [anti-analysis, sandbox-evasion, anti-debug, malware-analysis,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 689
prerequisites:
  - Day 613 — Static Analysis Tools
  - Day 615 — Dynamic Analysis and Sandboxing
  - Day 617 — Memory Forensics Intro
related_topics:
  - Day 700 — Module 10 Competency Check
  - Day 707 — B-07 Malware Analysis
---

# Day 689 — Anti-Analysis Techniques: Sandbox Evasion and Anti-Debug

> "Malware authors spend as much time evading your sandbox as you spend
> running it. If your analysis produces 'no suspicious activity' in under
> 60 seconds, you have not analysed the sample — you have been trolled by
> it. Today we study the tricks so you can see through them."
>
> — Ghost

---

## Goals

Understand the most common sandbox evasion and anti-debug techniques used by
real-world malware. Learn how to detect and bypass each technique during manual
analysis. Apply detection to real samples and recognise evasion in Cuckoo or
Any.run reports.

**Prerequisites:** Days 613–617 (Malware Analysis sub-module).
**Estimated study time:** 3 hours.

---

## 1 — Why Malware Evades

Automated sandboxes run samples for a fixed time (30–120 seconds) in a clean
VM. Malware authors know this. If the sample can detect it is running in a
sandbox, it behaves benignly — the automated report shows nothing, and the
sample is marked clean.

The three evasion layers:

```
Layer 1: Environment detection
  "Am I in a real machine or a VM/sandbox?"

Layer 2: Timing checks
  "Is execution happening too fast (automated) or is there a real user?"

Layer 3: Anti-debug
  "Is a debugger attached? If yes, alter behaviour."
```

---

## 2 — Environment Detection Techniques

### 2.1 CPUID / VM Artefacts

```c
/* Check for VMware/VirtualBox hypervisor flag in CPUID */
int cpuid_check(void) {
    unsigned int ecx = 0;
    __asm__ volatile("cpuid" : "=c"(ecx) : "a"(1) : "ebx", "edx");
    return (ecx >> 31) & 1;   /* Hypervisor Present bit */
}

/* Check VM string in CPUID leaf 0x40000000 */
char hypervisor_name[13] = {0};
unsigned int regs[4];
__cpuid(0x40000000, regs[0], regs[1], regs[2], regs[3]);
memcpy(hypervisor_name, &regs[1], 12);
/* Returns "VMwareVMware", "KVMKVMKVM\0\0\0", "VBoxVBoxVBox", etc. */
```

**Detection/Bypass:** Configure your sandbox to use bare-metal or patch CPUID
responses. In manual analysis: when you see `CPUID` with leaf `0x40000000`,
the sample is probing for hypervisor strings.

### 2.2 Registry and File Artefacts

```python
# Common VM artifact checks observed in malware
VM_REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
    r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
    r"HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest",
    r"HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0"
    r"\Target Id 0\Logical Unit Id 0\Identifier",  # disk "VBOX HARDDISK"
]

VM_FILES = [
    r"C:\Windows\System32\drivers\vmmouse.sys",
    r"C:\Windows\System32\drivers\vmhgfs.sys",
    r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
    r"C:\Windows\System32\drivers\VBoxMouse.sys",
]

VM_PROCESSES = ["vmtoolsd.exe", "vmwaretray.exe", "vboxservice.exe",
                "vboxtray.exe", "sandboxie.exe", "wireshark.exe"]
```

**Detection/Bypass:** Rename VM guest additions processes and drivers. Use
Pafish (a test tool) to verify your sandbox passes VM checks.

### 2.3 Hardware Fingerprinting

```c
/* Disk serial number check */
DWORD serial;
GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
/* Sandbox VMs commonly have serial 0xABCD1234 or similar static values */

/* MAC address vendor check */
/* 00:0C:29:xx:xx:xx = VMware NIC
   08:00:27:xx:xx:xx = VirtualBox NIC
   52:54:00:xx:xx:xx = QEMU/KVM NIC */
```

**Detection/Bypass:** Randomise MAC addresses and disk serials in the sandbox
template. In Cuckoo: configure `resultserver_ip` and use `auxiliary.conf` to
spoof hardware identifiers.

---

## 3 — Timing Evasion Techniques

### 3.1 Sleep-and-Wait

```c
/* Sleep 10 minutes before executing — sandbox will time out */
Sleep(600000);     /* 10 minutes */
```

Most sandboxes fast-forward `Sleep()` calls. Modern malware compensates:

### 3.2 CPU-Bound Delay Loop

```c
/* Delay loop that cannot be fast-forwarded by the sandbox */
volatile unsigned long long count = 0;
for (unsigned long long i = 0; i < 500000000ULL; i++) {
    count += i;   /* prevents compiler elimination */
}
/* ~1-2 seconds on a real machine; sandbox may "accelerate" this
   by skipping iterations, but that changes the final count */
```

### 3.3 Time Delta Check

```c
/* Compare RDTSC before and after a Sleep — if sandbox fast-forwarded
   the Sleep, the wall clock advanced but RDTSC may not have */
LARGE_INTEGER freq, start, end;
QueryPerformanceCounter(&start);
Sleep(1000);
QueryPerformanceCounter(&end);
double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
if (elapsed < 0.5) {
    /* Sandbox fast-forwarded our Sleep — exit */
    ExitProcess(0);
}
```

**Detection:** In a Cuckoo report: look for `Sleep` calls with short actual
wall-clock duration, `QueryPerformanceCounter` pairs, or RDTSC instructions in
an unusual context. These are timing checks, not performance code.

### 3.4 User Activity Detection

```c
/* Check if mouse has moved since last check */
POINT pt1, pt2;
GetCursorPos(&pt1);
Sleep(5000);
GetCursorPos(&pt2);
if (pt1.x == pt2.x && pt1.y == pt2.y) {
    /* No mouse movement — probably a sandbox */
    ExitProcess(0);
}

/* Check system uptime — fresh VMs have short uptimes */
DWORD uptime = GetTickCount();
if (uptime < 300000) {   /* less than 5 minutes */
    ExitProcess(0);
}
```

**Detection/Bypass:** Cuckoo's `human.py` auxiliary module simulates mouse
movement and clicks. Enable it. Also: set sandbox template uptime to >1 hour.

---

## 4 — Anti-Debug Techniques

### 4.1 IsDebuggerPresent / CheckRemoteDebuggerPresent

```c
/* Most common — trivially bypassable */
if (IsDebuggerPresent()) {
    ExitProcess(1);
}

/* Reads PEB.BeingDebugged directly — same as IsDebuggerPresent */
BOOL dbg = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
if (dbg) ExitProcess(1);
```

**Bypass in x64dbg:** Set `PEB.BeingDebugged = 0` via the ScyllaHide plugin,
or use the `HideDebugger` plugin. In GDB: `set {char}0x<PEB_addr>+2 = 0`.

### 4.2 NtGlobalFlag and Heap Flags

```c
/* PEB.NtGlobalFlag: 0x70 when debugged (FLG_HEAP_ENABLE_TAIL_CHECK etc.) */
PPEB peb = (PPEB)__readgsqword(0x60);
if (peb->NtGlobalFlag & 0x70) {
    ExitProcess(1);
}

/* Heap flags: 0x40000062 when debugged vs 0x2 normally */
PDWORD heap_flags = (PDWORD)((char *)peb->ProcessHeap + 0x74);
if (*heap_flags & 0x40000000) {
    ExitProcess(1);
}
```

**Bypass:** ScyllaHide patches these in memory before the check runs.

### 4.3 Timing Checks with RDTSC

```c
/* If a debugger is attached, single-stepping between RDTSC calls
   takes much longer than normal execution */
unsigned long long t1, t2;
__asm__ volatile("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(t1) :: "rdx");
/* do nothing */
__asm__ volatile("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(t2) :: "rdx");
if (t2 - t1 > 1000) {   /* suspiciously slow */
    ExitProcess(1);
}
```

**Bypass:** Do not single-step past RDTSC checks. Set a breakpoint after the
check and let execution run to it.

### 4.4 Exception-Based Anti-Debug

```c
/* INT3 self-test: if no debugger, the exception handler fires;
   if a debugger intercepts INT3, the handler never fires */
volatile BOOL handler_fired = FALSE;

__try {
    __asm { int 3 }
} __except(EXCEPTION_EXECUTE_HANDLER) {
    handler_fired = TRUE;
}

if (!handler_fired) {
    ExitProcess(1);   /* debugger consumed the exception */
}
```

**Bypass in x64dbg:** Change exception handling options. Go to
`Options → Preferences → Exceptions` and configure INT3 to be passed to the
application instead of handled by the debugger.

---

## 5 — Analyst Counter-Techniques Reference

| Evasion | Detection signal | Bypass |
|---|---|---|
| CPUID hypervisor check | CPUID with leaf 0x40000000 | Patch CPUID / bare-metal sandbox |
| Registry VM key check | `RegOpenKey` for VM keys | Remove VM guest additions |
| Process name check | `CreateToolhelp32Snapshot` + `Process32Next` | Rename analysis tools |
| `Sleep()` evasion | API call without wall-clock advance | Enable human simulation |
| RDTSC timing check | RDTSC instructions in unusual context | Run at full speed, no stepping |
| `IsDebuggerPresent` | PEB.BeingDebugged read | ScyllaHide / manual patch |
| Uptime < 5min check | `GetTickCount()` < 300,000 | Set VM uptime > 1 hour |
| Mouse activity check | `GetCursorPos()` pairs | Cuckoo `human.py` |

---

## 6 — Lab Exercise

Download a sample tagged `AgentTesla` or `AsyncRAT` from MalwareBazaar.
**Do this inside an isolated VM — never on your host.**

```
ANTI-ANALYSIS IDENTIFICATION LAB

Sample: __________________________ MD5: ____________________

STATIC PHASE (strings + imports):
  IsDebuggerPresent import: Y / N
  CheckRemoteDebuggerPresent import: Y / N
  CPUID instruction found (look in hexdump/disasm): Y / N
  Sleep() import with parameter > 60000: Y / N
  GetTickCount / QueryPerformanceCounter: Y / N
  GetCursorPos / GetSystemInfo: Y / N

DYNAMIC PHASE (procmon + API monitor):
  First evasion trigger observed (API call + result): ______________
  Sample terminated early? Y / N  At what point: ________________

BYPASS APPLIED:
  ScyllaHide enabled: Y / N
  VM guest tools renamed/removed: Y / N
  Mouse simulation enabled: Y / N

AFTER BYPASS — malware behaviour revealed:
  Network connection to: _______________________________________
  Persistence mechanism: _______________________________________
  Credential theft target: _____________________________________
```

---

## Key Takeaways

1. **A clean sandbox report is not proof of safety.** It may be proof that
   the malware successfully evaded. Check the API call log for evasion probes
   (`IsDebuggerPresent`, `CreateToolhelp32Snapshot`, `GetCursorPos`) before
   concluding a sample is benign.
2. **Modern malware uses multiple evasion layers.** Bypassing `IsDebuggerPresent`
   is not enough if the sample also checks for VM processes, mouse movement,
   and system uptime. You must address all layers simultaneously.
3. **ScyllaHide addresses most Windows anti-debug in one plugin.** Install it
   as the first plugin in every new x64dbg setup. It patches PEB flags,
   heap flags, NtGlobalFlag, and intercepts the common anti-debug APIs.
4. **Time-based evasion is the hardest to bypass automatically.** CPU-bound
   delay loops and RDTSC-delta checks specifically resist sandbox fast-forward.
   The only reliable bypass is running the sample on bare metal with automated
   interaction — or using a manual analyst who waits it out.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q689.1, Q689.2 …).

---

## Navigation

← Previous: [Day 688 — Heap Exploitation from the Researcher's Perspective](DAY-0688-Heap-Exploitation-Researcher-Perspective.md)
→ Next: [Day 690 — Advanced YARA Rule Engineering](DAY-0690-Advanced-YARA-Engineering.md)
