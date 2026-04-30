---
title: "Anti-Debugging Techniques"
tags: [reverse-engineering, anti-debug, ptrace, IsDebuggerPresent, timing-attacks,
  NtQueryInformationProcess, bypass]
module: 07-RE-02
day: 453
related_topics:
  - Ghidra Lab Crackme 2 (Day 435)
  - Dynamic Analysis with GDB (Day 436)
  - Obfuscation and Deobfuscation (Day 454)
---

# Day 453 — Anti-Debugging Techniques

> "Every anti-debug technique is a question the binary asks about its
> environment: 'Am I being watched?' Your job is to make every answer
> come back 'No' — whether that is true or not."
>
> — Ghost

---

## Goals

Identify and bypass the most common anti-debug techniques on Linux and Windows.
Understand the mechanism behind each technique so you can defeat it statically
or dynamically.
Build a library of bypass patterns for your RE toolkit.

**Prerequisites:** Day 435 (ptrace anti-debug), Day 436 (GDB), Day 437 (Frida).
**Time budget:** 4 hours.

---

## Part 1 — Why Anti-Debug Exists

Anti-debugging techniques appear in:

| Context | Goal |
|---|---|
| Malware | Prevent dynamic analysis in sandbox or under debugger |
| Commercial protection | Prevent cracking of licensed software |
| CTF challenges | Force you to learn bypass techniques |
| Packers | Prevent dumping at OEP |

Every technique has a bypass. Understanding the mechanism is the bypass.

---

## Part 2 — Linux Anti-Debug Techniques

### Technique 1: ptrace(PTRACE_TRACEME)

Covered in Day 435. The kernel only allows one tracer per process.

```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    // already being traced → debugger detected
    exit(1);
}
```

**Detection in Ghidra:** `call ptrace` with `edi = 0` (PTRACE_TRACEME = 0).

**Bypass options:**

1. **Static patch:** NOP the call, or force `eax = 0` after the call.
2. **Frida:** Hook `ptrace` and return 0.
   ```javascript
   Interceptor.replace(Module.getExportByName(null, 'ptrace'),
       new NativeCallback(function() { return 0; }, 'long', ['int','int','int','int']));
   ```
3. **LD_PRELOAD:** Preload a shared library that overrides `ptrace`.
   ```c
   // ptrace_bypass.c
   long ptrace(int req, int pid, void *addr, void *data) { return 0; }
   ```
   ```bash
   gcc -shared -fPIC -o ptrace_bypass.so ptrace_bypass.c
   LD_PRELOAD=./ptrace_bypass.so ./binary
   ```

---

### Technique 2: /proc/self/status — TracerPid

```c
FILE *f = fopen("/proc/self/status", "r");
// Parse the "TracerPid:" line
// If TracerPid != 0, a debugger is attached
int tracer_pid;
fscanf(f, "TracerPid:\t%d", &tracer_pid);
if (tracer_pid != 0) exit(1);
```

**Detection in Ghidra:** `fopen` with `/proc/self/status` argument + parsing loop.

**Bypass options:**

1. **Static patch:** NOP the check or force the result register to 0.
2. **Frida:** Hook `fopen` for `/proc/self/status`; return a fake file that
   always shows `TracerPid: 0`.
   ```javascript
   Interceptor.attach(Module.getExportByName(null, 'fopen'), {
       onEnter: function(args) {
           var path = args[0].readUtf8String();
           if (path && path.includes('status')) {
               this.intercept = true;
           }
       },
       onLeave: function(retval) {
           if (this.intercept) {
               // Return a fake FILE* or patch the buffer after fread
           }
       }
   });
   ```
3. **Simplest:** Detach the debugger, patch the binary, re-run without a debugger.

---

### Technique 3: Timing Checks (rdtsc)

The CPU instruction `rdtsc` (Read Time Stamp Counter) returns the number of
CPU cycles since boot. A debugger causes significant delays between instructions.

```c
unsigned long long t1, t2;
__asm__ volatile ("rdtsc" : "=A"(t1));
// ... some instructions ...
__asm__ volatile ("rdtsc" : "=A"(t2));
if (t2 - t1 > THRESHOLD) {
    // too slow → debugger detected
    exit(1);
}
```

**Detection in Ghidra:** `rdtsc` instruction, followed by a subtraction and
a comparison.

**Bypass options:**

1. **Static:** NOP the `jg`/`ja` (jump-if-greater) that follows the comparison.
2. **GDB:** Step over the `rdtsc` calls and manually set the delta to a small
   value: `set $rax = 100`.
3. **Frida:** Not directly applicable (no function to hook). Static patching is
   faster.

---

### Technique 4: Signal Handling

Debuggers absorb signals like `SIGTRAP`. A binary can send itself a signal and
check whether its own handler fires.

```c
volatile int handler_called = 0;
signal(SIGTRAP, sighandler);    // install handler
raise(SIGTRAP);                 // send signal to self
if (!handler_called) {
    // handler did not fire → debugger consumed the signal
    exit(1);
}
```

**Bypass:** NOP the `raise(SIGTRAP)` call, or in GDB: `handle SIGTRAP nostop`
to pass the signal to the process instead of the debugger.

---

## Part 3 — Windows Anti-Debug Techniques

### Technique 5: IsDebuggerPresent

```c
if (IsDebuggerPresent()) {
    exit(1);
}
```

**Detection in Ghidra (PE):** Import `IsDebuggerPresent` in the IAT.

**Bypass:**
```javascript
// Frida
Interceptor.replace(Module.getExportByName('kernel32.dll', 'IsDebuggerPresent'),
    new NativeCallback(function() { return 0; }, 'bool', []));
```

Or in x64dbg: Plugin → ScyllaHide (automatically bypasses common Windows
anti-debug).

### Technique 6: NtQueryInformationProcess (ProcessDebugPort)

```c
// More stealthy than IsDebuggerPresent — checks kernel directly
NTSTATUS status = NtQueryInformationProcess(
    GetCurrentProcess(),
    ProcessDebugPort,   // 7
    &debug_port,
    sizeof(DWORD),
    NULL
);
if (debug_port != 0) exit(1);
```

**Detection:** Import `NtQueryInformationProcess` with second argument `7`.

**Bypass:** Hook `NtQueryInformationProcess` in Frida; when `ProcessInfoClass == 7`,
return 0 in the output buffer.

### Technique 7: CheckRemoteDebuggerPresent

```c
BOOL is_debugged = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_debugged);
if (is_debugged) exit(1);
```

**Bypass:** Same as `IsDebuggerPresent` — hook the function.

### Technique 8: Heap Flag Checks

Windows sets specific flags in the Process Heap when a debugger is present.

```c
PVOID heap = GetProcessHeap();
ULONG flags = *(ULONG*)((char*)heap + 0x40);  // offset varies by OS
if (flags & 0x40) exit(1);  // HEAP_TAIL_CHECKING_ENABLED
```

**Bypass:** Patch the heap flag check, or use ScyllaHide which patches the PEB
and heap flags automatically.

---

## Part 4 — Anti-Debug Bypass Reference

| Technique | Platform | Detection signal | Bypass |
|---|---|---|---|
| `ptrace(PTRACE_TRACEME)` | Linux | `call ptrace, edi=0` | LD_PRELOAD / Frida / NOP |
| `/proc/self/status` | Linux | `fopen("/proc/self/status")` | Frida / patch |
| `rdtsc` timing | Any | `rdtsc` opcode | Patch JMP / adjust delta |
| `SIGTRAP` signal | Linux | `raise(SIGTRAP)` | `handle SIGTRAP nostop` in GDB |
| `IsDebuggerPresent` | Windows | IAT import | Frida / ScyllaHide |
| `NtQueryInformationProcess` | Windows | param 7 | Frida hook |
| Heap flag check | Windows | PEB/heap flag comparison | ScyllaHide |
| TLS anti-debug | Any | TLS callback with anti-debug | Check TLS first; patch |

---

## Part 5 — Building a Universal Frida Anti-Debug Bypass Script

```javascript
// antidebug_bypass.js
// Works on Linux x64 binaries

// 1. Bypass ptrace
var ptrace_sym = Module.findExportByName(null, 'ptrace');
if (ptrace_sym) {
    Interceptor.replace(ptrace_sym,
        new NativeCallback(function(req, pid, addr, data) {
            console.log('[bypass] ptrace blocked');
            return 0;
        }, 'long', ['int', 'int', 'pointer', 'pointer'])
    );
}

// 2. Bypass /proc/self/status TracerPid
var fopen_sym = Module.findExportByName(null, 'fopen');
if (fopen_sym) {
    Interceptor.attach(fopen_sym, {
        onEnter: function(args) {
            var path = args[0].readCString();
            if (path && path.indexOf('status') !== -1) {
                console.log('[bypass] fopen /proc/self/status intercepted');
                this.patch_status = true;
            }
        }
    });
}

// 3. Bypass clock_gettime / timing: harder to bypass in Frida without hooks
// For rdtsc: must patch binary statically

console.log('[*] Anti-debug bypass script loaded');
```

```bash
frida -f ./target -l antidebug_bypass.js
```

---

## Key Takeaways

1. Every anti-debug technique is a detectable pattern in Ghidra. `ptrace`,
   `IsDebuggerPresent`, `NtQueryInformationProcess` — all show up as function
   calls with recognisable arguments.
2. Static patching (NOP the check, force the register) is the fastest bypass.
   It permanently disables the check in the binary.
3. Frida hooks are runtime bypasses that do not modify the binary on disk.
   Use them when you cannot or should not modify the binary.
4. `rdtsc`-based timing checks cannot be hooked — they are CPU instructions,
   not function calls. Patch the comparison or the conditional jump.
5. Always check TLS callbacks. Anti-debug code placed in TLS fires before your
   breakpoint at `main`. Break before the entry point, or check TLS first.

---

## Exercises

1. Add a `/proc/self/status` anti-debug check to `crackme2`. Verify it works
   (binary exits under GDB). Then bypass it using the Frida script above.
2. Add a `rdtsc` timing check to a simple binary. Verify it exits when run under
   GDB (due to debugger overhead). Bypass it by patching the conditional jump.
3. Write a comprehensive Frida script that bypasses all three Linux techniques
   (ptrace, /proc/status, signal-based) in one script.
4. Research `ScyllaHide` — what Windows API hooks does it patch, and how does
   each hook bypass a specific anti-debug technique?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q453.1, Q453.2 …).

---

## Navigation

← Previous: [Day 452 — Unpacking Lab](DAY-0452-Unpacking-Lab.md)
→ Next: [Day 454 — Obfuscation and Deobfuscation](DAY-0454-Obfuscation-and-Deobfuscation.md)
