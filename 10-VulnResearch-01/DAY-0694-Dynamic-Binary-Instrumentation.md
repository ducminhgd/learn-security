---
title: "Dynamic Binary Instrumentation and Taint Tracking"
tags: [dbi, dynamic-analysis, taint-tracking, pin, dynamorio, frida,
  vulnerability-research, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 694
prerequisites:
  - Day 613 — Static Analysis Tools
  - Day 615 — Dynamic Analysis and Sandboxing
  - Day 687 — CodeQL Taint Analysis
related_topics:
  - Day 700 — Module 10 Competency Check
  - Day 703 — Advanced iOS: Jailbreak
---

# Day 694 — Dynamic Binary Instrumentation and Taint Tracking

> "Source code is a luxury. Most real targets — firmware, proprietary parsers,
> commercial software — have no source. DBI puts instrumentation inside the
> binary at runtime without modifying the file. It is how researchers watch
> exactly where untrusted bytes flow when there is no compiler to ask."
>
> — Ghost

---

## Goals

Understand Dynamic Binary Instrumentation (DBI) frameworks: what they do,
how they work, and when to use each. Implement a Frida script that tracks
taint flow from file input to memory operations in a target binary.
Write a Pin tool (conceptual) for taint propagation. Apply DBI to identify
crash-triggering input paths in a target without source code.

**Prerequisites:** Days 613, 615, 687.
**Estimated study time:** 3 hours.

---

## 1 — What Is Dynamic Binary Instrumentation?

DBI frameworks insert analysis code into a running process at the instruction
level — without modifying the binary on disk.

```
DBI EXECUTION MODEL

Target binary → DBI framework intercepts basic blocks
              → Instruments each block (add analysis code)
              → Executes instrumented code
              → Target cannot detect instrumentation (in most cases)

Result: complete visibility into every instruction executed, every
        memory read/write, every function call — at the cost of
        significant runtime overhead (2×–100× slower).
```

### DBI Framework Comparison

| Framework | Language | Platform | Best for |
|---|---|---|---|
| **Frida** | JavaScript/Python | All (incl. Android/iOS) | Dynamic analysis, hooking APIs |
| **Intel Pin** | C++ (PinTool) | x86/x64 (Linux/Windows) | Low-level taint tracking |
| **DynamoRIO** | C (Drltool) | x86/x64/ARM (Linux/Windows) | High-performance instrumentation |
| **Valgrind** | C (Callgrind etc.) | Linux/macOS | Memory error detection |

---

## 2 — Frida for Taint Tracking

Frida is the fastest DBI tool to deploy. It hooks at the API level, not the
instruction level — lower fidelity but much easier to script.

### 2.1 Frida Architecture

```python
# Frida uses a host-side controller (Python) + target-side script (JavaScript)
# The JS script is injected into the target process

import frida
import sys

TARGET = "target_parser"

def on_message(message, data):
    if message["type"] == "send":
        print(f"[FRIDA] {message['payload']}")
    elif message["type"] == "error":
        print(f"[ERROR] {message['stack']}")

session = frida.attach(TARGET)   # or spawn for a new process
```

### 2.2 Tracking File Read → Memory Copy

```javascript
// frida_taint.js — track fread/read → memcpy flow

// Track what fread() reads
const fread_ptr = Module.getExportByName(null, "fread");
Interceptor.attach(fread_ptr, {
    onEnter: function(args) {
        this.buf  = args[0];
        this.size = args[1].toInt32();
        this.nmemb = args[2].toInt32();
    },
    onLeave: function(ret) {
        const bytes_read = ret.toInt32() * this.size;
        if (bytes_read > 0) {
            send({
                event: "fread",
                buf:   this.buf.toString(),
                size:  bytes_read,
                // Read first 16 bytes of what was read
                preview: Memory.readByteArray(this.buf, Math.min(16, bytes_read))
            });
            // Mark this buffer address as tainted
            this.context.tainted_buf = this.buf;
        }
    }
});

// Track memcpy() calls — are any source pointers near a tainted address?
const memcpy_ptr = Module.getExportByName(null, "memcpy");
Interceptor.attach(memcpy_ptr, {
    onEnter: function(args) {
        const dst = args[0];
        const src = args[1];
        const n   = args[2].toInt32();
        send({
            event: "memcpy",
            dst:   dst.toString(),
            src:   src.toString(),
            n:     n
        });
    }
});

// Track malloc — log allocation sizes
const malloc_ptr = Module.getExportByName(null, "malloc");
Interceptor.attach(malloc_ptr, {
    onEnter: function(args) {
        this.size = args[0].toInt32();
    },
    onLeave: function(ret) {
        send({
            event: "malloc",
            size:  this.size,
            ptr:   ret.toString()
        });
    }
});
```

```python
# Run the Frida script against a target
import frida, json, sys

events = []

def on_message(msg, data):
    if msg["type"] == "send":
        events.append(msg["payload"])
        ev = msg["payload"]
        if ev["event"] == "malloc" and ev["size"] < 0:
            print(f"[!] SUSPICIOUS malloc({ev['size']}) — integer overflow?")
        elif ev["event"] == "fread":
            print(f"[*] fread → buf@{ev['buf']} size={ev['size']}")
        elif ev["event"] == "memcpy":
            print(f"    memcpy(dst={ev['dst']}, src={ev['src']}, n={ev['n']})")

session = frida.spawn(["./target_parser", "test.input"],
                      on_message=on_message)
frida.resume(session)
sys.stdin.read()  # wait for user interrupt
```

### 2.3 Hooking C++ Virtual Functions

When targets use polymorphism and virtual dispatch, hook at the vtable level:

```javascript
// Find a C++ object's vtable and hook a virtual function
const obj_ptr = /* obtained from previous hook */ ptr("0x12345678");

// Read vtable pointer from the object
const vtable  = obj_ptr.readPointer();

// Hook the 3rd virtual function (index 2, 0-indexed)
const vfunc_2 = vtable.add(2 * Process.pointerSize).readPointer();
Interceptor.attach(vfunc_2, {
    onEnter: function(args) {
        send({event: "vfunc_call", obj: args[0].toString()});
    }
});
```

---

## 3 — Intel Pin Taint Tracking (Conceptual)

Pin operates at the instruction level — every memory read and write is visible.
Implementing full taint tracking with Pin is a research project in itself;
here we cover the architecture so you can read and adapt existing tools.

### 3.1 Pin Tool Structure

```cpp
// Minimal Pin tool — logs all memory reads and writes
#include "pin.H"
#include <iostream>

// Called for every memory read instruction
VOID RecordMemRead(VOID *ip, VOID *addr, UINT32 size) {
    std::cout << "READ  " << ip << " @ " << addr << " size=" << size << "\n";
}

// Called for every memory write instruction
VOID RecordMemWrite(VOID *ip, VOID *addr, UINT32 size) {
    std::cout << "WRITE " << ip << " @ " << addr << " size=" << size << "\n";
}

// Instrumentation: called once per basic block
VOID Trace(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsMemoryRead(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                               IARG_INST_PTR, IARG_MEMORYREAD_EA,
                               IARG_MEMORYREAD_SIZE, IARG_END);
            }
            if (INS_IsMemoryWrite(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                               IARG_INST_PTR, IARG_MEMORYWRITE_EA,
                               IARG_MEMORYWRITE_SIZE, IARG_END);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_StartProgram();
    return 0;
}
```

### 3.2 Existing DBI Taint Tools

Rather than building a full taint engine from scratch, use existing tools:

| Tool | Based on | What it does |
|---|---|---|
| **Taint Grind** | Valgrind | Byte-level taint tracking for Linux |
| **libdft** | Intel Pin | Dynamic taint flow for x86/x64 |
| **TritonDBA** | Pin/DynamoRIO | Symbolic + taint analysis |
| **DynamoRIO-DRCOV** | DynamoRIO | Coverage-only (fast) |

```bash
# DynamoRIO coverage-guided analysis (no taint, just coverage)
drrun -t drcov -- ./target_parser test.input

# Convert to LCOV format for visualisation
python3 drcov2lcov.py -input target.log -output coverage.info
genhtml coverage.info --output-directory coverage_report/
```

---

## 4 — When to Use DBI vs Other Approaches

```
USE DBI WHEN:
  - No source code available (binary-only target)
  - You need to confirm exactly which code paths process untrusted data
  - You want to trace what happens to a specific byte from file input
    through to memory operations
  - You are reversing an obfuscated binary and need runtime data flow

USE SOURCE-LEVEL TOOLS INSTEAD WHEN:
  - Source is available → use CodeQL or Semgrep + ASan
  - You need high throughput → DBI overhead (2×–100×) is too slow for fuzzing
  - You need instruction-level taint → implement a Pin tool or use Triton

USE FRIDA SPECIFICALLY WHEN:
  - Hooking at the API level is sufficient (function calls, not individual instructions)
  - Target is on Android or iOS (Frida is the dominant tool)
  - Fast iteration: JavaScript changes without recompilation
  - You need to modify return values or arguments to test behaviour changes
```

---

## 5 — Lab Exercise

```
DBI TAINT TRACKING LAB

Target: any C binary that reads from file and processes the data
Approach: Frida API-level hooks

Setup:
  [ ] Frida installed: pip3 install frida-tools
  [ ] Target process identified (pid or name)
  [ ] Frida script written for: fread, malloc, memcpy, free

RESULTS:

fread calls observed: _______
  Largest single fread: _______ bytes

malloc calls observed: _______
  Suspicious sizes (> 0x1000000 or == 0): _______
  Sizes near fread buffer sizes: _______

memcpy calls where src near fread buffer: _______
  Largest memcpy: _______ bytes

Potential overflow candidate:
  fread size: _______
  Subsequent malloc size: _______
  Relationship: _______ (e.g., malloc is 4× smaller than fread)
  Manual confirmation: Y / N
```

---

## Key Takeaways

1. **DBI is a last resort — powerful but slow.** Source-level tools (ASan,
   CodeQL) are 10–100× faster and easier to iterate. Use DBI when source is
   unavailable or when you need runtime confirmation of a data flow hypothesis
   that static analysis cannot prove.
2. **Frida at the API level is sufficient for most applied research.** You do
   not need instruction-level taint to confirm "fread result flows to malloc
   argument." Hooking three C runtime functions tells you the same story in
   a tenth of the development time.
3. **DBI coverage is the input to smarter fuzzing.** Use `drcov` to identify
   which code paths your current corpus covers. Feed low-coverage functions
   to a hand-crafted seed corpus. This bridges DBI analysis with fuzzing.
4. **Frida is the dominant tool for mobile targets.** On Android and iOS, where
   there is no source and the OS limits process debugging, Frida's dynamic
   JavaScript injection is the standard approach. Everything you learn here
   transfers directly to mobile vulnerability research.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q694.1, Q694.2 …).

---

## Navigation

← Previous: [Day 693 — Reading NVD Entries as an Attacker](DAY-0693-NVD-CVE-Reading-as-Attacker.md)
→ Next: [Day 695 — Container Security Vulnerabilities](DAY-0695-Container-Security-Vulnerabilities.md)
