---
title: "Obfuscation and Deobfuscation"
tags: [reverse-engineering, obfuscation, control-flow-flattening, string-encryption,
  VM-protection, deobfuscation]
module: 07-RE-02
day: 454
related_topics:
  - Anti-Debugging Techniques (Day 453)
  - Deobfuscation Lab (Day 455)
  - Packers and Obfuscation (Day 451)
---

# Day 454 — Obfuscation and Deobfuscation

> "A packer hides what the program does. An obfuscator hides how it does it.
> Packers are a lock you pick once. Obfuscation is a maze you have to
> navigate. The way through is to ignore the obfuscation and focus
> on the data and the effects."
>
> — Ghost

---

## Goals

Understand the four major obfuscation categories: string encryption, control
flow flattening, opaque predicates, and VM-based protection.
Apply deobfuscation techniques for string encryption and simple CFF.
Know where obfuscation analysis ends and dynamic observation begins.

**Prerequisites:** Day 453 (anti-debug), Day 434 (assembly patterns), Ghidra.
**Time budget:** 4 hours.

---

## Part 1 — Obfuscation Categories

| Category | What it does | Difficulty to reverse |
|---|---|---|
| String encryption | Hides strings in encrypted arrays | Low — emulate or hook |
| Control flow flattening | Scrambles execution order | Medium — trace at runtime |
| Opaque predicates | Adds dead code with provably fixed conditions | Low — identify and skip |
| VM-based protection | Interprets custom bytecode | High — requires VM RE |
| Code virtualisation | Converts native code to custom ISA | Very High |

---

## Part 2 — String Encryption

Without string encryption:
```
strings binary | grep "http"
→ http://c2.attacker.com/check-in
```

With string encryption:
```
strings binary | grep "http"
→ (nothing useful)
```

### How It Works

```c
// Strings stored as XOR-encrypted bytes
static const char encrypted_url[] = {
    0x1c, 0x1b, 0x1e, 0x1c, 0x1b, 0x5b, 0x5b, 0x4a, ...  // "http://c2.attacker.com"
};

char *decrypt_string(const char *enc, int len, char key) {
    char *out = malloc(len + 1);
    for (int i = 0; i < len; i++) out[i] = enc[i] ^ key;
    out[len] = '\0';
    return out;
}

// At runtime:
char *url = decrypt_string(encrypted_url, sizeof(encrypted_url), 0x7f);
```

### Deobfuscation: Emulate or Hook

**Static (emulate the decryption):**
```python
# If you can read the encrypted bytes and key from Ghidra:
encrypted = [0x1c, 0x1b, 0x1e, ...]
key = 0x7f
print(''.join(chr(b ^ key) for b in encrypted))
```

**Dynamic (hook the decryption function):**
```javascript
// Frida: hook the decrypt_string function
// Find its address in Ghidra, hook in Frida
var base = Process.enumerateModulesSync()[0].base;
var decrypt = base.add(0x1234);  // Ghidra offset

Interceptor.attach(decrypt, {
    onLeave: function(retval) {
        if (!retval.isNull()) {
            console.log('[decrypted] ' + retval.readCString());
        }
    }
});
```

**Dynamic (log all malloc'd strings):**
```javascript
// Hook malloc and log the first call after any potential decryption
// Less precise but catches strings as they are allocated
Interceptor.attach(Module.getExportByName(null, 'malloc'), {
    onLeave: function(retval) {
        if (!retval.isNull()) {
            try {
                var s = retval.readCString(128);
                if (s && s.match(/^[\x20-\x7e]{5,}/)) {
                    console.log('[malloc string] ' + s);
                }
            } catch(e) {}
        }
    }
});
```

---

## Part 3 — Control Flow Flattening (CFF)

CFF scrambles the execution order by dispatching all blocks through a central
switch statement:

```
Original:       A → B → C → D (if X) → E → F
Flattened:      dispatcher → A → dispatcher → B → dispatcher → C → ...
                             ↑          sets "next block" variable
```

```c
// Flattened pseudocode
int state = INITIAL_STATE;
while (1) {
    switch(state) {
        case 0xdeadbeef: { /* block A */ state = 0xcafebabe; break; }
        case 0xcafebabe: { /* block B */ state = ...; break; }
        case 0x1337c0de: { /* block C */ if(x) state=D_state; else state=E_state; break; }
        // ...
    }
}
```

### Identifying CFF in Ghidra

CFF produces a distinctive call graph: a large number of blocks all leading
to a central dispatcher node, and all coming out of it. In Ghidra's Graph View:

```
View → Function Graph → look for the "octopus" pattern:
many blocks → central node → many blocks
```

### Deobfuscating CFF

**Approach 1: Trace at runtime**
```javascript
// Stalker — record every block executed with specific input
Stalker.follow(Process.mainThread().id, {
    events: { block: true },
    onReceive: function(events) {
        Stalker.parse(events).forEach(function(e) {
            if (e[0] === 'block') console.log('block: ' + e[1]);
        });
    }
});
```

**Approach 2: Symbolic execution (academic, using angr)**
```python
import angr
proj = angr.Project('./obfuscated_binary', auto_load_libs=False)
# Symbolic execution explores all paths; angr simplifies CFF automatically
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234)  # address of success
```

**Approach 3: Ignore the structure, follow the data**
In heavily flattened code, instead of deobfuscating the CFG, trace what data
the program reads and writes. The obfuscation structure is irrelevant if you
can observe the actual computation.

---

## Part 4 — Opaque Predicates

An opaque predicate is a condition that always evaluates to the same value
(always true or always false) but is not obviously so to a static analyser.

```c
// Always true: any perfect square modulo 4 is 0 or 1
int x = some_value;
if ((x * x) % 4 == 2) {
    // Dead code — this branch never executes
    // But decompilers may show it as reachable
}
```

### Impact on Decompiler Output

```c
// Decompiler output before recognising opaque predicate:
if (((x * x) & 3) == 2) {
    FUN_00401234(secret_key);  // this is confusing — is this real?
}
// After recognising: this branch is dead code
// FUN_00401234 is a decoy function that never runs
```

### Detection

Look for comparisons with mathematically impossible outcomes:
- Any expression `== constant` where the expression has a known range that
  excludes `constant`.
- Repeated `xor reg, reg` before a comparison (always zero).

**Bypass:** If the decompiler output is confusing due to dead branches, verify
with a debugger that the branch is never taken, then exclude it from analysis.

---

## Part 5 — VM-Based Protection

VM protection (e.g., Themida, VMProtect, Code Virtualizer) converts sections
of native x64 code into a custom bytecode that runs on an interpreter embedded
in the binary.

```
Protected code:
  push rbp
  mov rbp, rsp
  ...

Becomes:
  <custom bytecode>: 0x03 0xA1 0x12 0xFF ...

Interpreter (embedded):
  void execute_vm(uint8_t *bytecode) {
      while (1) {
          switch (*pc++) {
              case 0x03: vm_push(reg[A1]); break;
              case 0xFF: return;
              // ...
          }
      }
  }
```

### How to Handle VM Protection

1. **If the goal is just the output (flag, decrypted data):** Use dynamic analysis
   + Frida to observe inputs and outputs at the boundary of the VM. You do not
   need to understand the VM internals.

2. **If the goal is full understanding:** VM RE is a multi-day task.
   - Identify the interpreter loop (`switch(opcode)` on a byte stream).
   - Map each opcode to its operation.
   - Write a disassembler for the custom bytecode.
   - Re-lift the custom bytecode to C.

3. **Practical shortcut:** The VM always has an entry and exit point. Hook the
   entry (observe inputs) and exit (observe outputs/effects) with Frida to
   understand what the VM-protected function does without reversing the VM.

---

## Part 6 — Deobfuscation Decision Matrix

```
What is the obfuscation type?
  String encryption → emulate decryption statically or hook decrypt function
  Control flow flattening → trace with Stalker; focus on data, not control flow
  Opaque predicates → identify dead branches; ignore them
  VM protection:
    Just need I/O? → hook entry/exit with Frida
    Need full RE? → map opcodes; build custom disassembler (multi-day effort)
    Cannot afford time? → use Triton / angr for automated lifting (expert level)

Can I get what I need dynamically?
  Yes → hook it; do not reverse the obfuscation
  No → static analysis + emulation

Is this malware or a CTF?
  CTF → the obfuscation layer is usually solvable in hours (challenge design)
  Malware → focus on capability (what it does), not the full algorithm
```

---

## Key Takeaways

1. String encryption is the easiest obfuscation to defeat. Hook the decryption
   function with Frida and log every decrypted string — you get the full
   vocabulary in one pass.
2. CFF does not change what the code computes — only the order of blocks.
   Dynamic tracing with Stalker reveals the actual execution sequence.
3. Opaque predicates insert dead code. Verify statically impossible branches
   with a debugger. If they never execute, exclude them from analysis.
4. VM protection is the hardest obfuscation. If you only need the function's
   I/O, hook the boundary. Reserve full VM RE for cases where it is strictly
   necessary.
5. The goal of deobfuscation is not to produce a clean binary. The goal is to
   answer your specific question about the binary's behaviour.

---

## Exercises

1. Add XOR string encryption to `crackme1` (encrypt all strings with key 0x42).
   Recompile stripped. Write a Python script that extracts and decrypts all
   strings from the binary's `.rodata` using the known key.
2. Use angr to solve a simple crackme that uses opaque predicates. Observe how
   angr ignores the dead branches automatically.
3. Find a Themida or VMProtect-protected binary (crackmes.one has some). Open
   in Ghidra. Identify the interpreter loop. Describe the opcode dispatch
   pattern (switch structure or computed jump?).
4. Write a Frida script that hooks every `malloc` + `free` pair and logs the
   contents of every string allocated during execution of `crackme2`.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q454.1, Q454.2 …).

---

## Navigation

← Previous: [Day 453 — Anti-Debugging Techniques](DAY-0453-Anti-Debugging-Techniques.md)
→ Next: [Day 455 — Deobfuscation Lab](DAY-0455-Deobfuscation-Lab.md)
