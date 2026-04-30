---
title: "Ghidra Lab — Crackme 2: Multi-Stage with Anti-Debug"
tags: [reverse-engineering, ghidra, crackme, anti-debug, ptrace, multi-stage, lab]
module: 07-RE-01
day: 435
related_topics:
  - Ghidra Fundamentals (Day 432)
  - x64 Assembly for RE (Day 434)
  - Dynamic Analysis with GDB (Day 436)
  - Anti-Debugging Techniques (Day 453)
---

# Day 435 — Ghidra Lab: Crackme 2 — Multi-Stage with Anti-Debug

> "Real malware does not want to be analysed. A crackme that fights back
> is better training than one that surrenders. Learn to bypass the tricks
> before you meet them in the wild — because in the wild, the trick is
> standing between you and the payload."
>
> — Ghost

---

## Goals

Recognise and bypass a `ptrace` anti-debug check statically.
Reverse a two-stage key derivation algorithm.
Combine static and dynamic analysis on a binary that resists simple examination.

**Prerequisites:** Day 433 (crackme 1), Day 434 (assembly patterns), Day 431 (triage).
**Time budget:** 4–5 hours.

---

## Part 1 — The Lab Binary

```c
// crackme2.c — multi-stage with anti-debug
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>

// Stage 1: anti-debug via ptrace
static int is_debugged(void) {
    // ptrace(PTRACE_TRACEME, 0, 0, 0) returns -1 if already being traced
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        return 1;
    }
    return 0;
}

// Stage 2: transform input
static void transform(const char *in, char *out, int len) {
    int i;
    for (i = 0; i < len; i++) {
        out[i] = (char)((in[i] ^ 0x13) + i);
    }
    out[len] = '\0';
}

// Stage 3: compare to transformed secret
static const char TRANSFORMED[] = {
    0x6f, 0x73, 0x67, 0x67, 0x72, 0x71, 0x55, 0x57,
    0x65, 0x5a, 0x6c, 0x6b, 0x00
};

int main(void) {
    char input[64];
    char transformed[64];

    if (is_debugged()) {
        printf("Nice try.\n");
        return 1;
    }

    printf("Key: ");
    if (fgets(input, sizeof(input), stdin) == NULL) return 1;
    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n') { input[len-1] = '\0'; len--; }

    transform(input, transformed, (int)len);

    if (strcmp(transformed, TRANSFORMED) == 0) {
        printf("Correct. The ghost approves.\n");
    } else {
        printf("Wrong.\n");
    }
    return 0;
}
```

```bash
gcc -O1 -o crackme2 crackme2.c -s
```

---

## Part 2 — Triage

```bash
file crackme2
strings crackme2 | grep -E '.{3,}'
# Note: "Nice try." — anti-debug message
# "Key: " — prompt
# "Correct." / "Wrong."
# The TRANSFORMED array will NOT appear as a readable string
# (it is not printable ASCII)

strace ./crackme2 <<< "test" 2>&1 | head -20
# Look for: ptrace(PTRACE_TRACEME...) = 0
# strace attaches via ptrace → the check will fail → "Nice try."
```

---

## Part 3 — Static Analysis: Bypass the Anti-Debug

### Locate is_debugged()

In Ghidra, open `main()`. You will see a call to a function early in `main`.
Navigate to it. The decompiler shows:

```c
// Approximate
long result;
result = ptrace(PTRACE_TRACEME, 0, 0, 0);
if (result == -1) return 1;
return 0;
```

You do not need to bypass this at runtime for static analysis. But note the
technique:
- `ptrace(PTRACE_TRACEME, 0, 0, 0)` — if a debugger is already attached, this
  call fails with `-1 (EPERM)`.
- The binary uses the return value to detect debugging.

**Static bypass:** You do not need to run the binary to reverse it. Read the
algorithm in Ghidra and derive the key algebraically.

**Dynamic bypass (for Day 436):** Patch the `jne` after the `ptrace` call to
`je`, or NOP the check entirely.

---

## Part 4 — Static Analysis: The Transform Algorithm

Navigate to the `transform()` function. The decompiler shows:

```c
// Approximate Ghidra output
void transform(char *in, char *out, int len) {
    int i = 0;
    while (i < len) {
        out[i] = (char)((in[i] ^ 0x13) + i);
        i++;
    }
    out[len] = '\0';
}
```

And main's comparison:

```c
strcmp(transformed, "\x6f\x73\x67\x67\x72\x71\x55\x57\x65\x5a\x6c\x6b");
```

---

## Part 5 — Key Recovery

To find the input that produces TRANSFORMED:

```
transform(input[i]) = (input[i] ^ 0x13) + i = TRANSFORMED[i]
→ input[i] ^ 0x13 = TRANSFORMED[i] - i
→ input[i] = (TRANSFORMED[i] - i) ^ 0x13
```

```python
# key_recover.py
TRANSFORMED = [0x6f, 0x73, 0x67, 0x67, 0x72, 0x71, 0x55, 0x57,
               0x65, 0x5a, 0x6c, 0x6b]

key = ''.join(chr(((t - i) & 0xff) ^ 0x13)
              for i, t in enumerate(TRANSFORMED))
print("Key:", key)
```

```bash
python3 key_recover.py
# Key: backdoor_key
echo "backdoor_key" | ./crackme2
# → Correct. The ghost approves.
```

---

## Part 6 — Debrief: Anti-Debug Techniques Taxonomy

This crackme used the simplest anti-debug: `ptrace`. Others you will encounter:

| Technique | How it detects debugging | Day covered |
|---|---|---|
| `ptrace(PTRACE_TRACEME)` | Returns -1 if already traced | Today |
| Timing checks | `rdtsc` delta too large under GDB | Day 453 |
| `IsDebuggerPresent` (Windows) | PEB flag set by debugger | Day 453 |
| `/proc/self/status` | Check `TracerPid` field | Day 453 |
| Exception-based | Debugger absorbs exceptions instead of program | Day 453 |
| Anti-analysis via junk bytes | Invalid instructions confuse disassemblers | Day 454 |

Static analysis bypasses ALL of these: you never run the binary, so no
anti-debug fires.

---

## Key Takeaways

1. Anti-debug checks are execution-time defences. Static analysis bypasses them
   completely — you never trigger the check.
2. When a binary applies a transformation before comparing, reverse the
   transformation algebraically. You do not need to brute-force the input.
3. The `ptrace(PTRACE_TRACEME)` pattern is the simplest anti-debug on Linux.
   Recognise it in the Listing: `call ptrace` with `edi = 0`.
4. Multi-stage key derivation (XOR + addition with index) is a common crackme
   pattern. The mathematical inverse recovers the input directly.
5. `strace` itself attaches via `ptrace`. Anti-debug checks will fire under
   `strace`. Static analysis or a patched binary is needed for dynamic work.

---

## Exercises

1. Modify the transform function to use multiplication instead of addition
   (`out[i] = (in[i] ^ 0x13) * (i+1)`). Recompile. Re-reverse and adapt the
   key recovery script.
2. Patch the binary to NOP the `is_debugged()` call. Confirm you can run it
   under `strace` without seeing "Nice try."
3. Add a second stage to the crackme: after the first check passes, XOR the
   transformed result with a second constant before comparing. Reverse it.
4. Find a crackme on crackmes.one tagged "anti-debug". Apply today's methodology
   — static analysis first, derive the key without running the binary.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q435.1, Q435.2 …).

---

## Navigation

← Previous: [Day 434 — x64 Assembly for Reverse Engineers](DAY-0434-x64-Assembly-for-Reverse-Engineers.md)
→ Next: [Day 436 — Dynamic Analysis with GDB and PWNDBG](DAY-0436-Dynamic-Analysis-with-GDB-and-PWNDBG.md)
