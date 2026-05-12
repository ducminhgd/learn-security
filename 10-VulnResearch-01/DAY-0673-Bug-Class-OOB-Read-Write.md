---
title: "Bug Class Deep Dive — Out-of-Bounds Read and Write (CWE-125 / CWE-787)"
tags: [vulnerability-research, oob, out-of-bounds, cwe-125, cwe-787,
  integer-overflow, heap-overflow, cve-2021-22600, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 673
prerequisites:
  - Day 662 — Bug Class: Integer Overflow and Format String
  - Day 393 — Heap Buffer Overflow
related_topics:
  - Day 674 — OOB Lab
  - Day 671 — Bug Class: Type Confusion
---

# Day 673 — Bug Class: Out-of-Bounds Read and Write (CWE-125 / CWE-787)

> "The most common memory corruption vulnerability in C and C++ has been
> the same for forty years: a buffer that is too small for the data written
> into it. The language gives you a pointer and a size. The programmer does
> the arithmetic. The programmer gets the arithmetic wrong. The attacker
> makes the arithmetic wrong in exactly the right way. That is the game."
>
> — Ghost

---

## Goals

Understand the full taxonomy of OOB read and write vulnerabilities —
how they arise, how they differ in exploitation impact, how to find
them systematically, and how to tie them to real CVEs.

**Prerequisites:** Days 662, 393.
**Estimated study time:** 3–4 hours.

---

## CWE-125 — Out-of-Bounds Read

### What it is
Reading memory beyond the end (or before the start) of an allocated buffer.

### Why it matters
OOB reads leak memory contents to the attacker:
- Heap metadata (chunk headers, pointers to other allocations)
- Adjacent heap objects (tokens, keys, credentials)
- Stack data (return addresses, local variables, canary values)
- ASLR-defeating pointers (code and library addresses)

OOB reads alone typically cause information disclosure. Chained with
a write primitive, they become full exploitation chains.

### Minimal Example

```c
// The vulnerable function:
int get_score(int player_id) {
    int scores[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    return scores[player_id];   // player_id not bounds-checked
}
// Attack: get_score(100) reads 360 bytes past the start of scores[]
// → reads return address, canary, or adjacent heap data
```

### Detection Pattern

```bash
# Find array/pointer indexing without preceding bounds check
# Look for: buf[index] or ptr + index where index comes from user data

python3 << 'EOF'
import re, sys
from pathlib import Path

# Patterns for array/pointer index expressions
index_ops = re.compile(r'\[(\w+)\]')
ptr_arith  = re.compile(r'(\w+)\s*\+\s*(\w+)')

# High-risk: index is used without a preceding bounds check in the same scope
risky = re.compile(
    r'(->|\.)(length|size|count|num_|len)\s*[^=]'  # reading a size field
)

for src in Path(".").rglob("*.c"):
    text = src.read_text(errors="replace")
    for i, line in enumerate(text.splitlines(), 1):
        if index_ops.search(line) or ptr_arith.search(line):
            context = "\n".join(text.splitlines()[max(0,i-3):i+2])
            if risky.search(context):
                print(f"{src}:{i}: potential OOB read candidate")
                print(f"  {line.strip()}")
                print()
EOF
```

---

## CWE-787 — Out-of-Bounds Write

### What it is
Writing memory beyond the end (or before the start) of an allocated buffer.

### Why it matters
OOB writes corrupt adjacent memory. Depending on what is adjacent, the
impact ranges from crash (DoS) to arbitrary code execution:

| What is adjacent | Impact |
|---|---|
| Heap chunk header | Heap metadata corruption → arbitrary alloc |
| Function pointer | Redirect execution |
| vtable pointer | Redirect virtual dispatch → code execution |
| Return address (stack OOB) | Classic RIP/RIP overwrite |
| Canary | Likely detected (crash); partial overwrite may survive |
| Another object's data | Privilege escalation within application logic |

### The Five Root Causes of OOB Writes

**1. Missing bounds check**
```c
void copy_name(char *dst, const char *src) {
    strcpy(dst, src);          // dst is 64 bytes; src could be anything
}
```

**2. Integer overflow before allocation**
```c
size_t count  = read_u32(input);   // attacker-controlled
size_t total  = count * 16;        // overflows if count > 0x10000000
char  *buf    = malloc(total);     // tiny allocation
memcpy(buf, data, count * 16);     // writes count * 16 into tiny buf → OOB
```

**3. Off-by-one**
```c
char buf[256];
for (int i = 0; i <= 256; i++) {   // bug: i <= instead of i <
    buf[i] = data[i];              // writes 1 byte past end at i=256
}
```

**4. Signedness confusion**
```c
int length = read_i32(input);      // signed! attacker can set to -1
if (length > MAX_LEN) return;      // -1 passes this check (less than MAX_LEN)
memcpy(buf, data, length);         // length cast to size_t = SIZE_MAX → huge write
```

**5. Format string as OOB write (historical)**
```c
printf(user_input);                // %n writes integer to pointer argument
```

---

## Exploitation: Heap OOB Write → Code Execution

### The Standard Path

```
HEAP OOB WRITE EXPLOITATION PATH

1. Trigger: attacker crafts input that causes a buffer to be written
   N bytes past its end.

2. Adjacent object: what is physically adjacent on the heap?
   → Allocate a known-size object before the vulnerable buffer
   → OR rely on heap layout predictability (allocator internals)

3. Overwrite target: corrupt a field in the adjacent object.
   → Function pointer: write controlled address
   → vtable pointer: write address of fake vtable
   → Size field: expand a buffer to enable a larger read later

4. Trigger the corrupted path: call the function pointer / method.

5. Code execution.

KEY INSIGHT: The attacker does not control what to overwrite —
the heap layout determines that. The attacker's job is to
heap-groom so the right object is adjacent to the vulnerable buffer.
```

### Heap Grooming Pattern

```c
// Force the allocator to place objects adjacently:
// 1. Allocate many objects of the same size to fill tcache/fastbin
// 2. Free specific ones to create gaps
// 3. Allocate the vulnerable buffer into one gap
// 4. Allocate the target object into the adjacent gap

// In practice (pseudocode):
for (int i = 0; i < 20; i++) spray[i] = malloc(64);   // fill tcache
free(spray[5]);                                          // free slot at position 5
vuln_buf = malloc(64);                                   // goes into freed slot 5
target   = malloc(64);                                   // goes into slot 6 (adjacent)
trigger_oob_write(vuln_buf, 64 + 8, payload);            // write into target
```

---

## Real CVE Walkthrough: CVE-2021-22600

### Key Facts

| Field | Value |
|---|---|
| Product | Linux kernel — `packet` socket implementation |
| Class | Double-free leading to OOB write |
| CVSS | 8.8 (High) |
| Impact | Local privilege escalation to root |
| Kernel range | 4.15 – 5.15.x |
| Patch | 5.15.12, 5.16 |

### The Mechanism

```
VULNERABILITY PATH

1. The packet_set_ring() function accepts a size and allocates a ring buffer
   (pg_vec) based on user-supplied parameters.

2. BUG: When the ring buffer size is reduced (tpacket_req.tp_frame_nr is
   decreased), old frames in the ring are freed. But under certain racing
   conditions, the same pg_vec entry could be freed twice.

3. The double-free corrupts tcache:
   → A tcache chunk is added to the free list twice.
   → The next two allocs from that tcache slot return the same address.

4. Both allocs now alias the same memory. The kernel writes to both
   without knowing they overlap.

5. One write corrupts the other's data → OOB-equivalent corruption
   in kernel heap → privilege escalation.

KEY: The root cause is not "bad bounds check" but a race condition
     that creates a double-free. The double-free corrupts the allocator
     metadata, which then produces OOB-equivalent behaviour.
     Same end-state, different root cause.
```

### Lesson: OOB Writes Have Multiple Root Causes

```
NOT ALL OOB WRITES COME FROM MISSING BOUNDS CHECKS.

Root cause → OOB write mechanism:
  Missing size check     → directly writes past buffer end
  Integer overflow       → allocation too small → write past end
  Double-free            → allocator metadata corruption → OOB-equivalent
  Use-after-free         → stale pointer → arbitrary write elsewhere
  Type confusion         → wrong-sized write into wrong-typed object
  Race condition (TOCTOU) → allocation raced with write → inconsistent bounds

When you see "heap-buffer-overflow" in ASan output, ask:
  "Is this a direct bounds miss, or is it the downstream effect of
   another bug class?" The root cause determines the fix.
```

---

## Finding OOB Bugs in Source Audits

### The Five-Question Audit Method

For every function that writes to a buffer using a size from external input,
answer these five questions:

```
OOB AUDIT CHECKLIST — [function name]

1. Where does the destination buffer size come from?
   [ ] Constant (SAFE)
   [ ] Calculated from user input — formula: ___________________
   [ ] Returned from a prior function call — which?: ___________

2. Is arithmetic performed on the user-controlled size before the
   allocation?
   [ ] YES — operations: _______________  Overflow check: Y / N
   [ ] NO

3. Is there a bounds check before the write?
   [ ] YES — condition: ____________________________________________
   [ ] NO
   [ ] Partial — what is not checked? ___________________________

4. Can the write size be independently controlled from the allocation
   size?
   [ ] YES — how: ______________________________________________  ← HIGH RISK
   [ ] NO

5. Are there signedness issues?
   [ ] Length/size read as signed type: ________________________
   [ ] Cast to size_t / unsigned: Y / N / unclear
```

---

## Key Takeaways

1. **OOB write is the most exploitable memory corruption class.** OOB
   read leaks information; OOB write overwrites it. The vast majority of
   heap exploitation chains in modern software start with an OOB write.
   The exploitation complexity depends on what is adjacent — that is what
   heap grooming controls.
2. **Integer overflow before size-controlled operation is the most common
   root cause.** A field is read from user input, arithmetic is performed
   without overflow checking, and the result is used as a size. Review
   every multiplication and addition that feeds into `malloc`, `memcpy`,
   or `realloc` with user-controlled operands.
3. **Signed/unsigned confusion multiplies the attack surface.** A signed
   integer that is read from user input and then passed to a
   `size_t`-parameterised function (`memcpy`, `read`, `write`) is
   effectively a direct OOB write. `-1` passed as `size_t` is `SIZE_MAX`.
   Grep for `(int)` size parameters in allocation/copy calls.
4. **The heap grooming step is what makes OOB writes reliable exploits.**
   Understanding how an allocator manages free lists (tcache in glibc,
   freelist in Windows heap) tells you what will be adjacent to the
   vulnerable buffer. That knowledge is what separates a "crash" finding
   from an "exploitable" finding.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q673.1, Q673.2 …).

---

## Navigation

← Previous: [Day 672 — Type Confusion Lab](DAY-0672-Type-Confusion-Lab.md)
→ Next: [Day 674 — OOB Lab](DAY-0674-OOB-Lab.md)
