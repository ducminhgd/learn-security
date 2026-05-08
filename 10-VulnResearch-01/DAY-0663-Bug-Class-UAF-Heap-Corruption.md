---
title: "Bug Class Deep Dive — Use-After-Free and Heap Corruption"
tags: [vulnerability-research, bug-class, use-after-free, heap-corruption,
  double-free, CWE-416, CWE-122, heap-spraying, tcache, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 663
prerequisites:
  - Day 662 — Integer Overflow and Format String
  - Day 608 — Binary Exploitation Fundamentals
related_topics:
  - Vulnerability Research Sprint Day 1 (Day 664)
---

# Day 663 — Bug Class Deep Dive: Use-After-Free and Heap Corruption

> "UAF bugs are the crown jewel of modern exploitation. They are subtle,
> they are silent, and in a garbage-collected language they simply do not
> exist — which is why every major browser engine is now written in Rust.
> But every C and C++ codebase you will ever audit is full of them. Learn
> to see the lifecycle of a heap object: allocated, used, freed, used again.
> That last 'used again' is worth a lot of money."
>
> — Ghost

---

## Goals

Understand the heap allocator internals that make UAF exploitable. Learn to
identify UAF, double-free, and heap overflow patterns in source code and patch
diffs. Write a minimal UAF PoC. Understand the exploitation primitive each bug
class provides. Learn what a defender can detect at the heap and OS level.

**Prerequisites:** Days 662, 608.
**Estimated study time:** 4 hours.

---

## Heap Allocator Fundamentals (glibc ptmalloc)

```c
/*
 * GLIBC HEAP STRUCTURE — what you need to know for exploitation
 *
 * Every allocation is preceded by a malloc_chunk header:
 *   [prev_size: 8B] [size: 8B | flags] [user data: size bytes] [next chunk: ...]
 *
 * Flags in the size field:
 *   bit 0: PREV_INUSE — previous chunk is in use (not freed)
 *   bit 1: IS_MMAP — chunk was allocated with mmap
 *   bit 2: NON_MAIN_ARENA — chunk is in a thread arena
 *
 * BINS (where freed chunks live):
 *   tcache     — per-thread cache, 64 bins, up to 7 chunks each (glibc >= 2.26)
 *   fastbins   — small chunks (< 0x80 bytes), single-linked list, LIFO
 *   unsortedbin — newly freed large chunks, doubly-linked list
 *   smallbins  — sorted bins for chunks < 512 bytes
 *   largebins  — chunks >= 512 bytes
 *
 * KEY INSIGHT FOR EXPLOITATION:
 *   malloc() returns the SAME MEMORY that was previously freed (reuse).
 *   If code still holds a pointer to freed memory (UAF), a subsequent malloc()
 *   may return that same memory filled with attacker data.
 *   → The old pointer now points to attacker-controlled content.
 */
```

---

## Bug Class 1 — Use-After-Free (CWE-416)

```c
/*
 * USE-AFTER-FREE — minimal example and exploitation model
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    int  id;
    void (*destroy)(void *);   /* Function pointer — exploitable if replaced */
    char name[64];
} User;

typedef struct {
    char data[72];             /* Same size as User — will be returned by malloc */
    void (*exploit_target)(void *);
} AttackerObject;

/* VULNERABLE CODE PATH */
void process_request(int free_user, int use_user) {
    User *u = malloc(sizeof(User));  /* Allocate: User (80 bytes) */
    u->id = 1;
    u->destroy = free;
    strcpy(u->name, "alice");

    if (free_user) {
        u->destroy(u);  /* STEP 1: Free the user object */
        free(u);        /* Object is now freed */
    }

    /* ... many lines of code later ... */

    if (use_user) {
        /* STEP 2: Use the freed pointer — UAF */
        printf("User: %s\n", u->name);   /* reads freed memory */
        u->destroy(u);                    /* calls through freed function pointer */
        /* If attacker controls the freed memory (via a new allocation), they
         * can replace u->destroy with a pointer to their shellcode */
    }
}

/* EXPLOITATION MODEL:
 * 1. Trigger free(u)                                    ← attacker controls timing
 * 2. Allocate AttackerObject of same size               ← same memory returned
 * 3. Write attacker_func to AttackerObject->exploit_target at the same offset as u->destroy
 * 4. Trigger u->destroy(u)                              ← calls attacker_func
 *
 * REAL CVEs:
 *   CVE-2022-42856 (WebKit): UAF in JIT compiler → RCE
 *   CVE-2021-30858 (WebKit): UAF in JavaScript engine → browser RCE
 *   CVE-2019-2025  (Android Binder): UAF → kernel LPE
 */
```

```python
#!/usr/bin/env python3
"""
UAF detection patterns — what to look for in code review.
"""
from __future__ import annotations

UAF_PATTERNS = {
    "classic_uaf": {
        "description": "Free occurs, pointer NOT nulled, pointer used again",
        "vulnerable_code": [
            "free(ptr);",
            "/* ... many lines ... */",
            "ptr->field = value;   /* UAF: ptr not set to NULL after free */",
        ],
        "grep": r"free\(\w+\).*\n.*\w+->",
        "fix": "Set ptr = NULL immediately after free(); check for NULL before use",
        "cvss_impact": "Typically High to Critical — depends on what is read/written",
    },
    "error_path_uaf": {
        "description": "Object freed in error path, but caller continues to use it",
        "vulnerable_code": [
            "int do_something(Object *obj) {",
            "    if (error) { free(obj); return -1; }   /* freed here */",
            "    return process(obj);                     /* BUG: caller still has ptr */",
            "}",
        ],
        "grep": r"if.*error.*free\(",
        "fix": "Return error code; let caller own the free, or document ownership transfer",
        "cvss_impact": "Varies — may require specific error condition to trigger",
    },
    "callback_uaf": {
        "description": "Object freed inside a callback while outer code still holds a reference",
        "vulnerable_code": [
            "object->callback = user_callback;",
            "process(object);   /* calls object->callback which frees object */",
            "use(object);       /* UAF: object may have been freed by callback */",
        ],
        "grep": r"callback|event_handler|destructor",
        "fix": "Reference counting (retain/release pattern) or generation counters",
        "cvss_impact": "Often Critical in browsers, OS kernels, event-driven systems",
    },
    "double_free": {
        "description": "free() called twice on the same pointer (CWE-415)",
        "vulnerable_code": [
            "free(ptr);",
            "/* ... */",
            "cleanup();         /* cleanup() also frees ptr — double free */",
        ],
        "grep": r"free\(\w+\).*free\(\w+\)",
        "fix": "Set ptr = NULL after free; check for NULL before free; single ownership",
        "cvss_impact": "Heap corruption — potentially exploitable for arbitrary write",
    },
}

print("[*] UAF PATTERN REFERENCE")
for name, info in UAF_PATTERNS.items():
    print(f"\n  [{name.upper()}]")
    print(f"  Description: {info['description']}")
    print(f"  Fix: {info['fix']}")
    print(f"  Impact: {info['cvss_impact']}")
```

---

## Bug Class 2 — Heap Buffer Overflow (CWE-122)

```c
/*
 * HEAP BUFFER OVERFLOW — corrupting adjacent heap metadata
 *
 * Unlike stack overflows, heap overflows do not directly overwrite return addresses.
 * Instead, they corrupt adjacent heap chunks — metadata or other objects.
 *
 * CORRUPTION TARGETS:
 *   1. Heap chunk metadata (size field, prev_size, fd/bk pointers in bins)
 *   2. Adjacent heap objects (vtable pointers, function pointers, capability fields)
 *   3. Heap management structures (top chunk pointer, arena metadata)
 *
 * EXPLOITATION PRIMITIVE:
 *   Corrupt the size field of the next chunk → convince allocator to return
 *   overlapping memory on the next malloc() → two pointers to same memory
 *   → write through one pointer to control what the other pointer reads as
 */

#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t capacity;           /* user-supplied buffer capacity */
    char   data[];             /* flexible array member — the buffer */
} Buffer;

typedef struct {
    void (*execute)(char *);   /* function pointer — exploitation target */
    int  privilege_level;
} Session;

/* VULNERABLE: copy len bytes into buf, no bounds check */
void fill_buffer(Buffer *buf, const char *src, size_t len) {
    memcpy(buf->data, src, len);   /* VULNERABLE if len > buf->capacity */
}

/* ATTACK SCENARIO:
 * Heap layout before attack:
 *   [Buffer: capacity=8, data=........][Session: execute=safe_fn, priv=0]
 *
 * Call fill_buffer(buf, attacker_data, 256):
 *   [Buffer: capacity=8, data=AAAA..AAAA][0x...attacker_execute...99 ...]
 *                                         ↑ Session.execute overwritten
 *
 * Next call to session->execute() → calls attacker code
 *
 * REAL CVEs:
 *   CVE-2021-44228 (Log4Shell): heap overflow leading to JNDI code execution
 *   CVE-2022-0847  (Dirty Pipe): heap corruption in pipe buffer
 *   CVE-2021-3156  (sudo): heap overflow via argv manipulation
 */
```

```python
#!/usr/bin/env python3
"""
Heap corruption PoC toolkit for CTF and research environments.
Uses pwntools — ensure target is a lab binary.
"""
from __future__ import annotations

from pwn import ELF, context, flat, log, p64, process, u64


def demo_tcache_poisoning(binary_path: str) -> None:
    """
    tcache poisoning: corrupt tcache->next pointer to get malloc() to return
    an arbitrary address.
    Requires: heap leak + UAF or heap overflow, glibc < 2.32 (no safe-linking).
    """
    elf = ELF(binary_path)
    context.binary = elf
    io = process(binary_path)

    log.info("Step 1: Create two chunks of the same size")
    # ... send commands to create chunk A and chunk B ...

    log.info("Step 2: Free chunk B, then free chunk A → A is at head of tcache")
    # After freeing: tcache[size] → A → B → NULL

    log.info("Step 3: UAF — overwrite A's tcache->next pointer")
    # A's fd pointer (first 8 bytes of freed chunk) = target address
    target = elf.got["printf"]           # Example: overwrite printf GOT entry
    # ... send command to write p64(target) to A's fd slot via UAF ...

    log.info("Step 4: malloc() twice — first gets A, second gets target address")
    # malloc() → A (returns chunk A to caller)
    # malloc() → target address (reads A->fd = target) → returns target as heap ptr!

    log.info("Step 5: Write to the returned 'target address' heap chunk")
    # This write goes to elf.got["printf"] — overwrite with system() address

    io.close()
    log.warning("Fill in the specific send/recv calls for your target binary")


def heap_spray_poc(target_addr: int, spray_size: int = 0x100) -> bytes:
    """
    Craft a heap spray payload.
    Fills the spray region with a repeated address (for UAF exploitation).
    """
    # Fill with NOP-sled equivalent + target address repeating
    nop_addr = target_addr
    # Each 8-byte slot = the address we want in the freed object's function pointer
    chunk = p64(nop_addr)
    spray_data = chunk * (spray_size // 8)
    log.info(f"Heap spray: {len(spray_data)} bytes, pattern = {nop_addr:#x}")
    return spray_data


def find_heap_base_via_uaf(io, alloc_size: int, offset: int) -> int:
    """
    Leak the heap base address via UAF: allocate, free, read the fd pointer.
    The fd pointer of a freed tcache chunk points to the next free chunk.
    The first freed chunk's fd = 0 (on glibc >= 2.32, it's XOR'd with key).
    """
    # Allocate, then free → fd pointer of freed chunk holds heap address
    # Use UAF read to get the fd value
    leaked = 0x0  # Replace with actual read from vulnerable binary
    log.info(f"Leaked heap fd pointer: {leaked:#x}")
    return leaked


# Reference: heap exploitation writeup targets
HEAP_EXPLOITATION_REFERENCES = {
    "how2heap": "https://github.com/shellphish/how2heap — example programs for each technique",
    "tcache_poisoning": "https://github.com/shellphish/how2heap/blob/master/glibc_2.31/tcache_poisoning.c",
    "house_of_spirit": "https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_spirit.c",
    "fastbin_dup": "https://github.com/shellphish/how2heap/blob/master/glibc_2.31/fastbin_dup.c",
    "pwndbg_commands": [
        "heap         — show all heap chunks",
        "bins         — show all bin contents (tcache, fastbins, etc.)",
        "heapinfo     — show arena metadata",
        "vis_heap_chunks — visual heap map",
        "find_fake_fast addr — find nearby fake fastbin chunks",
    ],
}

print("[*] HEAP EXPLOITATION REFERENCES")
for name, ref in HEAP_EXPLOITATION_REFERENCES.items():
    if isinstance(ref, str):
        print(f"  {name}: {ref}")
    elif isinstance(ref, list):
        print(f"  {name}:")
        for item in ref:
            print(f"    {item}")
```

---

## Stage 3 — Detecting UAF and Heap Corruption in Code Review

```python
#!/usr/bin/env python3
"""
Code review checklist for memory safety bugs.
"""
from __future__ import annotations

MEMORY_SAFETY_REVIEW = {
    "object_lifecycle_questions": [
        "Who owns this pointer? (who allocates, who is responsible for freeing?)",
        "Is there a reference count, or is ownership single-threaded?",
        "What happens if an error occurs mid-function — is the object freed correctly?",
        "Are there callbacks or event handlers that could free the object unexpectedly?",
        "Is the pointer zeroed after free? (ptr = NULL after free(ptr))",
        "Is there a use after free in any of the error paths?",
    ],
    "heap_overflow_questions": [
        "Is the destination buffer size checked before memcpy/strcpy/sprintf?",
        "Is the source length attacker-controlled (comes from a parsed field)?",
        "Is the buffer size calculated with arithmetic that could overflow?",
        "Does realloc() correctly update all pointers to the old buffer?",
        "Can the length field be set to a value larger than the allocated chunk?",
    ],
    "red_flags_in_code": [
        "free(ptr) without immediately setting ptr = NULL",
        "Multiple call sites that may free the same object independently",
        "Objects with function pointers stored alongside user data on the heap",
        "memcpy(dst, src, user_len) without bounds check on user_len",
        "realloc() return value not checked for NULL (allocation failure)",
        "Object shared across threads without synchronisation (race → UAF)",
    ],
    "patch_diff_signals": [
        "NULL pointer set immediately after free: '+ ptr = NULL;'",
        "Reference counting added: '+ refcount_inc(obj); ... refcount_dec(obj);'",
        "Ownership flag added to prevent double-free: '+ obj->freed = true;'",
        "Bounds check added before write: '+ if (len > capacity) { return ERR; }'",
        "Object size calculation fixed: '+ if (size > MAX_SIZE / 4) { ... }'",
    ],
}

print("[*] MEMORY SAFETY CODE REVIEW CHECKLIST")
for section, items in MEMORY_SAFETY_REVIEW.items():
    print(f"\n  [{section.upper()}]")
    for item in items:
        print(f"    → {item}")
```

---

## Stage 4 — Defences and Detection

```python
#!/usr/bin/env python3
"""
Compiler and OS defences against heap memory corruption.
"""
from __future__ import annotations

HEAP_DEFENCES = {
    "compile_time": {
        "AddressSanitizer": {
            "flag": "-fsanitize=address",
            "detects": "UAF, heap overflow, double-free, stack overflow",
            "overhead": "2–4× slowdown; not suitable for production",
            "usage": "Testing and fuzzing only",
        },
        "MemorySanitizer": {
            "flag": "-fsanitize=memory",
            "detects": "Use of uninitialised memory",
            "overhead": "3–7× slowdown",
            "usage": "Fuzzing campaigns targeting uninit read bugs",
        },
        "FORTIFY_SOURCE": {
            "flag": "-D_FORTIFY_SOURCE=2 -O2",
            "detects": "Known unsafe function calls at compile time",
            "overhead": "Negligible",
            "usage": "All production builds — enable by default",
        },
        "SafeStack": {
            "flag": "-fsanitize=safe-stack",
            "detects": "Stack smashing attacks (not heap)",
            "overhead": "~1% slowdown",
            "usage": "Production use viable for security-critical code",
        },
    },
    "runtime_glibc": {
        "tcache_key": "glibc 2.29+: each freed chunk contains a key; double-free detected",
        "safe_linking": "glibc 2.32+: tcache next pointers XOR'd with heap address (defeat type confusion)",
        "malloc_perturb": "MALLOC_PERTURB_=255 fills freed memory with 0xFF; catches UAF reads",
    },
    "language_alternatives": {
        "Rust": "Ownership model prevents UAF and double-free at compile time; zero overhead",
        "Go":   "GC prevents UAF; race detector: go test -race",
        "Java": "GC prevents UAF; heap overflow rare (bounds checked arrays)",
    },
    "detection_signals": {
        "SIGSEGV or SIGABRT": "Crash in malloc/free → heap corruption detected by glibc",
        "ASan output": "heap-buffer-overflow / heap-use-after-free in error message",
        "Valgrind": "valgrind --tool=memcheck ./target — detects UAF and leaks without crash",
        "WinDbg !heap": "Windows: !heap -p -a <addr> shows allocation/free history",
        "Volatility vadinfo": "Memory forensics: RWX regions without image-backed VAD = injected shellcode",
    },
}

print("[*] HEAP CORRUPTION DEFENCES")
print("\nCompile-time defences:")
for name, info in HEAP_DEFENCES["compile_time"].items():
    print(f"  {name}: {info['flag']}")
    print(f"    Detects: {info['detects']}")

print("\nRuntime glibc protections:")
for name, desc in HEAP_DEFENCES["runtime_glibc"].items():
    print(f"  {name}: {desc}")

print("\nDetection signals:")
for signal, desc in HEAP_DEFENCES["detection_signals"].items():
    print(f"  {signal}: {desc}")
```

---

## Key Takeaways

1. **UAF exploitability depends on heap feng shui — shaping the heap so that
   the right allocation fills the freed slot.** A UAF is only exploitable when:
   the freed object is reused by a new allocation of the same size; the new
   allocation contains attacker-controlled data; and the freed pointer is later
   used in a way that derferences the attacker-controlled data (typically calling
   a function pointer). All three conditions must be met. Understanding this helps
   you assess severity accurately.
2. **The tcache changed exploitation forever — but not in the defenders' favour.**
   glibc's tcache (2.26+) made heap manipulation faster and per-thread, which
   made UAF easier to exploit because the freed chunk is almost always returned
   to the same thread's next allocation. Safe-linking (2.32+) adds a mangling
   step, but heap leaks still defeat it. Modern heap exploitation requires knowing
   which glibc version the target uses.
3. **Double-free is a subset of UAF and equally dangerous.** Calling `free(ptr)`
   twice corrupts the bin structure. In tcache (without the 2.29 key protection),
   this creates a loop in the linked list — the next two malloc() calls return
   the same address, giving two independent pointers to the same memory. This is
   the basis of most CTF heap challenges post-2018.
4. **AddressSanitizer catches UAF in testing; nothing catches it cleanly in
   production without a performance hit.** Run ASan in your CI fuzzing pipeline.
   Deploy FORTIFY_SOURCE and glibc safe-linking in production. For new projects,
   use Rust or a GC language for any component that handles untrusted heap data.
   For legacy C/C++, audit every `free()` call site and enforce the null-after-free
   pattern via code review.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q663.1, Q663.2 …).

---

## Navigation

← Previous: [Day 662 — Integer Overflow and Format String](DAY-0662-Bug-Class-Integer-Overflow-Format-String.md)
→ Next: [Day 664 — Vulnerability Research Practice Sprint Day 1](DAY-0664-VulnResearch-Practice-Sprint-Day1.md)
