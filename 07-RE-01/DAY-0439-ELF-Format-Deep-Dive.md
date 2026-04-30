---
title: "ELF Format Deep Dive"
tags: [reverse-engineering, ELF, linux, PLT, GOT, dynamic-linking, sections, symbols]
module: 07-RE-01
day: 439
related_topics:
  - Windows PE Format (Day 438)
  - Memory Layout of a Process (Day 366)
  - Return-Oriented Programming (Day 373)
  - Identifying Algorithms in Binaries (Day 440)
---

# Day 439 — ELF Format Deep Dive

> "You already used the PLT and GOT in your ROP chains. Now you understand them
> from first principles. The dynamic linker, the PLT trampoline, the GOT slot —
> this is not magic. It is a specific design with specific attack surfaces.
> Know the design, own the attack surface."
>
> — Ghost

---

## Goals

Read and interpret every major ELF section and header field.
Understand how PLT/GOT dynamic linking works step by step.
Use `readelf` and `objdump` to extract information from binaries.
Understand how the GOT is a write target in exploits and a read target in RE.

**Prerequisites:** Day 366 (memory layout), Day 373 (ROP/GOT overwrite), Day 438 (PE
comparison).
**Time budget:** 3–4 hours.

---

## Part 1 — ELF Header

Every ELF file starts with a 64-byte header:

```
Magic:   7f 45 4c 46  ("ELF")
Class:   2 = 64-bit
Data:    1 = little-endian
Type:    2 = ET_EXEC (executable), 3 = ET_DYN (shared object / PIE)
Machine: 62 = x86-64
Entry point address: virtual address of _start
Start of program headers: offset in file
Start of section headers: offset in file
```

```bash
readelf -h /bin/ls | head -20
# Shows all header fields

file /bin/ls
# "ELF 64-bit LSB pie executable" → ET_DYN with PIE
```

---

## Part 2 — Sections vs Segments

ELF has two views of the file:

| View | Structure | Used by |
|---|---|---|
| Section view | Section headers | Linker, debugger, analysis tools |
| Segment view | Program headers | OS loader — what gets mapped into memory |

```bash
readelf -S /bin/ls    # sections (what RE tools care about)
readelf -l /bin/ls    # segments (what the OS loads)
```

### Key Sections for RE

| Section | Contents |
|---|---|
| `.text` | Executable code |
| `.rodata` | Read-only data — strings, constants, jump tables |
| `.data` | Initialised read/write global variables |
| `.bss` | Zero-initialised globals (no bytes on disk) |
| `.got` | Global Offset Table — pointer-sized slots for global variable addresses |
| `.got.plt` | GOT entries for PLT-resolved functions |
| `.plt` | Procedure Linkage Table — trampoline stubs for library calls |
| `.plt.got` | Variant PLT (partial RELRO binaries) |
| `.symtab` | Symbol table (stripped in production) |
| `.dynsym` | Dynamic symbol table (always present — needed by linker) |
| `.dynstr` | String table for `.dynsym` |
| `.rela.plt` | Relocation entries for PLT slots |
| `.debug_info` | DWARF debug info (if compiled with `-g`) |

---

## Part 3 — PLT and GOT: How Dynamic Linking Works

When a binary calls `printf()`, the call goes through the PLT trampoline:

```
Binary code:
    call    printf@plt          ; CALL to PLT stub

PLT stub for printf (in .plt section):
    jmp     qword ptr [printf@got.plt]   ; jump to GOT slot
    push    0x0                           ; push relocation index (first call only)
    jmp     _dl_runtime_resolve          ; ask the dynamic linker to resolve

GOT slot for printf (in .got.plt):
    Initially: points back into the PLT push instruction
    After first call: points to the actual printf() in libc
```

### Visualised

```
First call to printf():
  CALL printf@plt
    → PLT: jmp [GOT[printf]]          (GOT still points to PLT+6)
    → PLT: push reloc_index
    → PLT: jmp _dl_runtime_resolve    (dynamic linker finds printf)
    → GOT[printf] = &printf in libc   (patched by linker)
    → execute printf

Subsequent calls to printf():
  CALL printf@plt
    → PLT: jmp [GOT[printf]]          (GOT now points to libc printf)
    → execute printf directly
```

This is called **lazy binding**. With FULL RELRO, all GOT entries are resolved
at startup and the GOT is made read-only.

---

## Part 4 — Reading the GOT in RE and Exploits

```bash
# See all GOT entries (what functions are imported and where their GOT slots are)
objdump -d -M intel /bin/ls | grep '@plt'
# Shows every PLT stub name

readelf -r /bin/ls | grep -E 'R_X86_64_JUMP_SLOT'
# Shows PLT relocation entries: virtual address of each GOT slot
```

### In Ghidra

In the Listing view, navigate to `printf@plt`. You see:
```
JMP  qword ptr [printf@GOT]
```

Click on `printf@GOT` → navigates to the GOT slot address.
This is the address you overwrite in a GOT hijack exploit.

---

## Part 5 — Symbol Tables

### .dynsym (Always Present)

Contains symbols needed for dynamic linking. Even stripped binaries have
`.dynsym` because the dynamic linker needs it.

```bash
readelf --dyn-syms /bin/ls | head -20
# Shows imported library functions with their types
```

### .symtab (Usually Stripped)

Contains all symbols including local functions. Only present if the binary was
compiled without `-s`.

```bash
readelf -s /bin/ls
# Stripped binary → "no symbols" or very few
# Unstripped binary → full function/variable list
```

### Checking Strip Status

```bash
file binary
# "not stripped" → .symtab present → function names in Ghidra
# "stripped" → only .dynsym → Ghidra shows FUN_00401234 names
```

---

## Part 6 — .init, .fini, .init_array, .fini_array

These sections contain code that runs before/after `main()`:

| Section | When it runs |
|---|---|
| `.init` | Before `_start` calls `main()` |
| `.init_array` | Array of function pointers, all called before `main()` |
| `.fini` | After `main()` returns |
| `.fini_array` | Array of function pointers, all called after `main()` |

```bash
readelf -S binary | grep -E 'init|fini'
# Find these sections

objdump -d binary | grep -A5 '<_init>'
```

**RE implication:** Malware may hide initialisation code in `.init_array` to run
before any analysis breakpoints set at `main()`. Check these sections for
suspicious function pointers.

---

## Part 7 — Practical: Full Binary Fingerprint

```bash
#!/bin/bash
# elf_triage.sh
TARGET=$1

echo "=== ELF HEADER ==="
readelf -h $TARGET | grep -E 'Type:|Machine:|Entry point'

echo "=== SECTIONS ==="
readelf -S $TARGET | grep -E '\.text|\.data|\.bss|\.got|\.plt|\.rodata|init|fini'

echo "=== DYNAMIC SYMBOLS (imports) ==="
readelf --dyn-syms $TARGET | grep -E 'FUNC' | awk '{print $8}' | sort -u

echo "=== PLT RELOCATIONS ==="
readelf -r $TARGET | grep 'JUMP_SLOT' | awk '{print $5}'

echo "=== ENTROPY PER SECTION ==="
python3 << EOF
import math
data = open("$TARGET", "rb").read()

import subprocess
result = subprocess.run(["readelf", "-S", "$TARGET"],
    capture_output=True, text=True).stdout

# Simple overall entropy
freq = [data.count(i)/len(data) for i in range(256) if data.count(i)]
h = -sum(p*math.log2(p) for p in freq)
print(f"Overall entropy: {h:.2f}")
EOF
```

---

## Key Takeaways

1. PLT/GOT is the mechanism for lazy binding. The GOT slot starts pointing back
   into the PLT; after the first call, it points to the real library function.
2. With FULL RELRO, the GOT is read-only. GOT hijacks require a different write
   target (e.g., `__malloc_hook`, `__free_hook`, or modern alternatives).
3. `.init_array` and `.fini_array` hold constructor/destructor function pointers
   that run before/after `main()`. Malware hides code here.
4. `.dynsym` is always present — it names every imported function. Even stripped
   binaries reveal their library dependencies through it.
5. Section entropy identifies packed or encrypted sections. Any section with
   entropy > 7.0 deserves extra attention.

---

## Exercises

1. Run `elf_triage.sh` on three binaries: `/bin/ls`, a custom-compiled binary
   with `-g`, and a UPX-packed binary. Compare the results.
2. Trace a PLT call in GDB: set a breakpoint at `printf@plt`, single-step
   through the PLT stub, the GOT lookup, and into the actual libc `printf`.
   Confirm the GOT slot address matches `readelf -r` output.
3. Read the `.init_array` of any binary. What functions are in it?
   What does each one do?
4. Compare the `.dynsym` import lists of a clean `ssh` client and a malicious
   binary with process injection capability. What differences stand out?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q439.1, Q439.2 …).

---

## Navigation

← Previous: [Day 438 — Windows PE Format](DAY-0438-Windows-PE-Format.md)
→ Next: [Day 440 — Identifying Algorithms in Binaries](DAY-0440-Identifying-Algorithms-in-Binaries.md)
