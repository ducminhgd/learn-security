---
title: "Unpacking Lab — Manual Unpacking of a UPX Binary"
tags: [reverse-engineering, unpacking, UPX, OEP, process-dump, gdb, lab]
module: 07-RE-02
day: 452
related_topics:
  - Packers and Obfuscation (Day 451)
  - Anti-Debugging Techniques (Day 453)
  - Dynamic Analysis with GDB (Day 436)
---

# Day 452 — Unpacking Lab: Manually Unpack a UPX Binary

> "Automatic unpacking tools break on custom packers. Manual unpacking
> does not. Learn to catch the binary at the OEP and dump it. That skill
> works against every packer you will ever meet."
>
> — Ghost

---

## Goals

Understand the manual unpacking workflow: run to OEP, dump, fix imports.
Manually unpack a UPX binary using GDB without using `upx -d`.
Understand the generalised OEP-detection technique for custom packers.

**Prerequisites:** Day 451 (packer internals), Day 436 (GDB dynamic analysis).
**Time budget:** 4 hours.

---

## Part 1 — The Manual Unpacking Method

Manual unpacking always follows the same four steps:

```
Step 1: Run the binary in a debugger
Step 2: Let the unpacking stub run — stop at the OEP (just before JMP to original code)
Step 3: Dump the process memory at that point — the payload is now decrypted
Step 4: Fix the Import Address Table in the dumped binary
```

This works against ANY packer. The stub must decrypt before running — you just
wait for it to finish.

---

## Part 2 — Lab Setup

```bash
# Create a simple binary to pack
cat > target.c << 'EOF'
#include <stdio.h>
#include <string.h>

int check(const char *s) {
    return strcmp(s, "unpack_me") == 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { puts("Usage: target <key>"); return 1; }
    if (check(argv[1])) {
        puts("You unpacked me. Well done.");
    } else {
        puts("Wrong.");
    }
    return 0;
}
EOF

gcc -O0 -no-pie -o target target.c    # no PIE for simpler addressing
upx -9 -o target_packed target        # pack it
```

**Verify packing:**
```bash
file target         # ELF 64-bit, not stripped
file target_packed  # UPX compressed
strings target | grep unpack_me  # found
strings target_packed | grep unpack_me  # not found — it is inside the compressed blob
```

---

## Part 3 — Finding the OEP in GDB

The UPX stub ends with a JMP to the Original Entry Point. The OEP is in the
decompressed section (UPX0 — the section that starts at low entropy because it
is zero-filled on disk but filled at runtime).

### Method 1: Hardware Breakpoint on Code Execution in UPX0

```bash
gdb ./target_packed
pwndbg> run                    # let it crash or break at a known point
# Find the UPX0 section range:
pwndbg> info proc mappings
# Look for a region that is executable but starts with zeroes on disk
# Typically the lowest address executable region after the stub
pwndbg> hbreak *0x401000       # set hardware execute breakpoint at UPX0 start
# Hardware breakpoints trigger on execution, not just on data access
pwndbg> run
# GDB stops at the OEP — the first instruction of the original binary
```

### Method 2: Step Through the Stub to the Final JMP

```bash
gdb ./target_packed
pwndbg> break *<entry_point_address>   # break at the UPX stub start
# get entry point: readelf -h target_packed | grep Entry
pwndbg> run
# In the Listing: watch for the unpacking loop to end
# Then: single-step (si) until you see: JMP <address_in_upx0>
# That JMP target is the OEP
```

### Method 3: Breakpoint on the JMP Pattern

UPX stub ends with: `pop eax; push <regs>; jmp eax`

```bash
# Search for the JMP pattern in the loaded text:
pwndbg> search -x ff e0    # "jmp eax" opcode
# Or: search for 'jmp' instructions in the stub section
# Breakpoint on the jmp
pwndbg> break *<jmp_address>
pwndbg> run
# At the break, examine EAX/RAX — it contains the OEP
```

---

## Part 4 — Dumping the Process

Once stopped at the OEP, the entire original binary is decrypted in memory.
Dump it:

### Using GDB `dump`

```bash
# At the OEP breakpoint:
pwndbg> info proc mappings   # find the executable region start and size
# Dump from the image base to end of last mapped region:
pwndbg> dump binary memory unpacked.bin 0x400000 0x402000
```

### Using `/proc/PID/maps` + dd

```bash
# From another terminal while GDB is paused:
cat /proc/$(pgrep target_packed)/maps
# Find: 00400000-00402000 r-xp ... (the original .text region)
dd if=/proc/$(pgrep target_packed)/mem bs=1 skip=$((0x400000)) \
   count=$((0x2000)) of=unpacked.bin 2>/dev/null
```

### Using pwntools to Automate

```python
# dump_at_oep.py
from pwn import *

p = process('./target_packed')
# attach GDB, break at OEP, then use pwntools to read memory
gdb.attach(p, gdbscript='''
break *0x401000
continue
''')
# After GDB breaks, dump from Python:
# (This is illustrative; actual process memory reading requires /proc)
p.interactive()
```

---

## Part 5 — Fixing the Import Table

The dumped binary's IAT entries contain runtime addresses (ASLR-affected or
the resolved libc addresses), not the original RVAs that a valid PE/ELF needs.

### For ELF on Linux: Rebuilding the PLT/GOT

ELF unpacking is simpler than PE: the PLT and GOT are part of the original
binary structure. After dumping, if the base address is correct:

```bash
# Verify the dump is correct:
file unpacked.bin           # should say ELF if dump was correct
readelf -h unpacked.bin     # should show valid header
readelf --dyn-syms unpacked.bin   # should show imports
```

### For PE on Windows: Using Scylla / ImpREC

PE import fixing requires specialised tools:

```
Windows workflow:
1. Pause at OEP (using x64dbg or OllyDbg)
2. Use Scylla plugin: Scylla → IAT Autosearch → Get Imports → Fix Dump
3. The fixed PE is a valid, loadable executable
```

---

## Part 6 — Confirming the Unpack

```bash
# Your dumped binary should be functional:
chmod +x unpacked.bin
./unpacked.bin unpack_me
# → "You unpacked me. Well done."

./unpacked.bin wrong
# → "Wrong."

# Confirm the key is now visible:
strings unpacked.bin | grep unpack_me
# → unpack_me  ← visible because the binary is decompressed
```

---

## Part 7 — Generalised OEP Detection Technique

For custom (non-UPX) packers, the OEP detection method is the same conceptually:

```
1. Identify the packed region (high entropy section).
2. Identify where the stub writes decompressed data (usually via VirtualAlloc
   or mmap + a write loop).
3. Set a hardware breakpoint on EXECUTE access to the target address (the base
   of the decompressed region).
4. Run — GDB breaks when the CPU first executes code at the decompressed region.
   That is the OEP.
5. Dump memory at that point.
```

Hardware breakpoints on execute (`hbreak`) are the key: they do not require you
to know the OEP address in advance. You just know the region where the OEP will be.

---

## Key Takeaways

1. The manual unpacking workflow: run to OEP → dump memory → fix imports.
   This works against every packer, because every packer must decrypt before
   executing.
2. Hardware execute breakpoints (`hbreak` in GDB) are the universal OEP
   detection tool. Set them on the decompressed region; the CPU fires them
   when execution reaches the OEP.
3. `upx -d` is the easy path for UPX. Learn manual unpacking for everything
   else — and to understand what the automatic tools do.
4. After dumping, validate the binary with `file` and `readelf`. A valid dump
   has a correct ELF/PE header at the base address.
5. The IAT is broken in a raw dump. On Linux/ELF this is often self-healing;
   on Windows/PE you need Scylla or ImpREC.

---

## Exercises

1. Manually unpack `target_packed` using Method 1 (hardware execute breakpoint).
   Confirm the key "unpack_me" is visible in the dump with `strings`.
2. Manually unpack `target_packed` using Method 2 (step through to JMP). Record
   every step with screenshots or terminal output.
3. Write a pwntools script that: (a) launches the packed binary, (b) uses GDB's
   `hbreak` at a known address, (c) dumps memory to a file automatically.
4. Find a custom-packed binary (search MalwareBazaar for samples tagged
   "custom packer"). Apply the generalised OEP detection technique in a
   sandboxed VM. Document the unpacking stub algorithm.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q452.1, Q452.2 …).

---

## Navigation

← Previous: [Day 451 — Packers and Obfuscation](DAY-0451-Packers-and-Obfuscation.md)
→ Next: [Day 453 — Anti-Debugging Techniques](DAY-0453-Anti-Debugging-Techniques.md)
