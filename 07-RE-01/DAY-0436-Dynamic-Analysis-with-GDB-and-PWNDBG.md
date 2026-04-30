---
title: "Dynamic Analysis with GDB and PWNDBG"
tags: [reverse-engineering, gdb, pwndbg, dynamic-analysis, breakpoints, watchpoints, tracing]
module: 07-RE-01
day: 436
related_topics:
  - GDB and PWNDBG (Day 368)
  - Ghidra Lab Crackme 2 (Day 435)
  - Frida for Reverse Engineering (Day 437)
---

# Day 436 — Dynamic Analysis with GDB and PWNDBG

> "Static analysis tells you what the code says. Dynamic analysis tells
> you what the code actually does with your specific input. They answer
> different questions. A serious reverser uses both."
>
> — Ghost

---

## Goals

Use GDB and pwndbg as a reverse engineering tool, not just an exploit
development tool.
Set breakpoints on functions without source code.
Use watchpoints to catch when a memory location changes.
Trace program execution to observe the actual runtime flow.

**Prerequisites:** Day 368 (GDB basics), Day 435 (crackme 2), pwndbg installed.
**Time budget:** 3–4 hours.

---

## Part 1 — RE-Focused GDB Workflow

In exploit development, you chase crash offsets. In RE, you trace program logic.
The questions change:

| Exploit Dev question | RE question |
|---|---|
| Where does RIP point after overflow? | What does this function return with this input? |
| What is the offset to EIP? | What value does this comparison use? |
| Where is system()? | What arguments are passed to this function? |

---

## Part 2 — Breakpoints Without Source Code

### Break on a Function Name

```bash
gdb ./crackme2
pwndbg> info functions           # list all function symbols (if not stripped)
pwndbg> break main
pwndbg> break check_password     # if Ghidra gave you the name, it may be present
```

### Break on an Address

When the binary is stripped, use Ghidra's address:

```bash
pwndbg> run <<< "test_input"
# Let it run once to load the binary. Get the base address:
pwndbg> info proc mappings
# Find the mapped range of the binary (the first r-xp segment)
# Base = 0x555555554000 (typical with PIE)
# Ghidra function at 0x001156 → runtime addr = 0x555555555156
pwndbg> break *0x555555555156
```

### Disable/Skip a Check Temporarily

```bash
# Run to the ptrace anti-debug check
pwndbg> break *<address_of_ptrace_call>
pwndbg> run
# At the break, skip the ptrace call:
pwndbg> set $rip = $rip + <size_of_call_instruction>
# Or force the return value to 0:
pwndbg> finish    # let ptrace run
# If it returned -1, override:
pwndbg> set $rax = 0   # pretend ptrace returned 0 (success)
pwndbg> continue
```

---

## Part 3 — Observing Values at Runtime

### Print Register Values

```bash
pwndbg> info registers           # all registers
pwndbg> p $rax                   # specific register
pwndbg> p/x $rax                 # hex format
pwndbg> p/c $al                  # character format (single byte)
```

### Print Memory

```bash
pwndbg> x/s $rdi                 # print string at address in RDI
pwndbg> x/32xb $rsp              # print 32 bytes at RSP in hex
pwndbg> x/8gx $rsp               # print 8 quad-words at RSP
pwndbg> x/10i $rip               # print next 10 instructions at RIP
```

### Catching Function Arguments

On the first instruction of a function call (x64 SysV ABI):

```
RDI = 1st argument
RSI = 2nd argument
RDX = 3rd argument
```

```bash
# Break at the start of check_password
pwndbg> break *check_password
pwndbg> run <<< "my_input"
pwndbg> x/s $rdi                 # should show "my_input"
```

---

## Part 4 — Watchpoints

A watchpoint fires when a memory address is **read or written**.
Essential for tracking where a value changes.

```bash
# Watch a stack variable
pwndbg> break main
pwndbg> run
# Get address of local variable (output is from 'x' command):
pwndbg> info frame               # see frame info, local variable addresses
pwndbg> watch *0x7fffffffde50    # set watchpoint on that address
pwndbg> continue                 # run until the variable changes
# GDB will stop and show you who changed it
```

**Use case:** You see a comparison in Ghidra but cannot figure out where the
expected value is computed. Watchpoint the expected-value buffer. Run the binary.
GDB stops when the value is written — you see exactly which instruction wrote it.

---

## Part 5 — Tracing with `strace` and `ltrace`

### strace — System Call Tracer

```bash
strace ./crackme2 <<< "test"
# Shows every syscall: open, read, write, exit...
# Key observations:
#   read(0, ...) → reads your input from stdin
#   write(1, "Wrong.\n", 7) → which output path was taken
#   ptrace(PTRACE_TRACEME, ...) = -1 EPERM → caught by strace itself
```

### ltrace — Library Call Tracer

```bash
ltrace ./crackme2 <<< "test"
# Shows library function calls:
#   ptrace(0, 0, 0, 0) = -1
#   fgets(...) = 0x...
#   strcmp("transformed", "expected") = N   ← the comparison value
```

`ltrace` is often more useful than `strace` for crackmes because it shows you
the arguments to `strcmp`, `memcmp`, and `strncmp` directly.

```bash
ltrace ./crackme2 <<< "test" 2>&1 | grep -E 'strcmp|memcmp|strncmp'
```

---

## Part 6 — Practical Session on Crackme 2

Goal: observe the comparison at runtime to recover the key dynamically.

```bash
# Step 1: run under ltrace to catch the strcmp
ltrace ./crackme2 <<< "aaaaaaaaaaaaa" 2>&1 | grep strcmp
# Output (approximately):
# strcmp("\x5c\x5d\x5e\x5f\x60\x61\x63\x65...", "o s g g r q U W e Z l k")
# Left side: transform("aaaaaaaaaaaaa")
# Right side: TRANSFORMED constant

# Step 2: if ltrace is blocked by anti-ltrace, patch the binary
# In Ghidra, find the is_debugged function address
# Patch: change 'call is_debugged' → 'xor eax, eax; nop; nop'
# Save the patched binary
# Run ltrace on the patched binary

# Step 3: breakpoint at strcmp in GDB
gdb ./crackme2
pwndbg> break strcmp
pwndbg> run <<< "aaaaaaaaaaaaa"
pwndbg> x/s $rdi       # first argument (transformed input)
pwndbg> x/s $rsi       # second argument (expected TRANSFORMED)
```

---

## Part 7 — Binary Patching in Ghidra

Sometimes you want to patch a check to bypass it permanently for analysis.

```
In Ghidra Listing view:
1. Navigate to the instruction to patch (e.g., JNE after ptrace check)
2. Right-click → Patch Instruction
3. Change JNE to JE (or NOP the instruction)
4. File → Export Program → ELF → save as crackme2_patched
```

For raw patching:

```bash
# Find the offset of the JNE:
objdump -d crackme2 | grep -A5 ptrace
# Note the file offset (not virtual address — use objdump -F)
# Patch with a hex editor (e.g., xxd):
cp crackme2 crackme2_patched
printf '\x90\x90' | dd of=crackme2_patched bs=1 seek=OFFSET conv=notrunc
```

---

## Key Takeaways

1. `ltrace` is the fastest way to catch string comparisons in crackmes.
   `strcmp(input, expected)` leaks both sides in the trace.
2. Watchpoints catch writes to memory that you cannot find statically.
   Set them on mystery buffers and let the binary reveal who writes them.
3. Anti-debug tricks that target `ptrace` break `ltrace` and `strace` too.
   Static analysis or binary patching is required.
4. Break on an address (not a symbol name) when the binary is stripped.
   Compute `runtime_address = base + ghidra_offset` using `info proc mappings`.
5. Combining static (identify the algorithm) + dynamic (confirm and extract
   values) is always faster than either approach alone.

---

## Exercises

1. Use `ltrace` on crackme1 from Day 433. Can you recover the password from the
   `strcmp` arguments in the trace? Why or why not (recall the custom loop)?
2. Set a watchpoint on the `transformed` buffer in crackme2. Run it with input
   "aaaaaaaaaaaaa". Watch GDB stop as each byte is written.
3. Patch crackme2 to bypass the `ptrace` anti-debug. Verify that `strace` now
   runs without triggering "Nice try."
4. Write a Python script that: (a) uses pwntools to launch crackme2, (b) sets a
   breakpoint at the strcmp, (c) reads the second argument (expected value),
   and (d) prints the expected string.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q436.1, Q436.2 …).

---

## Navigation

← Previous: [Day 435 — Ghidra Lab: Crackme 2](DAY-0435-Ghidra-Lab-Crackme-2.md)
→ Next: [Day 437 — Frida for Reverse Engineering](DAY-0437-Frida-for-Reverse-Engineering.md)
