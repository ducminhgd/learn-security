---
title: "x64 Assembly for Reverse Engineers"
tags: [reverse-engineering, assembly, x64, disassembly, patterns, structs, loops, switches]
module: 07-RE-01
day: 434
related_topics:
  - x86/x64 Assembly Basics (Day 367)
  - Ghidra Lab Crackme 1 (Day 433)
  - Ghidra Lab Crackme 2 (Day 435)
---

# Day 434 — x64 Assembly for Reverse Engineers

> "Binary exploitation taught you assembly to control execution.
> Reverse engineering teaches you assembly to read intention.
> Same instructions. Different question. Now you ask:
> what was the programmer trying to do here?"
>
> — Ghost

---

## Goals

Read disassembly output fluently without relying solely on the decompiler.
Recognise common C constructs in assembly: loops, if/else, switch, structs, arrays.
Identify compiler-introduced patterns versus programmer logic.
Use the Listing view in Ghidra as a primary analysis tool.

**Prerequisites:** Day 367 (x64 assembly basics), Day 432 (Ghidra).
**Time budget:** 4 hours.

---

## Part 1 — Reading x64 Assembly in a RE Context

You already know the registers and instructions. The RE challenge is pattern
recognition — mapping familiar C constructs to their compiled form.

### The Key Difference from Exploit Dev

In exploit development you follow one execution path to control RIP.
In reverse engineering you read ALL paths to understand the program's logic.

### Ghidra Listing vs Decompiler

| Listing (disassembly) | Decompiler |
|---|---|
| Always accurate | Best-effort approximation |
| Verbose | Concise |
| Shows every instruction | Hides compiler noise |
| Required for obfuscated code | Sufficient for clean code |
| Shows addresses directly | Uses variable names |

Use decompiler to orient. Switch to Listing to verify.

---

## Part 2 — Recognising C Constructs in Assembly

### If / Else

```c
// C source
if (x > 0) {
    result = 1;
} else {
    result = -1;
}
```

```asm
; Compiled x64 (typical)
cmp     dword ptr [rbp-4], 0     ; compare x to 0
jle     .else_branch             ; if x <= 0, jump to else
mov     dword ptr [rbp-8], 1    ; result = 1
jmp     .end_if
.else_branch:
mov     dword ptr [rbp-8], -1   ; result = -1
.end_if:
```

**Pattern:** `cmp` + conditional jump + assignment.
The jump condition is often **the inverse** of the C condition (`jle` for `if (x > 0)`).

---

### While Loop

```c
// C source
while (i < 10) {
    sum += arr[i];
    i++;
}
```

```asm
; Typical compiled form
jmp     .loop_check            ; jump to condition check first
.loop_body:
    movsxd  rax, dword ptr [rbp-4]    ; i
    mov     ecx, dword ptr [rbp-8+rax*4]  ; arr[i]
    add     dword ptr [rbp-12], ecx   ; sum += arr[i]
    add     dword ptr [rbp-4], 1      ; i++
.loop_check:
    cmp     dword ptr [rbp-4], 10     ; i < 10?
    jl      .loop_body                ; if so, loop back
```

**Pattern:** Condition check at the end (or a JMP to the check), loop body above.

---

### For Loop (Equivalent)

```asm
; for (i=0; i<10; i++) is compiled identically to the while above.
; The initialiser i=0 appears before the loop.
mov     dword ptr [rbp-4], 0    ; i = 0
jmp     .loop_check
```

---

### Switch Statement

```c
switch (cmd) {
    case 1: handle_read(); break;
    case 2: handle_write(); break;
    case 3: handle_exit(); break;
    default: handle_error();
}
```

Compilers generate two patterns depending on case density:

**Jump table (dense cases):**
```asm
; cmd in eax
sub     eax, 1                     ; normalize: case 1 → index 0
cmp     eax, 2                     ; is index > max_case?
ja      .default                   ; if so, jump to default
lea     rcx, [rip+jump_table]      ; load jump table address
movsxd  rax, dword ptr [rcx+rax*4] ; load offset from table
add     rax, rcx                   ; compute absolute address
jmp     rax                        ; jump to case handler
jump_table:
    dd offset_case1
    dd offset_case2
    dd offset_case3
```

Ghidra renders jump tables as computed `JMP` instructions. In the decompiler
they appear as `switch` statements automatically.

**If-else chain (sparse cases):**
```asm
cmp     eax, 1
je      .case_1
cmp     eax, 2
je      .case_2
jmp     .default
```

---

### Struct Access

```c
// C source
struct User {
    int id;         // offset 0
    char name[32];  // offset 4
    int active;     // offset 36
};
struct User *u = get_user();
printf("%d %s\n", u->id, u->name);
```

```asm
; rax = pointer to User struct
mov     edi, dword ptr [rax]       ; u->id  (offset 0)
lea     rsi, [rax+4]               ; &u->name (offset 4)
```

**Pattern:** Fixed positive offsets from a base register (`[rax+N]`) indicate
struct field access. Group the offsets — they reveal the struct layout.

**Technique:** In Ghidra, select the base register in the decompiler. Right-click
→ "Auto Create Structure" to have Ghidra infer the struct.

---

### String Operations

```asm
; strlen equivalent (manual loop)
.strlen_loop:
    cmp     byte ptr [rax], 0       ; is *ptr == '\0'?
    je      .strlen_done
    add     rax, 1                  ; ptr++
    jmp     .strlen_loop
.strlen_done:

; memcpy equivalent
rep     movsb                        ; copy RCX bytes from RSI to RDI
; OR:
movdqu  xmm0, xmmword ptr [rsi]     ; SSE: copy 16 bytes at once
movdqu  xmmword ptr [rdi], xmm0
```

---

## Part 3 — Compiler Idioms to Recognise

### Integer Division by Constant

```asm
; Dividing by a constant (e.g., n / 10) is compiled as multiplication
imul    rax, rcx, 0x6666666666666667  ; magic constant for /10
sar     rax, 0x23                     ; arithmetic right shift
```

This is not obfuscation — it is compiler optimisation. The decompiler will
show `/ 10` correctly. In the Listing, recognise the magic constant pattern.

### Boolean Expressions with Bit Tricks

```asm
; x != 0 → (bool)
test    eax, eax         ; sets ZF if eax == 0
setnz   al               ; al = 1 if not zero, 0 if zero
```

### Tail Call Optimisation

```asm
; Instead of: call foo; ret
; Compiler emits: jmp foo
; The called function returns directly to the original caller
jmp     check_password
```

### Inlined memset / bzero

```asm
; memset(buf, 0, 64)
pxor    xmm0, xmm0
movdqu  xmmword ptr [rsp], xmm0
movdqu  xmmword ptr [rsp+0x10], xmm0
movdqu  xmmword ptr [rsp+0x20], xmm0
movdqu  xmmword ptr [rsp+0x30], xmm0
```

---

## Part 4 — A Full Disassembly Reading Exercise

Read this function in the Listing without looking at the decompiler:

```asm
check_serial:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x20
    mov     qword ptr [rbp-0x18], rdi   ; save first arg (serial string)
    mov     dword ptr [rbp-4], 0        ; i = 0
    jmp     .check_cond
.loop_body:
    mov     rax, qword ptr [rbp-0x18]   ; serial ptr
    movsxd  rcx, dword ptr [rbp-4]      ; i
    movzx   eax, byte ptr [rax+rcx]     ; serial[i]
    movsxd  rcx, dword ptr [rbp-4]      ; i
    and     eax, 0xff                   ; zero-extend
    xor     eax, 0x5a                   ; serial[i] ^ 0x5A
    lea     rcx, [rip+expected]         ; expected[] in .rodata
    movsxd  rdx, dword ptr [rbp-4]      ; i
    movzx   ecx, byte ptr [rcx+rdx]     ; expected[i]
    cmp     eax, ecx                    ; (serial[i] ^ 0x5A) == expected[i] ?
    je      .loop_continue
    mov     eax, 0                      ; return 0 (fail)
    jmp     .done
.loop_continue:
    add     dword ptr [rbp-4], 1        ; i++
.check_cond:
    cmp     dword ptr [rbp-4], 8        ; i < 8?
    jl      .loop_body
    mov     eax, 1                      ; return 1 (success)
.done:
    add     rsp, 0x20
    pop     rbp
    ret
```

**What does this function do?**

Each byte of the input is XOR'd with `0x5A` and compared to `expected[i]`.
To find the valid serial: `expected[i] ^ 0x5A` for each byte.

If `expected` at the `.rodata` address contains: `0x3A 0x29 0x3A 0x1F 0x21 0x27 0x29 0x3F`
Then the serial is: `'p' 's' 'p' 'e' '{' 'a' 's' 'e'` (each XOR'd with 0x5A).

```python
expected = [0x3A, 0x29, 0x3A, 0x1F, 0x21, 0x27, 0x29, 0x3F]
serial = ''.join(chr(b ^ 0x5A) for b in expected)
print(serial)
```

---

## Key Takeaways

1. Every C construct compiles to a recognisable assembly pattern. Loops end with
   a conditional jump backward. If/else uses forward jumps. Switch uses a jump
   table or a series of `cmp`/`je` pairs.
2. Struct field access appears as fixed positive offsets from a base pointer.
   Grouping the offsets reveals the struct layout.
3. Compiler optimisations (division magic numbers, SIMD memset, tail calls) are
   noise, not obfuscation. The decompiler undoes most of them.
4. When a loop XORs input with a constant and compares to a fixed array, the
   key extraction is: `array[i] ^ constant`.
5. Read the disassembly when the decompiler is wrong. The disassembly is the
   ground truth.

---

## Exercises

1. Compile a C file containing a `switch` with 5 cases. Inspect the compiled
   output in Ghidra. Does it use a jump table or an if-else chain? Why?
2. Write a C struct with 4 fields of different types. Compile, import into
   Ghidra, and use "Auto Create Structure" to let Ghidra infer the layout.
   Verify it matches your source.
3. Find the division-by-constant idiom in any real binary
   (`/usr/bin/date` has date arithmetic). Note the magic constant.
4. Solve the XOR serial exercise above manually in Python. Verify the serial
   works by compiling a test binary with that expected array.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q434.1, Q434.2 …).

---

## Navigation

← Previous: [Day 433 — Ghidra Lab: Crackme 1](DAY-0433-Ghidra-Lab-Crackme-1.md)
→ Next: [Day 435 — Ghidra Lab: Crackme 2 with Anti-Debug](DAY-0435-Ghidra-Lab-Crackme-2.md)
