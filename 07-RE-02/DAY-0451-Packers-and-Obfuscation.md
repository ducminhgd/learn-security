---
title: "Packers and Obfuscation"
tags: [reverse-engineering, packers, UPX, obfuscation, entropy, unpacking, PE-sections]
module: 07-RE-02
day: 451
related_topics:
  - RE Practice Labs (Days 441–450)
  - Unpacking Lab (Day 452)
  - Anti-Debugging Techniques (Day 453)
  - Identifying Algorithms in Binaries (Day 440)
---

# Day 451 — Packers and Obfuscation

> "A packed binary is the attacker's first line of defence against your
> analysis. They took their payload, compressed and encrypted it, and
> wrapped it in a stub that decrypts at runtime. Your job starts by
> peeling off that wrapper. Only then do you see the actual program."
>
> — Ghost

---

## Goals

Understand what a packer does and why malware authors use them.
Detect packing through section entropy, section names, and missing imports.
Understand the structure of a packing stub and how it decrypts the payload.
Set up for manual unpacking (Day 452).

**Prerequisites:** Days 438–439 (PE and ELF format), Day 440 (algorithm recognition).
**Time budget:** 3–4 hours.

---

## Part 1 — What Packers Do

A packer takes an original executable (the **original program**) and produces a
new executable (the **packed binary**) that:

1. Contains the original program as compressed/encrypted data.
2. Contains a small **unpacking stub** that:
   - Allocates memory.
   - Decrypts/decompresses the original data.
   - Reconstructs the original program's structure (sections, imports).
   - Transfers control to the original entry point (OEP — Original Entry Point).

```
Packed EXE on disk:
  ┌─────────────────────────┐
  │ Unpacking stub (.text)  │ ← what the OS executes first
  │ Compressed/encrypted    │ ← the real program, hidden
  │ original program        │
  └─────────────────────────┘

At runtime:
  1. Stub decrypts payload into new memory
  2. Stub fixes up the IAT (import addresses)
  3. JMP to OEP → original program runs normally
```

---

## Part 2 — Why Malware Uses Packers

| Goal | How packing achieves it |
|---|---|
| AV evasion | Encrypted payload does not match static signatures |
| Analysis resistance | Analysts see stub code, not actual logic |
| Licence protection (legitimate) | Prevents easy decompilation of commercial software |
| Size reduction | UPX can reduce binary by 50–60% |

The same technology protects commercial software and hides malware. Context matters.

---

## Part 3 — Detecting Packed Binaries

### Signal 1: High Section Entropy

```bash
python3 << 'EOF'
import math
import pefile

pe = pefile.PE("sample.exe")
for section in pe.sections:
    name = section.Name.decode().rstrip('\x00')
    data = section.get_data()
    if not data: continue
    freq = [data.count(i)/len(data) for i in range(256) if data.count(i)]
    h = -sum(p*math.log2(p) for p in freq)
    print(f"{name:10} entropy: {h:.2f}")
EOF

# Unpacked binary:   .text = 5.5–6.5 (code), .rodata = 4–5
# Packed binary:     section entropy = 7.0–8.0 (encrypted data looks random)
```

### Signal 2: Missing or Minimal Imports

```bash
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        for i in e.imports:
            print(e.dll.decode(), '→', i.name.decode() if i.name else 'ordinal')
else:
    print('No import directory — almost certainly packed')
"
```

A packed binary may import only: `LoadLibrary`, `GetProcAddress`, `VirtualAlloc`,
`VirtualProtect` — the minimum needed to unpack itself.

### Signal 3: Unusual Section Names

```bash
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
for s in pe.sections:
    print(s.Name.decode().rstrip('\x00'))
"
# UPX: UPX0, UPX1, UPX2
# ASPack: .aspack, .adata
# Themida: .boot
# MPRESS: .MPRESS1, .MPRESS2
# Custom packers: random names or empty names
```

### Signal 4: Entry Point in an Unusual Section

```bash
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print(f'Entry point RVA: 0x{ep:x}')
for s in pe.sections:
    start = s.VirtualAddress
    end = start + s.Misc_VirtualSize
    if start <= ep < end:
        print(f'Entry in section: {s.Name.decode().rstrip(chr(0))}')
        break
"
# Entry in .text = normal
# Entry in UPX1, .boot, .adata = packed
```

---

## Part 4 — UPX: The Reference Packer

UPX (Ultimate Packer for eXecutables) is the most common and most reversible packer.

```bash
# Pack a binary
upx -9 -o packed.exe original.exe

# Unpack (trivially, because UPX is open-source)
upx -d -o unpacked.exe packed.exe

# Confirm:
file packed.exe    # shows UPX compressed
file unpacked.exe  # shows original binary type
```

### UPX Stub Structure

```
Packed PE:
  .text section (stub) — small, simple
  UPX0 section — zero-filled (placeholder for decompressed payload)
  UPX1 section — compressed original binary (high entropy)
  UPX2 section — original PE header backup

Stub execution:
  1. copy UPX1 → decompressed buffer
  2. run Lempel-Ziv decompression
  3. fix imports using GetProcAddress
  4. push original entry point address
  5. jmp to OEP
```

```bash
# In Ghidra, after importing a UPX binary:
# Look at the entry function in .text
# You will see: a tight loop (decompressor) ending with a JMP to OEP
# The OEP is often inside UPX0 after decompression
```

---

## Part 5 — Custom Packers: What to Look For

Custom packers vary, but the stub always does the same sequence:

```
1. Allocate memory (VirtualAlloc / mmap)
2. Decrypt payload (XOR loop, AES, RC4...)
3. Reconstruct PE headers (optional — only if it rebuilds a full PE)
4. Fix imports (loop calling GetProcAddress)
5. JMP to OEP
```

### Recognise the Decryption Loop

```asm
; XOR decryption loop (common in simple packers)
.decrypt_loop:
    movzx eax, byte ptr [esi]   ; read encrypted byte
    xor   al, bl                ; XOR with key byte
    mov   [edi], al             ; write decrypted byte
    inc   esi
    inc   edi
    add   bl, DELTA             ; key evolution (rolling key)
    dec   ecx
    jnz   .decrypt_loop
```

### Recognise the OEP Transfer

```asm
; At the end of the stub:
pop   eax          ; OEP from stack
push  ebx          ; saved registers for original entry
push  ebp
jmp   eax          ; jump to OEP (Original Entry Point)
```

The OEP jump is the end of the unpacking process. If you catch the program at
this point, the payload is fully decrypted in memory.

---

## Part 6 — Packer Detection Tools

| Tool | What it does |
|---|---|
| `PEiD` (Windows) | Identifies packer signatures |
| `Detect-It-Easy (DIE)` | Cross-platform packer/compiler detection |
| `ExeinfoPE` | PE packer identifier |
| `entropy.py` | Manual entropy analysis |

```bash
# Detect-It-Easy (Linux)
sudo apt install die
die sample.exe
# Output: "PE: [UPX] 3.96"
# Or: "PE: [MPRESS] 2.19"
# Or: "PE: Compiler: GCC (uncompressed)"
```

---

## Key Takeaways

1. Packed binaries show high section entropy (> 7.0), minimal imports, unusual
   section names, and an entry point outside `.text`.
2. UPX is trivially unpacked with `upx -d`. For everything else, you need to
   let the stub run and dump the process at the OEP (Day 452).
3. Every packing stub follows: allocate → decrypt → fix imports → JMP to OEP.
   Find the final JMP and you find the OEP.
4. The decryption loop is the most valuable code in a custom packer. Reversing
   it tells you the encryption algorithm — which may be the same algorithm used
   for C2 traffic.
5. Run `die` or `PEiD` as part of triage on every binary. Knowing it is packed
   before opening Ghidra saves you from reversing stub code thinking it is the
   actual program.

---

## Exercises

1. Pack `crackme1` (from Day 433) with UPX (`upx -9 -o packed_crackme crackme1`).
   Run the triage protocol. Confirm the entropy and section name signals.
   Then unpack with `upx -d` and confirm the entropy returns to normal.
2. Write a Python script that accepts a PE file and prints: section names,
   per-section entropy, and a flag if any section exceeds 7.0 entropy.
3. Open a UPX-packed binary in Ghidra without unpacking. Navigate to the entry
   point. Read the decompressor loop. Can you identify the compression algorithm?
4. Find a real malware sample on MalwareBazaar tagged "packed". Run `die` and
   your entropy script on it. Identify the packer.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q451.1, Q451.2 …).

---

## Navigation

← Previous: [Days 441–450 — RE Practice Labs](../07-RE-01/DAY-0441-RE-Practice-Labs.md)
→ Next: [Day 452 — Unpacking Lab](DAY-0452-Unpacking-Lab.md)
