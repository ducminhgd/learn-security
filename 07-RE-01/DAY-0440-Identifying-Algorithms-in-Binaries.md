---
title: "Identifying Algorithms in Binaries"
tags: [reverse-engineering, crypto-constants, compression, hashing, algorithm-recognition,
  yara]
module: 07-RE-01
day: 440
related_topics:
  - ELF Format Deep Dive (Day 439)
  - Windows PE Format (Day 438)
  - RE Practice Labs (Days 441–450)
  - YARA rules (Day 404 concept)
---

# Day 440 — Identifying Algorithms in Binaries

> "You do not need to reverse every line of a 50,000-instruction binary.
> You need to find the part that matters. Crypto constants, compression
> signatures, and protocol parsers leave fingerprints. Recognise the
> fingerprint and you skip 90% of the reversal work."
>
> — Ghost

---

## Goals

Identify cryptographic algorithms by their constants and code patterns.
Recognise compression algorithm signatures.
Understand network protocol parser patterns.
Use YARA rules to automate algorithm detection across a malware corpus.

**Prerequisites:** Day 434 (reading assembly patterns), Day 439 (ELF format), Ghidra.
**Time budget:** 3–4 hours.

---

## Part 1 — Why Algorithm Recognition Matters

When you encounter a 200-function binary, you do not read all of it. You look for
the functions that:

1. Process your input or attacker-controlled data.
2. Implement crypto (because it protects the C2 channel or encrypts the payload).
3. Parse network traffic or file formats (because that is the attack surface).

Algorithm recognition lets you say: "This is RC4. This is Zlib. This is TLV
parsing" — and immediately understand a large block of code without reversing
every instruction.

---

## Part 2 — Cryptographic Constants

Cryptographic algorithms embed magic constants in their implementation. These are
computable, fixed values that appear in virtually every implementation.

### AES S-Box

AES uses a 256-byte substitution table (the S-box). It always starts with:

```
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
```

In Ghidra: Search → Memory → search for `63 7c 77 7b` as a byte sequence.
If found, the surrounding code is AES.

### SHA-256 Initial Hash Values

```c
// SHA-256 initial state constants (H0–H7)
0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
```

Search for `6a09e667` in the binary. Its presence confirms SHA-256.

### MD5 Initial Values

```c
0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
```

### SHA-1 Initial Values

```c
0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
```

Note: MD5 and SHA-1 share the first four constants. Check the fifth.

### RC4 Key Scheduling

RC4 has a recognisable key-scheduling loop:

```asm
; KSA (Key Scheduling Algorithm) — initialise S[256]
mov  ecx, 256
xor  eax, eax
.init_loop:
    mov  byte ptr [S+eax], al   ; S[i] = i
    inc  eax
    loop .init_loop

; PRGA (Pseudo-Random Generation Algorithm)
; Recognisable by: byte swap with S[j], j = (j + S[i] + key[i%len]) % 256
```

### CRC32 Table

CRC32 uses a pre-computed 256-entry lookup table. The first entry is `0x00000000`
and the second is `0x77073096`.

```bash
strings binary | grep -c "77073096"  # if in string form
# Or search for the bytes 96 30 07 77 in memory
```

---

## Part 3 — Finding Crypto with findcrypt / CAPA

### findcrypt3 (Ghidra plugin)

Findcrypt is a Ghidra script that scans for known cryptographic constants.

```
In Ghidra Script Manager → find "findcrypt"
Run it against the binary
→ Results window shows: "AES S-Box found at 0x00402000"
```

Install:
```bash
# Clone to Ghidra scripts directory
git clone https://github.com/d3v1l401/findcrypt-ghidra
# Place in ~/.ghidra/Scripts
```

### CAPA — Malware Capability Detection

CAPA from Mandiant maps binary capabilities to ATT&CK techniques and MBC
(Malware Behaviour Catalogue).

```bash
pip install capa
capa sample.exe
# Output:
# +-------------------------------------------------------------------+
# | ATT&CK Technique: T1573 — Encrypted Channel                      |
# |   crypto/RC4 via KSA                                              |
# | ATT&CK Technique: T1082 — System Information Discovery           |
# |   queries OS version                                              |
# +-------------------------------------------------------------------+
```

CAPA saves hours of manual analysis on malware samples.

---

## Part 4 — Compression Algorithm Signatures

### Zlib / DEFLATE

```
Magic bytes at start of compressed data: 0x78 0x9C (default compression)
  0x78 0x01 = low compression
  0x78 0xDA = best compression

ZLIB_MAGIC = b'\x78\x9c'  # search in file or memory dump
```

Code patterns:
```asm
; Recognise by: call to zlib exports
; inflateInit, inflate, deflateInit, deflate
; OR by the DEFLATE Huffman tables in .rodata
```

### LZ4

```
Magic: 0x04 0x22 0x4D 0x18
Frame header starts at offset 0 in LZ4 frames.
```

### UPX Packer

```
Section names: UPX0, UPX1, UPX2
Magic in header: "UPX!" at the end of the file
High entropy in UPX0/UPX1 sections
```

```bash
strings binary | grep UPX
# If you see UPX0/UPX1 or "UPX!" → packed with UPX
upx -d binary  # unpack it
```

---

## Part 5 — Protocol Parser Patterns

### TLV (Type-Length-Value) Parsers

Common in custom C2 protocols, binary file formats, and hardware protocols.

```asm
; Read tag (type)
movzx eax, byte ptr [buffer]
; Switch on tag
cmp   eax, 1
je    .handle_type_1
cmp   eax, 2
je    .handle_type_2
; Read length
mov   ecx, dword ptr [buffer+1]
; Copy value
lea   rsi, [buffer+5]
```

The jump table from a `switch(type)` on the tag field is the giveaway.

### HTTP Parser Patterns

```asm
; Look for string comparisons with HTTP method names
cmp   dword ptr [buf], 'TEG\0'    ; "GET "
je    .handle_get
cmp   dword ptr [buf], 'TSOP'     ; "POST" (little-endian)
je    .handle_post
```

Or: calls to `strncmp` with arguments "GET", "POST", "HTTP/1.1".

---

## Part 6 — YARA Rules for Algorithm Detection

```yara
rule AES_SBox {
    meta:
        description = "AES S-Box constant"
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition:
        $sbox
}

rule SHA256_Constants {
    meta:
        description = "SHA-256 initial hash values"
    strings:
        $h0 = { 67 E6 09 6A }  // 0x6a09e667 little-endian
        $h1 = { 85 AE 67 BB }  // 0xbb67ae85
    condition:
        $h0 and $h1
}

rule UPX_Packer {
    meta:
        description = "UPX packed binary"
    strings:
        $magic = "UPX!"
        $sec1  = "UPX0"
        $sec2  = "UPX1"
    condition:
        $magic or ($sec1 and $sec2)
}

rule RC4_KSA {
    meta:
        description = "RC4 KSA loop — 256-byte initialisation"
    strings:
        // xor eax, eax; mov [S+eax], al; inc eax — look for the pattern
        $ksa = { 31 C0 88 04 ?? 40 }  // approximate byte pattern
    condition:
        $ksa
}
```

```bash
yara aes_rule.yara sample.exe
```

---

## Part 7 — Finding Algorithms: A Decision Tree

```
Is there a call to an external crypto library? (OpenSSL, CryptAPI)
  Yes → read the API arguments to know the algorithm
  No → look for constants

Are there large arrays in .rodata?
  256 bytes → potential S-box or CRC table
  1024+ bytes → Huffman table, large lookup

Does the binary have high-entropy sections?
  Yes → packer, encryption, or compressed payload

Are there loops with XOR + rotation?
  rotation by 7, 12, 17, 22 → MD5
  rotation by 2, 13, 22, etc. → SHA-256
  simple XOR with a short key → XOR cipher or RC4 PRGA

Call to 'inflate' or 'deflate'?
  Yes → zlib/DEFLATE compression
```

---

## Key Takeaways

1. Crypto algorithms leave fixed constants. Learn the most common ones (AES
   S-box, SHA-256 IV, MD5 IV) and you can identify 80% of binary crypto use.
2. CAPA and findcrypt automate most algorithm identification. Run them first;
   manual analysis confirms what they find.
3. UPX packing is detectable by section names and the "UPX!" signature. Always
   check for packers before spending hours reversing encrypted payload code.
4. TLV parsers signal custom protocols. The `switch(type)` jump table is the
   parser's skeleton — map it to understand the protocol.
5. YARA rules operationalise your algorithm recognition: once you identify a
   pattern, you can scan hundreds of samples for the same pattern in seconds.

---

## Exercises

1. Install findcrypt in Ghidra. Run it against a binary that calls OpenSSL.
   Confirm it identifies the crypto algorithm correctly.
2. Write a YARA rule that detects the first 16 bytes of the AES S-box. Test it
   against a binary that uses AES (e.g., an OpenSSL test binary).
3. Run CAPA against three malware samples from MalwareBazaar (in a VM). Map
   the identified capabilities to MITRE ATT&CK techniques.
4. Find a binary that uses CRC32. Locate the lookup table in Ghidra. Read the
   first four entries. Verify they match the known CRC32 polynomial table.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q440.1, Q440.2 …).

---

## Navigation

← Previous: [Day 439 — ELF Format Deep Dive](DAY-0439-ELF-Format-Deep-Dive.md)
→ Next: [Days 441–450 — RE Practice Labs](DAY-0441-RE-Practice-Labs.md)
