---
title: "Windows PE Format"
tags: [reverse-engineering, PE, windows, headers, imports, exports, TLS-callbacks, sections]
module: 07-RE-01
day: 438
related_topics:
  - ELF Format Deep Dive (Day 439)
  - Frida for Reverse Engineering (Day 437)
  - Identifying Algorithms in Binaries (Day 440)
---

# Day 438 — Windows PE Format

> "You will meet Windows binaries. Malware ships as PE files. Crackmes run
> on Windows. Knowing the PE format is knowing the terrain before you enter.
> The Import Address Table is the map of every library function the binary
> uses. Start there."
>
> — Ghost

---

## Goals

Understand the structure of a Windows PE (Portable Executable) file.
Identify key PE headers and what they reveal about a binary's behaviour.
Read the Import Address Table (IAT) to enumerate library dependencies.
Understand TLS callbacks as a pre-main execution point.

**Prerequisites:** ELF format concepts (Day 439 — read this alongside Day 439
for comparison), Ghidra basics.
**Time budget:** 3–4 hours.

---

## Part 1 — PE File Layout

```
PE File on Disk:
┌──────────────────────────────────┐
│ DOS Header (64 bytes)            │ ← "MZ" magic (0x4D5A)
│   e_lfanew: offset to PE header  │
├──────────────────────────────────┤
│ DOS Stub (variable)              │ "This program cannot be run..."
├──────────────────────────────────┤
│ PE Signature (4 bytes)           │ "PE\0\0" (0x50450000)
├──────────────────────────────────┤
│ COFF File Header (20 bytes)      │ Machine type, section count, timestamp
├──────────────────────────────────┤
│ Optional Header (224/240 bytes)  │ Entry point, image base, section alignment
│   Data Directories (128 bytes)   │ Pointers to IAT, export table, resources...
├──────────────────────────────────┤
│ Section Table                    │ One 40-byte entry per section
├──────────────────────────────────┤
│ .text   section                  │ Executable code
│ .rdata  section                  │ Read-only data (strings, constants)
│ .data   section                  │ Read/write global data
│ .idata  section                  │ Import tables (IAT)
│ .rsrc   section                  │ Resources (icons, dialogs, manifests)
│ .reloc  section                  │ Base relocation table
│ (custom sections as needed)      │
└──────────────────────────────────┘
```

---

## Part 2 — DOS Header and PE Signature

```
Offset 0x00: e_magic = 0x5A4D ("MZ") → identifies a PE file
Offset 0x3C: e_lfanew → 4-byte offset to the PE signature

At e_lfanew:
  "PE\0\0" (0x50450000) — the PE signature
  Followed immediately by the COFF header
```

**Why attackers care:**
- Malware checkers look for "MZ" at offset 0. Packers may shift this.
- `e_lfanew` can be forged to confuse parsers.
- The DOS stub can carry payload bytes that anti-virus parsers skip.

---

## Part 3 — COFF File Header

```
Machine:         0x8664 = AMD64, 0x014C = x86, 0xAA64 = ARM64
NumberOfSections: section count
TimeDateStamp:   compile time (often forged in malware)
SizeOfOptionalHeader
Characteristics: 0x0002 = executable, 0x2000 = DLL
```

```bash
# Read PE header with Python
python3 -c "
import struct, sys
data = open('sample.exe','rb').read()
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
machine = struct.unpack_from('<H', data, e_lfanew+4)[0]
nsections = struct.unpack_from('<H', data, e_lfanew+6)[0]
ts = struct.unpack_from('<I', data, e_lfanew+8)[0]
print(f'PE at: 0x{e_lfanew:x}')
print(f'Machine: 0x{machine:x}')
print(f'Sections: {nsections}')
import datetime
print(f'Timestamp: {datetime.datetime.fromtimestamp(ts)}')
"
```

---

## Part 4 — Optional Header and Entry Point

```
AddressOfEntryPoint: RVA of the first instruction executed
ImageBase:           preferred load address (0x140000000 for 64-bit DLL/EXE)
SectionAlignment:    alignment in memory (usually 0x1000)
FileAlignment:       alignment on disk (usually 0x200)
```

**Entry point note:** `AddressOfEntryPoint` points to the CRT startup code, not
`main()`. The CRT calls `main()`. In Ghidra, follow the entry point to find the
`WinMain` or `main` call.

**TLS Callbacks** (more below) execute BEFORE `AddressOfEntryPoint`.

---

## Part 5 — Import Address Table (IAT)

The IAT is the most useful table for initial analysis. It tells you every
external function the binary calls.

### Structure

```
Import Directory Table:
  For each DLL imported:
    OriginalFirstThunk → INT (Import Name Table) → function names
    Name              → DLL name string
    FirstThunk        → IAT → runtime function addresses (filled by loader)
```

### Reading the IAT

```bash
# Using dumpbin (Windows, with Visual Studio)
dumpbin /imports sample.exe

# Using Python (cross-platform, manual parsing)
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f'DLL: {entry.dll.decode()}')
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else f'ordinal_{imp.ordinal}'
        print(f'  {name}')
"
```

### What the IAT Tells You

| Import found | Implies |
|---|---|
| `CreateRemoteThread`, `VirtualAllocEx` | Process injection |
| `RegSetValueEx`, `RegOpenKeyEx` | Registry persistence |
| `InternetOpen`, `HttpSendRequest` | Network C2 communication |
| `CryptEncrypt`, `CryptDecrypt` | Payload encryption |
| `CreateService`, `OpenSCManager` | Service-based persistence |
| `IsDebuggerPresent` | Anti-debug present |
| `LoadLibrary`, `GetProcAddress` | Dynamic import resolution (evasion) |

---

## Part 6 — Export Table

DLLs export functions for other binaries to call. The export table maps names to
RVAs.

```bash
python3 -c "
import pefile
pe = pefile.PE('sample.dll')
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    name = exp.name.decode() if exp.name else f'ord_{exp.ordinal}'
    print(f'{name}: 0x{exp.address:x}')
"
```

**Malware use:** Custom malware DLLs often export a single function that is the
payload entry point. Finding it requires checking the export table.

---

## Part 7 — TLS Callbacks

Thread Local Storage (TLS) callbacks execute **before the entry point** — even
before the CRT startup code runs.

```
IMAGE_DIRECTORY_ENTRY_TLS → IMAGE_TLS_DIRECTORY
  AddressOfCallBacks → array of function pointers (terminated by NULL)
```

**Why attackers use TLS:**

1. Code at TLS callbacks runs before most debuggers break at the entry point.
2. Anti-debug checks placed in TLS callbacks fire before your first breakpoint.
3. Analysts who do not check TLS miss the first stage of execution.

```bash
# Find TLS callbacks with pefile
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    cb_addr = tls.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
    print('TLS callback RVA:', hex(cb_addr))
else:
    print('No TLS directory')
"
```

**In Ghidra:** Search → Program Text → "TLS_callback" or look at the TLS
section in the section list. Set a breakpoint BEFORE the entry point if
your debugger supports it (x64dbg does; GDB requires manual address finding).

---

## Part 8 — Tools for PE Analysis

| Tool | Platform | Best for |
|---|---|---|
| `pefile` (Python) | Cross-platform | Scripted parsing, IAT extraction |
| `pe-bear` | Windows/Linux | GUI PE viewer |
| `CFF Explorer` | Windows | Full PE editor |
| `dumpbin` | Windows | Quick headers/imports dump |
| `objdump -x` | Linux | Basic headers |
| `PE Studio` | Windows | Malware triage — VirusTotal integration |
| Ghidra | Cross-platform | Full analysis |

---

## Key Takeaways

1. The IAT is the fastest way to understand what a PE binary does. Import list
   → behaviour inference in 60 seconds.
2. TLS callbacks run before the entry point. Anti-debug code placed there will
   fire before your debugger breaks at `main`. Always check for TLS.
3. The timestamp in the COFF header is often forged by malware. Do not trust it
   for attribution without corroboration.
4. `LoadLibrary` + `GetProcAddress` in the IAT means the binary resolves imports
   dynamically — the static IAT does not show the real import list. Dynamic
   analysis is required.
5. PE sections with high entropy (> 7.0) in `.text` or unnamed sections indicate
   packing or encryption.

---

## Exercises

1. Install `pefile` (`pip3 install pefile`). Write a script that reads any
   `.exe` and prints all imported DLL names and functions. Run it on a Windows
   system binary (e.g., `notepad.exe`).
2. Find a packed binary (UPX is common — `upx sample.exe`). Run your entropy
   script. Compare the section entropy of the packed vs unpacked binary.
3. Search for TLS callbacks in a Windows malware sample from MalwareBazaar
   (use a sandboxed VM). Note whether TLS is present.
4. Compare the IAT of a clean binary and the same binary after injecting a DLL.
   What new entries appear?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q438.1, Q438.2 …).

---

## Navigation

← Previous: [Day 437 — Frida for Reverse Engineering](DAY-0437-Frida-for-Reverse-Engineering.md)
→ Next: [Day 439 — ELF Format Deep Dive](DAY-0439-ELF-Format-Deep-Dive.md)
