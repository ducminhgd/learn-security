---
title: "Advanced YARA Rule Engineering"
tags: [yara, malware-detection, threat-hunting, rule-writing, pe-analysis,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 690
prerequisites:
  - Day 619 — Malware Report Writing
  - Day 643 — Memory Forensics: Malware Detection
related_topics:
  - Day 700 — Module 10 Competency Check
  - B-04 — Endpoint Detection
---

# Day 690 — Advanced YARA Rule Engineering

> "A one-line YARA rule that catches 80% of a malware family in production
> is worth more than a perfect rule that only fires in a lab. But a rule
> that creates 50 false positives for every true positive is worse than
> no rule at all — it trains your SOC to ignore alerts. Precision beats
> recall every time when your analysts have a finite attention span."
>
> — Ghost

---

## Goals

Write YARA rules that use PE header fields, byte patterns, and module
extensions (`pe`, `math`, `hash`) to detect malware with high precision.
Understand rule performance tuning. Build a malware family signature set
with zero false positives against a clean corpus.

**Prerequisites:** Days 619, 643.
**Estimated study time:** 3 hours.

---

## 1 — YARA Architecture Review

A YARA rule has four sections:

```yara
rule RuleName {
    meta:        /* informational — not used for matching */
    strings:     /* patterns to find in the file/memory */
    condition:   /* boolean expression that must be true to match */
}
```

The condition is the key. `all of them` is the simplest condition; complex
rules combine string matches with PE header fields, file size constraints,
entropy calculations, and hash checks.

---

## 2 — PE Module: Structural Signatures

The `pe` module exposes parsed PE header fields. Use it to match on
characteristics that survive string obfuscation.

```yara
import "pe"

rule AgentTesla_PE_Characteristics {
    meta:
        author      = "Ghost"
        description = "AgentTesla infostealer — PE characteristics"
        tlp         = "WHITE"

    strings:
        /* .NET string from assembly metadata */
        $str_namespace = "AgentTesla" nocase wide ascii

        /* SMTP credential theft pattern — survives mild obfuscation */
        $str_smtp1 = "smtp" nocase wide ascii
        $str_smtp2 = "587" ascii

        /* Keylogger string — common across variants */
        $str_kl    = { 4B 00 65 00 79 00 4C 00 6F 00 67 00 }  /* "KeyLog" UTF-16LE */

    condition:
        /* PE32 or PE32+ executable */
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and

        /* .NET assembly (CLR header present) */
        pe.number_of_sections >= 2 and
        pe.characteristics & pe.EXECUTABLE_IMAGE and
        pe.is_dotnet and

        /* Match on at least 2 of 4 strings */
        2 of ($str_*)
}
```

### 2.1 Useful PE Module Predicates

```yara
/* File size bounds (avoid matching on huge files or tiny stubs) */
filesize > 50KB and filesize < 2MB

/* Compilation timestamp — detect freshly compiled malware */
pe.timestamp > 1700000000  /* after November 2023 */

/* Check specific section name */
pe.sections[0].name == ".text"

/* PE import: function name match */
pe.imports("ws2_32.dll", "WSAConnect")
pe.imports("kernel32.dll", "VirtualProtect")

/* Number of imports — packers have very few */
pe.number_of_imports < 5

/* Rich header present (compiler fingerprint) */
pe.rich_signature.length > 0

/* Entry point section name */
pe.sections[pe.section_index(pe.entry_point)].name == "UPX1"

/* Overlay: data appended after the last section */
pe.overlay.offset > 0
```

---

## 3 — Math Module: Entropy Analysis

Packed or encrypted sections have high entropy (> 7.0 bits/byte). The `math`
module calculates Shannon entropy.

```yara
import "pe"
import "math"

rule Packed_High_Entropy_PE {
    meta:
        description = "PE with high-entropy sections — likely packed/encrypted"

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) : (
            math.entropy(pe.sections[i].raw_data_offset,
                         pe.sections[i].raw_data_size) > 7.0 and
            pe.sections[i].raw_data_size > 4096    /* ignore tiny sections */
        )
}
```

```yara
import "math"

rule Suspicious_High_Entropy_Whole_File {
    meta:
        description = "Whole-file entropy > 7.2 — dropper payload or obfuscated script"

    condition:
        math.entropy(0, filesize) > 7.2 and
        filesize < 5MB
}
```

---

## 4 — Hash Module: Imphash and Section Hashes

```yara
import "pe"
import "hash"

rule Cobalt_Strike_Default_Beacon {
    meta:
        description = "Cobalt Strike default Beacon DLL — imphash match"
        reference   = "https://labs.sentinelone.com/..."

    condition:
        uint16(0) == 0x5A4D and
        /* Imphash of unmodified Cobalt Strike default beacon */
        pe.imphash() == "23dac3f3c0b3e834e6d1ca1e0c45a17d"
}
```

```yara
import "hash"

rule Mirai_Hardcoded_Credential_Block {
    meta:
        description = "Mirai variant — MD5 of embedded credential block"

    strings:
        /* Credential block starts at a fixed offset in many Mirai builds */
        $cred_magic = { 72 6F 6F 74 00 78 63 }  /* "root\0xc..." */

    condition:
        $cred_magic and
        /* Optional: hash of the full credential section */
        hash.md5(@cred_magic, 256) == "a1b2c3d4e5f6..."
}
```

---

## 5 — Memory Scanning Rules

YARA can scan process memory (via Volatility or `yara -p PID`). Memory rules
look for in-memory strings and injected code.

```yara
rule Cobalt_Strike_Beacon_In_Memory {
    meta:
        description = "Cobalt Strike Beacon loaded in memory — config block"
        author      = "Ghost"

    strings:
        /* Default x64 shellcode stub header */
        $shellcode_x64 = {
            FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51
        }

        /* MZ header in unexpected memory region (reflective DLL) */
        $mz_in_rwx = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }

        /* Beacon metadata XOR key pattern */
        $config_marker = { 00 01 BE EF 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        /* Note: no PE header check — this is an in-memory rule */
        any of them
}
```

```yara
rule Injected_PE_In_Process_Memory {
    meta:
        description = "PE header in unexpected memory location — DLL injection"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0 and
        /* If running against memory dump: check for PE32+ signature */
        uint32(uint32(0x3C)) == 0x00004550
}
```

---

## 6 — Rule Performance Tuning

Bad YARA rules scan every byte of every file. Good ones pre-filter:

### 6.1 Anchored String Matching

```yara
/* BAD — searches entire file */
strings:
    $magic = { 4D 5A }

/* GOOD — checks only the first 2 bytes */
condition:
    $magic at 0
```

### 6.2 Use Conditions as Pre-Filters

```yara
/* Put cheap checks first — YARA short-circuits on AND */
condition:
    filesize < 5MB and           /* cheap — filesystem metadata */
    uint16(0) == 0x5A4D and      /* cheap — 2-byte read at offset 0 */
    pe.is_dotnet and             /* cheap — PE header field */
    $expensive_regex             /* expensive — only reached if above pass */
```

### 6.3 Rule Sets Over One-Big-Rule

```yara
/* One rule that catches the broad family */
rule AgentTesla_Broad {
    condition:
        /* broad indicators — higher recall, lower precision */
        ...
}

/* A second rule that applies only to confirmed hits */
rule AgentTesla_Confirmed : AgentTesla_Broad {
    condition:
        /* very specific indicators — high precision */
        AgentTesla_Broad and
        2 of ($specific_*)
}
```

---

## 7 — Lab: Build a Precision Rule Set

Use 3–5 samples from the same malware family (e.g., all `AsyncRAT` from
MalwareBazaar) and 100 clean executables.

```
YARA PRECISION LAB

Malware family: _______________________ (5 samples)
Clean corpus: _______________________ (100 binaries)

RULE v1 — String only:
  Rule text: ______________________________
  True positives (5/5 ideal): ______
  False positives (0/100 ideal): ______
  Precision: ______%

RULE v2 — Add PE module constraints:
  Changes made: ________________________________
  True positives: ______
  False positives: ______
  Precision: ______%

RULE v3 — Add entropy/imphash:
  Changes made: ________________________________
  True positives: ______
  False positives: ______
  Precision: ______%

FINAL RULE (paste):
```

---

## Key Takeaways

1. **PE module fields survive string obfuscation.** An attacker can change
   all strings in a binary. They cannot change the fact that it is a .NET
   assembly, imports `WSAConnect`, and has three sections with high entropy.
   Combine structural features with strings for robust detection.
2. **Entropy > 7.0 alone is not a rule — it is a lead.** Plenty of legitimate
   compressed files have high entropy. Combine with PE structure, imports, and
   specific byte patterns to get precision.
3. **Pre-filter in the condition to keep scan speed high.** A YARA rule that
   checks `filesize`, `uint16(0)`, and `pe.is_dotnet` before scanning for
   strings reduces the scanning domain from millions of bytes to hundreds.
4. **Test against a clean corpus before deploying.** A rule that matches
   `kernel32.dll` or `notepad.exe` is not a rule — it is noise. Every rule
   must pass a clean-corpus false-positive test before production deployment.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q690.1, Q690.2 …).

---

## Navigation

← Previous: [Day 689 — Anti-Analysis Techniques](DAY-0689-Anti-Analysis-Sandbox-Evasion.md)
→ Next: [Day 691 — Fuzzing Harness Engineering with libFuzzer](DAY-0691-libFuzzer-Harness-Engineering.md)
