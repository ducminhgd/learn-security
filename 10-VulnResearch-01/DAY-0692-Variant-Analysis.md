---
title: "Variant Analysis — From One CVE to a Bug Class Sweep"
tags: [variant-analysis, cve, code-audit, vulnerability-research, bug-class,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 692
prerequisites:
  - Day 656 — Patch Diffing and CVE Reproduction
  - Day 662 — Bug Class: Integer Overflow and Format String
  - Day 663 — Bug Class: UAF and Heap Corruption
related_topics:
  - Day 687 — CodeQL Taint Analysis
  - Day 700 — Module 10 Competency Check
---

# Day 692 — Variant Analysis: From One CVE to a Bug Class Sweep

> "The most efficient way to find bugs is to find the same bug twice.
> When a vendor patches CVE-2023-1234 — a heap overflow in the image
> decoder — your first question is not 'what else is in this codebase.'
> Your first question is 'does this same pattern exist in every other
> format they support?' It does. They patched one instance. You find
> all of them."
>
> — Ghost

---

## Goals

Understand the variant analysis workflow: start from one known CVE, extract
the root-cause pattern, and systematically search for the same pattern across
a codebase. Apply to a real CVE using grep, CodeQL, and manual review. Produce
a variant analysis report listing all confirmed and suspected variants.

**Prerequisites:** Days 656, 662, 663.
**Estimated study time:** 4 hours.

---

## 1 — What Variant Analysis Is

Variant analysis starts from a known vulnerability and asks:

> **"Does the same root-cause pattern exist elsewhere in the same codebase
> or related codebases?"**

It is the most productive activity after confirming a bug. Vendors typically
fix the reported instance; researchers who find variants earn additional CVEs
and bug bounty payouts for what is essentially follow-on work.

### The Three Variant Relationships

```
1. SAME FUNCTION, DIFFERENT CALL SITE
   The fix changes function foo(), but foo() is called from 5 other places
   with the same unsafe pattern.

2. SAME PATTERN, DIFFERENT COMPONENT
   The integer-before-malloc pattern is in image.c — is it also in audio.c,
   video.c, and document.c? Same library, same codebase, different files.

3. SAME PATTERN, RELATED PROJECT
   libpng fixed an integer overflow in row calculation. Does libqpdf, libtiff,
   or libjpeg have the same class of bug in their own row calculations?
```

---

## 2 — Variant Analysis Workflow

```
STEP 1: STUDY THE ORIGINAL CVE
  → Root cause (what exact C pattern caused the bug)
  → Fix (what line changed in the patch)
  → Location (file, function, subsystem)

STEP 2: EXTRACT THE PATTERN
  → Reduce to the minimal dangerous construct
  → Example: "uint32 multiplication of two user-supplied width/height values
    used as malloc() argument without overflow check"

STEP 3: GREP FOR THE PATTERN
  → Write a grep/ripgrep query targeting the dangerous construct
  → Cast wide first, then narrow by manual review

STEP 4: CODEQL / SEMGREP SWEEP
  → Write a targeted rule for the specific pattern
  → Run across the entire codebase

STEP 5: MANUAL TRIAGE
  → For each hit: is there a bounds check before the dangerous operation?
  → Is the value user-controlled?
  → Does the check actually work? (Off-by-one? Wrong direction?)

STEP 6: DOCUMENT VARIANTS
  → For each confirmed variant: file, line, function, CVE reference ("variant of"),
    exploitability assessment, fix recommendation
```

---

## 3 — Case Study: CVE-2023-EXAMPLE — libpng Integer Overflow

### 3.1 The Original CVE

```c
/* ORIGINAL VULNERABLE CODE (simplified) */
png_uint_32 width  = png_get_image_width(png_ptr, info_ptr);
png_uint_32 height = png_get_image_height(png_ptr, info_ptr);

/* BUG: width * height can overflow uint32 */
size_t row_bytes = width * png_get_bit_depth(png_ptr, info_ptr) / 8;
png_bytep *row_ptrs = (png_bytep *)malloc(height * sizeof(png_bytep));
for (png_uint_32 i = 0; i < height; i++) {
    row_ptrs[i] = (png_bytep)malloc(row_bytes);  /* overflow if row_bytes wraps */
}
```

**Fix:** The vendor added:
```c
if (width > PNG_UINT_32_MAX / png_get_bit_depth(png_ptr, info_ptr))
    png_error(png_ptr, "image too wide");
```

### 3.2 Extract the Pattern

```
PATTERN: user-supplied dimension values (width × depth) used in
         size calculation for malloc() without overflow check.

Root cause in one line:
  malloc(user_width * user_depth / 8)
  where user_width and user_depth are both read from untrusted file header.
```

### 3.3 Grep Sweep

```bash
# Find all multiplication operations near malloc calls
grep -rn --include="*.c" --include="*.cpp" \
    -E "malloc\s*\(.*\*" \
    /path/to/codebase | head -40

# More targeted: find multiplications of variables named *width*, *height*,
# *size*, *count*, *len* near malloc
grep -rn --include="*.c" -A2 -B2 \
    -E "(width|height|count|len|num|size)\s*\*\s*(width|height|count|len|num|size)" \
    /path/to/codebase | grep -i "malloc\|alloc\|new\b"

# Find places where BOTH dimensions are read from user input
# (requires manual inspection of the grep results)
grep -rn "read_u32\|fread\|png_get" /path/to/codebase | \
    grep -E "(width|height|stride|pitch|depth)" | head -20
```

### 3.4 CodeQL Sweep for the Pattern

```ql
/**
 * @name Integer overflow in size calculation before malloc
 *       (variant analysis for CVE-2023-EXAMPLE pattern)
 * @id cpp/variant-width-height-overflow
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking

/* Find: malloc(expr) where expr contains a multiply of two field reads */
from FunctionCall malloc_call, MulExpr mult, FieldAccess fa1, FieldAccess fa2
where
  malloc_call.getTarget().hasName(["malloc", "calloc", "realloc"]) and
  malloc_call.getArgument(0) = mult and
  (mult.getLeftOperand()  = fa1 or mult.getLeftOperand()  = fa2) and
  (mult.getRightOperand() = fa1 or mult.getRightOperand() = fa2) and
  /* Both field names suggest dimensions */
  (fa1.getTarget().getName().regexpMatch(".*[Ww]idth.*|.*[Hh]eight.*|.*[Cc]ount.*|.*[Ss]ize.*"))
select malloc_call, "Potential integer overflow: multiplying $@ by $@ for malloc",
  fa1, fa1.getTarget().getName(), fa2, fa2.getTarget().getName()
```

### 3.5 Variant Report

```
VARIANT ANALYSIS REPORT

Original: CVE-2023-EXAMPLE — libpng integer overflow in row allocation
Pattern:  malloc(user_width * user_depth) without overflow check

Variants found:
─────────────────────────────────────────────────────────────────────
#1 FILE: src/png_read.c  LINE: 847  FUNCTION: read_alpha_channel()
   user_width × channel_count → malloc argument
   Bounds check: MISSING
   User-controlled: YES (channel_count from IHDR)
   Status: CONFIRMED VARIANT
   Severity: Same as original — CWE-190, heap overflow

#2 FILE: src/png_write.c  LINE: 412  FUNCTION: create_row_buffer()
   row_width × pixel_depth → malloc argument
   Bounds check: PARTIAL — checks row_width but not pixel_depth
   User-controlled: YES (pixel_depth from sRGB chunk)
   Status: SUSPICIOUS — depth check missing

#3 FILE: src/png_transform.c  LINE: 223  FUNCTION: scale_image()
   src_width × scale_factor → destination malloc
   Bounds check: PRESENT — if (src_width > MAX_DIM) return
   User-controlled: YES
   Status: LIKELY FALSE POSITIVE — check covers the overflow

#4 FILE: contrib/tools/png2bmp.c  LINE: 89  FUNCTION: convert()
   width × height × 3 → malloc
   Bounds check: MISSING
   User-controlled: YES (from PNG header)
   Status: CONFIRMED VARIANT — different subsystem, same class
─────────────────────────────────────────────────────────────────────
Summary: 2 confirmed, 1 suspicious, 1 false positive
```

---

## 4 — Lab: Variant Hunt

**Target:** Choose a real CVE that has been publicly disclosed with a patch
(examples: CVE-2022-1304, CVE-2022-0529, CVE-2021-44832). Find the patch.

```
VARIANT ANALYSIS LAB

CVE chosen: _______________________
Project: __________________________
Root cause (one sentence): ________________________________________
Dangerous pattern (code snippet):
  _______________________________________________________________

Grep query 1: ____________________________________________________
  Hits: ______  False positives (manual review): ______
  Confirmed variants: ______

CodeQL/Semgrep query:
  Written: Y / N
  Hits: ______
  New variants not found by grep: ______

VARIANT REPORT:
  Variant 1: File: __________ Line: _____ Status: ________________
  Variant 2: File: __________ Line: _____ Status: ________________
  Variant 3: File: __________ Line: _____ Status: ________________

FINDINGS SUMMARY:
  Total confirmed variants: ______
  Would you file these as separate CVEs? Y / N
  Justification: ______________________________________________
```

---

## Key Takeaways

1. **Vendors fix instances, not classes.** A vendor receives one CVE, patches
   one function, and closes the ticket. Variant analysis reveals that the same
   root cause exists in 3–7 other places in the same codebase. These are
   separate, independently patchable vulnerabilities.
2. **Extract the pattern before searching.** Do not start grepping until you
   can describe the root cause in one sentence: "uint32 multiplication of two
   user-controlled values used as malloc argument without overflow check." The
   grep query follows from that sentence.
3. **False positive rate is your biggest enemy.** A grep that returns 200 hits
   requires 200 manual reviews. Narrow with CodeQL taint tracking before
   manual review. Invest 30 minutes in a targeted query to save 3 hours of
   manual triage.
4. **Related projects are in scope.** If libpng has a width × height overflow,
   check libtiff, libjpeg, and libwebp. They solve the same problem with the
   same patterns. The vulnerability class transfers across projects even when
   the source code is entirely independent.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q692.1, Q692.2 …).

---

## Navigation

← Previous: [Day 691 — libFuzzer Harness Engineering](DAY-0691-libFuzzer-Harness-Engineering.md)
→ Next: [Day 693 — Reading NVD Entries and CVE Descriptions as an Attacker](DAY-0693-NVD-CVE-Reading-as-Attacker.md)
