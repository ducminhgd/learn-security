---
title: "Bug Class Deep Dive — Type Confusion (CWE-843)"
tags: [vulnerability-research, type-confusion, cwe-843, c-plus-plus, javascript,
  cve-2021-30551, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 671
prerequisites:
  - Day 663 — Bug Class: UAF and Heap Corruption
  - Day 662 — Bug Class: Integer Overflow and Format String
related_topics:
  - Day 672 — Type Confusion Lab
  - Day 392 — Use-After-Free (adjacent bug class)
---

# Day 671 — Bug Class: Type Confusion (CWE-843)

> "A type confusion bug is the program saying 'this memory is a Cat' when
> the attacker has arranged for it to actually contain a Dog. If a Cat has
> a function pointer at offset zero and a Dog has an integer at offset zero,
> the program just called an integer as a function. That is code execution.
> And the underlying reason is always the same: a cast or a union or a
> tagged type check that the programmer got wrong."
>
> — Ghost

---

## Goals

Understand how type confusion vulnerabilities occur, where they appear,
how they are exploited, and how to find them in code audits. Tie each
concept to a real CVE.

**Prerequisites:** Days 662, 663.
**Estimated study time:** 3–4 hours.

---

## The Attack

### Type Confusion — CWE-843 / ATT&CK T1203 (Client Execution)

**What it is:**
A program accesses memory using a type assumption that is wrong — the
memory object is of type A but the program treats it as type B, reading or
writing fields at incorrect offsets.

**Why it works:**
C and C++ do not enforce type safety at runtime. A pointer of type `Cat *`
is just an address; nothing stops you from casting it to `Dog *`. The CPU
will happily read `((Dog *)cat_ptr)->integer_field` even though that memory
contains a vtable pointer. When the attacker controls what goes at the
confused address, they control what the program reads as a function pointer.

**How to spot it in the wild:**
```c
// PATTERN 1: unsafe cast through a void pointer
void *obj = get_object(id);
SomeType *s = (SomeType *)obj;   // if obj is actually OtherType, UB / crash / exploit

// PATTERN 2: union abuse — accessing the wrong union member
union Value {
    double as_double;
    void  *as_pointer;
};
union Value v;
v.as_double = attacker_controlled_double;  // write double
exec(v.as_pointer);                        // read back as pointer → controlled address

// PATTERN 3: tagged type without validation
struct Object {
    uint8_t  type;     // 0 = integer, 1 = string, 2 = function
    uint64_t value;
};
// Bug: code checks obj->type == 1 but does not re-check after modification
// If attacker can flip obj->type = 2 after the check, the value is treated
// as a function pointer

// PATTERN 4: C++ virtual dispatch after incorrect downcasting
Base *b = get_from_pool(id);
Derived *d = static_cast<Derived *>(b);   // if b is actually DerivedOther,
d->dangerous_method();                     // calls wrong vtable slot
```

**Minimal exploit (conceptual):**
```c
// Vulnerable structure layout:
struct Cat { void (*meow)(void); int lives; };
struct Dog { int bones; int legs; };

// Cat.meow is at offset 0 (function pointer)
// Dog.bones is at offset 0 (integer — attacker-controlled)

// Confusion exploit:
struct Dog *dog = attacker_allocate();
dog->bones = (int)(uintptr_t)&evil_function;  // write shellcode address at offset 0

struct Cat *confused_cat = (struct Cat *)dog;  // type confusion
confused_cat->meow();                          // calls evil_function ← code execution
```

**Real-world case:**
CVE-2021-30551 — Chrome V8 Type Confusion (June 2021).
V8's TurboFan JIT compiler produced code that confused a `JSObject` with
a `JSArray`. The JIT assumed an object was a packed Smi array (small
integers), but the object had been changed to contain heap pointers. Reading
a heap pointer as a Smi and then using it as an array index produced an
out-of-bounds read, giving the attacker an infoleak. Chained with a
second bug, this led to renderer process RCE. Actively exploited in the
wild before the patch. CVSS 8.8 (High).

**Detection:**
- ASAN's `-fsanitize=type` (UBSan TypeSanitizer) catches bad casts at runtime.
- Clang's `-fno-sanitize-recover` with `-fsanitize=vptr` catches bad virtual
  dispatch in C++.
- Static: look for explicit `static_cast<Derived*>` without a preceding
  `dynamic_cast` or tag check.
- Fuzzers with type-aware harnesses (libFuzzer + structure-aware mutations)
  find these via crash.

**Fix:**
Validate the type tag before using the object as the assumed type. In C++,
use `dynamic_cast` with a null check instead of `static_cast`:
```cpp
// Vulnerable:
Derived *d = static_cast<Derived *>(base_ptr);

// Fixed:
Derived *d = dynamic_cast<Derived *>(base_ptr);
if (d == nullptr) {
    // handle error: object is not of type Derived
    return;
}
```
Or use a discriminated union/tagged type with an enforced invariant.

---

## Type Confusion in JavaScript Engines

JavaScript engines are the richest surface for type confusion because they
must track dozens of object types efficiently. TurboFan, SpiderMonkey, and
JavaScriptCore all have CVE histories dense with type confusion bugs.

### The JIT Optimisation Pattern

```
HOW TYPE CONFUSION ARISES IN JIT COMPILERS

1. JavaScript code is interpreted first. The engine observes types.
2. The JIT specialises the code for the observed types (e.g., "this
   variable is always a 32-bit integer").
3. An attacker crafts code that:
   a. Causes the JIT to specialise for type A
   b. Then provides type B at the specialised code path
4. The JIT code executes without a type re-check (it was "optimised away")
5. Type B's data layout is interpreted as type A → type confusion

EXAMPLE PATTERN:
  function f(arr) {
      for (let i = 0; i < 1000; i++) f([1, 2, 3]);   // warm up: JIT specialises arr as packed int array
      f({"0": {evil: true}});                          // now pass an object
      // JIT reads .length as if it's an array → reads object properties as int → type confusion
  }
```

---

## Finding Type Confusion in C/C++ Source Audits

### High-Risk Patterns to Search

```bash
# 1. Explicit casts through void pointer
grep -rn "(void \*)" --include="*.c" --include="*.cpp" . | \
  grep -v "malloc\|calloc\|free\|printf" | head -20

# 2. static_cast<Derived*> without preceding dynamic_cast
grep -rn "static_cast<" --include="*.cpp" . | \
  grep -v "const_cast\|reinterpret_cast" | head -30

# 3. Union member access patterns (reading different member than was written)
grep -B5 -A5 "\.as_\|union " --include="*.c" --include="*.h" -rn . | head -50

# 4. Tagged type checks — tag is checked but object is used after modification window
grep -rn "->type\|->kind\|->tag\|obj_type\|type_id" \
     --include="*.c" --include="*.cpp" . | head -30

# 5. C-style casts (always suspicious in C++)
grep -rn "(\(struct \|(\(const \)\?[A-Z][A-Za-z]*\s*\*\))" \
     --include="*.cpp" . | head -20
```

---

## CVE Walkthrough: CVE-2021-30551 (Chrome V8)

### Key Facts

| Field | Value |
|---|---|
| Product | Chromium — V8 JavaScript Engine |
| Version | Before 91.0.4472.101 |
| Class | Type Confusion in TurboFan JIT |
| CVSS | 8.8 (High) |
| Exploited | Yes — in the wild before patch |
| Patch date | 2021-06-09 |

### The Mechanism (Simplified)

```
1. Attacker creates a JavaScript array arr = [1, 2, 3] (PACKED_SMI_ELEMENTS)
2. JIT compiles a function using arr, specialised for Smi (small integer) elements
3. Attacker calls Array.prototype.shift() to change the internal structure
   of arr from PACKED_SMI_ELEMENTS to HOLEY_ELEMENTS
4. The JIT-compiled code still treats arr as PACKED_SMI_ELEMENTS
5. Reading arr[i] now returns heap pointers instead of Smis
6. Attacker uses these heap pointers as indices → out-of-bounds read
7. OOB read → memory layout leak → full sandbox escape via second bug

KEY: The JIT removed the type check assuming the type would not change.
     The attacker changed the type through a side channel (shift()).
```

### Why This Pattern Recurs

```
THE FUNDAMENTAL TENSION

JIT compilers are fast because they make assumptions about types.
Type assumptions produce specialised code without type checks.
Type checks are exactly what prevents type confusion.
Therefore: JIT optimisation and type confusion share the same root.

The fix is to add a check at the JIT deoptimisation path — a "guard" that
validates the type assumption has not been violated. If it has, the JIT
falls back to interpreted mode. Chrome's fix added such a guard.
```

---

## Type Confusion in Parsers

Not just JS engines — file format parsers frequently have type confusion
when the same code path handles multiple object types.

```c
// Simplified example from a hypothetical document parser
typedef enum { TYPE_INT, TYPE_STRING, TYPE_ARRAY, TYPE_OBJECT } ValueType;

struct Value {
    ValueType type;
    union {
        int64_t     as_int;
        char       *as_string;
        struct Array  *as_array;
        struct Object *as_object;
    } data;
};

void process_value(struct Value *v) {
    // BUG: type is checked here, but v might be mutated from another
    // thread or via a reference alias before data is accessed
    if (v->type == TYPE_STRING) {
        size_t len = strlen(v->data.as_string);  // what if v->type was changed to TYPE_INT
                                                  // between the check and this line?
        // TOCTOU type confusion: between check and use, type changed
        // v->data.as_int (which could be 0xDEADBEEF) is now read as a pointer
    }
}
```

---

## Key Takeaways

1. **Type confusion = wrong type, same address.** The vulnerability is
   always some code reading memory with the wrong type assumption. That
   wrong assumption is always the result of a cast, a union read, or an
   absent/bypassed tag check. Every type confusion CVE reduces to one of
   these three patterns.
2. **JIT engines are the richest hunting ground.** V8, SpiderMonkey, and
   JavaScriptCore have produced hundreds of type confusion CVEs because
   the entire performance model is based on type specialisation. If you
   want to research browser security, study how JIT guards work and how
   they can be bypassed.
3. **static_cast without dynamic_cast is a code smell.** In C++, if you
   need to downcast a base pointer to a derived pointer and you are not
   using `dynamic_cast` with a null check, you are trusting the caller
   to be correct. In a security context, the caller may not be.
4. **UBSan catches this class of bug.** Building with
   `-fsanitize=undefined,vptr` will catch bad casts and incorrect virtual
   dispatch at runtime in C++. If your codebase has never been run with
   UBSan, it very likely has type confusion bugs waiting to be found.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q671.1, Q671.2 …).

---

## Navigation

← Previous: [Day 670 — Audit Campaign Day 5: Finding Report](DAY-0670-Audit-Campaign-Finding-Report.md)
→ Next: [Day 672 — Type Confusion Lab](DAY-0672-Type-Confusion-Lab.md)
