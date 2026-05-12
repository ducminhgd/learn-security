---
title: "Day 732 — Windows Internals for Exploit Developers"
tags: [windows-internals, exploit-development, kernel-structures, handles,
  token-impersonation, nt-api, module-12-post-gate]
module: 12-PostGate
day: 732
prerequisites:
  - Day 731 — Career Path Planning
  - Day 406 — Windows Kernel Intro (Module 06)
  - Day 499 — Domain Dominance (Module 08)
related_topics:
  - Day 733 — Linux Kernel Exploitation
  - Day 734 — Hypervisor Security
---

# Day 732 — Windows Internals for Exploit Developers

> "Every Windows exploit eventually touches the NT kernel. Knowing the kernel
> structures — EPROCESS, ETHREAD, TOKEN, handles — is not optional knowledge
> for a serious Windows researcher. It is the language that the kernel speaks.
> If you cannot read it, you are working blind."
>
> — Ghost

---

## Goals

1. Understand the Windows NT executive model: kernel space vs. user space,
   objects, handles, and the object manager.
2. Navigate the EPROCESS and ETHREAD structures to understand process
   identity, privilege, and thread context.
3. Understand Windows security tokens: how TOKEN structures control privilege;
   how token duplication and impersonation work at the kernel level.
4. Use WinDbg to inspect live kernel structures and validate understanding.
5. Understand the exploiter's perspective: which structures, if modified,
   change security outcome.

---

## Prerequisites

- Days 406 (Windows Kernel Intro), 499 (Domain Dominance).
- Access to a Windows 10/11 VM with WinDbg and symbols installed.
- Kernel debugging enabled on the VM (or use local kernel debugging).

---

## 1 — The NT Executive Model

```
WINDOWS NT EXECUTIVE — LAYERS

User Mode (Ring 3):
  Applications → Win32 API → NTDLL.DLL (syscall stubs)
  ↓ (syscall instruction → transitions to kernel)

Kernel Mode (Ring 0):
  NT Executive (NTOSKRNL.EXE):
    ├── Object Manager    — tracks all kernel objects (processes, files, events)
    ├── Process Manager   — creates/destroys processes and threads
    ├── Memory Manager    — virtual memory, page tables, VAD tree
    ├── I/O Manager       — device driver communication
    ├── Security Reference Monitor (SRM) — enforces access control decisions
    ├── Cache Manager     — file system cache
    └── Plug-and-Play     — device enumeration

Hardware Abstraction Layer (HAL)
Hardware
```

Key insight for exploit developers: **the Security Reference Monitor makes
all security decisions** — but it relies on the TOKEN structure attached to
the current thread or process. Modify the TOKEN, and the SRM grants different
access.

---

## 2 — EPROCESS: The Process Object

Every running process has an EPROCESS structure in kernel memory. It contains
the complete state of the process, including its security token.

### 2.1 Key EPROCESS Fields

```c
// EPROCESS (simplified — Windows 11 offsets vary by build)
// Use WinDbg: dt nt!_EPROCESS to get exact offsets

typedef struct _EPROCESS {
    KPROCESS       Pcb;                 // kernel process block (scheduling)
    // ...
    HANDLE_TABLE  *ObjectTable;         // process handle table
    EX_FAST_REF    Token;               // TOKEN reference ← SECURITY TOKEN
    UNICODE_STRING ImageFileName;       // e.g., L"notepad.exe"
    LIST_ENTRY     ActiveProcessLinks;  // doubly-linked list of all processes
    ULONG_PTR      UniqueProcessId;     // PID
    // ...
} EPROCESS;
```

### 2.2 Walking EPROCESS with WinDbg

```
// Setup: enable kernel debugging on target VM
// Host WinDbg: File → Kernel Debug → Network or COM port

// In WinDbg:
lkd> dt nt!_EPROCESS          // show full structure with offsets
lkd> !process 0 0              // list all processes
lkd> !process 4 0              // System process (PID 4)

// Find lsass.exe (holds all domain credential hashes):
lkd> !process 0 0 lsass.exe
// Output: PROCESS ffffe00a`1234xxxx  ...
//   nt!_EPROCESS at address ffffe00a`1234xxxx

// Dump the EPROCESS of lsass.exe:
lkd> dt nt!_EPROCESS ffffe00a`1234xxxx Token
// Output: Token: 0xffffe00b`5678xxxx (EX_FAST_REF — low 4 bits are refcount)

// Extract the TOKEN address:
lkd> !token 0xffffe00b`5678xx00   // zero out low 4 bits
```

---

## 3 — TOKEN: The Security Object

The TOKEN structure is the kernel representation of a security principal's
identity and privileges. It determines:

- **Who** the process claims to be (user SID, group SIDs)
- **What** the process is allowed to do (privilege list)
- **Integrity level** (Low, Medium, High, System — Mandatory Integrity Control)

### 3.1 Key TOKEN Fields

```c
// TOKEN (simplified)
typedef struct _TOKEN {
    TOKEN_SOURCE    TokenSource;            // LsaLogon or NtProcessToken
    LUID            TokenId;
    LUID            AuthenticationId;       // logon session
    SID            *UserAndGroupCount;
    SID_AND_ATTRIBUTES *UserAndGroups;      // ← primary user SID + group SIDs
    LUID_AND_ATTRIBUTES *Privileges;        // ← privilege list (SeDebugPrivilege etc)
    ULONG           PrivilegeCount;
    // Integrity level stored in label SID:
    //   S-1-16-4096  = Low
    //   S-1-16-8192  = Medium
    //   S-1-16-12288 = High
    //   S-1-16-16384 = System
} TOKEN;
```

### 3.2 The Classic Token Steal Exploit Pattern

This is the kernel-level primitive that many Windows privilege escalation
exploits implement:

```c
// Pseudocode for token impersonation via EPROCESS walk
// (used in WriteProcessMemory-class kernel exploits)

// Step 1: Walk the ActiveProcessLinks list to find SYSTEM process (PID 4)
PEPROCESS system_proc = find_eprocess(4);        // PID 4 = System
QWORD     system_token = system_proc->Token.Value & ~0xF; // mask refcount bits

// Step 2: Find current process
PEPROCESS current_proc = PsGetCurrentProcess();

// Step 3: Overwrite current process token with SYSTEM token
current_proc->Token.Value = system_token;

// Step 4: Now running as SYSTEM in user space:
// - cmd.exe now shows NT AUTHORITY\SYSTEM
// - Can access LSASS memory
// - Can create services
// - Complete privilege escalation achieved
```

**Real CVEs using this pattern:**
- CVE-2021-34527 (PrintNightmare) — token steal after kernel write primitive
- CVE-2021-3156 (sudo, Linux equivalent) — privilege escalation pattern
- Many Windows LPE CVEs follow this exact EPROCESS walk → token replace flow

---

## 4 — Handles and the Object Manager

Every user-mode reference to a kernel object goes through a handle. Handles
are indices into per-process handle tables managed by the kernel.

### 4.1 Handle Table Structure

```
HANDLE TABLE STRUCTURE

Per-process: _HANDLE_TABLE at EPROCESS.ObjectTable
  → Array of _HANDLE_TABLE_ENTRY structures
  → Each entry: ObjectPointer (to _OBJECT_HEADER) + GrantedAccess

_OBJECT_HEADER → _EPROCESS / _ETHREAD / _TOKEN / _FILE_OBJECT / etc.

Exploiter interest:
  Handle tables can be duplicated (DuplicateHandle API)
  If kernel object address is known, handle value can sometimes be guessed
  Privileged handles (e.g., PROCESS_ALL_ACCESS to lsass) are the target
```

### 4.2 WinDbg Handle Inspection

```
// In WinDbg:
lkd> !handle 0 0 <pid>          // all handles for process PID
lkd> !object <object_address>   // inspect kernel object at address

// Find all process handles in the system:
lkd> !object \Sessions\1\BaseNamedObjects

// Specific handle type (find all open handles to lsass):
lkd> !handle 0 0 0 Process      // all Process handles system-wide
```

---

## 5 — Syscall Interface: NT API

User-mode exploits use the NT native API (NTDLL) to access kernel services.
Understanding which NT functions map to which kernel routines matters for
both exploitation and detection.

```
USER-MODE SYSCALL FLOW

Application calls:
  ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, ...)
  ↓ resolves to
  NTDLL!NtReadVirtualMemory
  ↓ MOV EAX, <syscall_number>  ; syscall numbers vary per OS build
    SYSCALL                    ; ring 3 → ring 0
  ↓ KiSystemCall64 (kernel dispatch)
  ↓ NtReadVirtualMemory (kernel implementation)

Key NT functions for exploit developers:
  NtAllocateVirtualMemory   → allocate memory (spraying, ROP staging)
  NtWriteVirtualMemory      → write to a process
  NtCreateSection           → map file into memory (shellcode execution)
  NtMapViewOfSection        → shared memory mapping
  NtDuplicateObject         → duplicate handle (privilege escalation)
  NtQuerySystemInformation  → kernel information disclosure (ASLR bypass)

Detection:
  EDR hooks NTDLL functions to intercept API calls
  Indirect syscalls bypass this by calling KiSystemCall64 directly
  (covered in Day 519 — Advanced Evasion)
```

---

## 6 — Lab: WinDbg EPROCESS Walk

Perform this exercise on your Windows VM with kernel debugging enabled:

```
WINDOWS INTERNALS LAB

SETUP:
  Target VM: Windows 10/11 with kernel debugging enabled
  Host: WinDbg with symbols loaded (sympath=srv*c:\symbols*https://msdl.microsoft.com/download/symbols)

TASK 1 — EPROCESS WALK:
  [ ] Run: !process 0 0  → locate lsass.exe EPROCESS address
  [ ] Run: dt nt!_EPROCESS <addr> Token → extract TOKEN address
  [ ] Run: !token <token_addr> → read token privileges
  [ ] Identify which privilege allows SeDebugPrivilege: Y / N (what is the value?)

TASK 2 — HANDLE TABLE:
  [ ] Find a process handle with PROCESS_ALL_ACCESS granted
      Command: !handle 0 0 <pid>
  [ ] Record: process name and handle value ___________________________

TASK 3 — SYSCALL NUMBER MAPPING:
  [ ] Find the syscall number for NtReadVirtualMemory:
      In WinDbg: ? nt!NtReadVirtualMemory  (for address)
      In NTDLL: u ntdll!NtReadVirtualMemory L5 → MOV EAX, <number>
  [ ] Syscall number: ____
  [ ] OS version: ____  (syscall numbers differ per build — document this)

TASK 4 — TOKEN INTEGRITY:
  [ ] Find notepad.exe EPROCESS
  [ ] Extract TOKEN address
  [ ] Find the integrity level SID in the token
  [ ] Label SID: S-1-16-_______ → Level: Low / Medium / High / System
```

---

## Key Takeaways

1. **EPROCESS.Token is the pivot point for Windows privilege escalation.**
   Every Windows local privilege escalation exploit that achieves SYSTEM
   ultimately modifies either the TOKEN structure or the privilege list
   within it. Understanding this structure makes every LPE CVE comprehensible.
2. **The Object Manager enforces access control at the kernel level.** User-
   mode security can be bypassed — but the kernel object manager validates
   access rights on every handle operation. A HANDLE to a process with
   PROCESS_ALL_ACCESS is the attacker's key to that process. Protecting LSASS
   from handle access is the purpose of Protected Process Light (PPL).
3. **Syscall numbers are build-specific — indirect syscalls are version-
   dependent.** Modern evasion techniques use direct syscalls to avoid NTDLL
   hooks. But syscall numbers change between Windows builds. Exploits and
   evasion tools must handle this dynamically.
4. **WinDbg is the ground truth.** When documentation, StackOverflow, and
   books disagree about Windows internals, WinDbg against a live kernel is
   always correct. Learning to navigate kernel structures in WinDbg is a
   career-long investment.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q732.1, Q732.2 …).

---

## Navigation

← Previous: [Day 731 — Career Path Planning](DAY-0731-Career-Path-Planning.md)
→ Next: [Day 733 — Linux Kernel Exploitation](DAY-0733-Linux-Kernel-Exploitation.md)
