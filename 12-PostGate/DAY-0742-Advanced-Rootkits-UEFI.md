---
title: "Day 742 — Advanced Rootkits and UEFI Implants"
tags: [rootkits, uefi, firmware, persistence, bootkit, cosmicstrand,
  lojax, secure-boot, module-12-post-gate]
module: 12-PostGate
day: 742
prerequisites:
  - Day 741 — Security Research Publication
  - Day 646–647 — Advanced Persistence Bootkits (Module 10)
  - Day 701 — Hardware Security: UART and JTAG
related_topics:
  - Day 743 — Cloud-Native Security
---

# Day 742 — Advanced Rootkits and UEFI Implants

> "A rootkit that lives in the OS can be removed by reinstalling the OS.
> A rootkit that lives in a driver can be removed by reimaging. A rootkit
> that lives in the UEFI firmware survives any of these. It survives disk
> replacement. It persists across Secure Boot — if Secure Boot is
> misconfigured. The most sophisticated threat actors in the world use UEFI
> implants because they provide persistence that nothing short of physical
> flash replacement can defeat."
>
> — Ghost

---

## Goals

1. Understand UEFI firmware architecture: DXE drivers, SMM, PEI, and the
   Boot Services/Runtime Services distinction.
2. Analyse the LoJax UEFI implant (first in-the-wild UEFI rootkit) at the
   technical level.
3. Understand CosmicStrand and MoonBounce — more advanced 2022 UEFI implants.
4. Use UEFITool and CHIPSEC to analyse and audit UEFI firmware images.
5. Understand Secure Boot and its bypass conditions.

---

## Prerequisites

- Days 646–647 (bootkit analysis), Day 701 (SPI flash dump).
- UEFITool, CHIPSEC installed in a lab VM.

---

## 1 — UEFI Firmware Architecture

```
UEFI FIRMWARE BOOT PHASES

Phase 1 — SEC (Security):
  First code to execute after power-on
  Minimal; initialises CPU and temporary RAM (CAR — Cache As RAM)
  Establishes trust root for following phases

Phase 2 — PEI (Pre-EFI Initialization):
  Initialises DRAM (memory comes online here)
  Finds and verifies DXE firmware volume
  PEI modules (PEIMs) run here — extremely privileged

Phase 3 — DXE (Driver Execution Environment):
  UEFI drivers load and register with the system table
  Boot Services active: memory allocation, protocol publishing
  Most UEFI attack surface is in DXE drivers

Phase 4 — BDS (Boot Device Selection):
  Boot options enumerated; user can enter setup
  Secure Boot verification happens HERE before OS loader

Phase 5 — TSL (Transient System Load):
  OS bootloader (Windows Boot Manager, GRUB) runs
  Verified by Secure Boot

Phase 6 — RT (Runtime):
  OS takes over; only Runtime Services remain available
  SMM (System Management Mode) persists across OS runtime

ATTACKER INTEREST:
  DXE drivers: modify/replace to inject rootkit code
  SMM: code in SMM runs at privilege level above Ring 0
       invisible to OS, hypervisor, and all security tools
  Runtime Services: hook GetVariable/SetVariable to intercept boot data
```

---

## 2 — LoJax: First In-the-Wild UEFI Rootkit

```
LOJAX — ESET ANALYSIS (2018)

ACTOR: Fancy Bear (APT28, Russian GRU)
FIRST OBSERVED: 2017 (operation; disclosed 2018)

HOW IT WORKS:
  Step 1: COMPROMISE — APT28 obtained access to the target's Windows system
  Step 2: DUMP — custom tool (using RWDrv.sys) read the SPI flash chip
           using the privileged driver interface (bypassing OS protections)
  Step 3: MODIFY — injected a malicious DXE module into the firmware image
           The injected module is small (4KB): it writes a Windows user-mode
           malware executable to disk on every boot BEFORE Windows loads.
  Step 4: FLASH — wrote the modified firmware image back to the SPI flash chip
  Step 5: PERSISTENCE — even after OS reinstall, the malicious DXE module
           recreates the Windows malware on every boot.

DETECTION EVASION:
  UEFI DXE modules run before any OS-level security tool
  Windows Defender, EDR, and all user-space security tools do not run yet
  Even Secure Boot did not catch it: the firmware modification happened before
  Secure Boot could verify — the image itself was modified, and Secure Boot
  only verifies the OS bootloader, not DXE modules (unless UEFI Secure Boot
  also verifies DXE drivers, which most systems do not configure)

IMPACT:
  Survived full OS reinstall
  Survived hard drive replacement
  Only removal: reflash the motherboard BIOS chip (physical or via BIOS update)
```

---

## 3 — CosmicStrand and MoonBounce (2022)

```
COSMICSTRAND — KASPERSKY (2022)

ACTOR: Chinese-aligned, unattributed
PERSISTENCE MECHANISM: CSMCORE DXE driver modification (Gigabyte firmware)

HOW IT DIFFERS FROM LOJAX:
  LoJax wrote a PE executable to disk via the DXE module.
  CosmicStrand is more sophisticated:
    → Patches the Windows Boot Manager in memory during boot
    → The patched bootmgfw.efi hooks further into the Windows kernel
    → Kernel-level shellcode sets up a usermode process injection
  → The entire chain runs BEFORE any OS security tool, hooking the kernel
    from the boot sequence itself

MOONBOUNCE — KASPERSKY (2022)

ACTOR: APT41 (Chinese state-sponsored)
TARGET: CORE_DXE module (fundamental UEFI module — harder to remove)
SOPHISTICATION: Highest publicly known
  → Patches a CORE_DXE function called during RAM driver loading
  → This function is called before OS loader
  → Injects kernel-mode implant directly into Windows kernel memory
  → Leaves zero artefacts on disk — entirely memory-resident
  → Requires firmware level to detect; undetectable by any OS tool

REMOVAL: Only reflashing the SPI flash chip removes MoonBounce.
          If the vendor provides a clean firmware update: run it.
          If not: physical chip replacement required.
```

---

## 4 — Analysis Tools

### 4.1 UEFITool

```bash
# Install UEFITool (Qt-based GUI + CLI tool)
git clone https://github.com/LongSoft/UEFITool
cd UEFITool
cmake . && make

# Or download binary release from GitHub

# Open a firmware image:
./UEFITool /path/to/firmware.bin
# GUI shows UEFI volumes → DXE modules → individual PE files

# Find a module by GUID:
./UEFITool /path/to/firmware.bin find --type DXE --guid {GUID}

# Extract a specific module:
./UEFITool /path/to/firmware.bin extract --output ./extracted.efi
# Then analyse the extracted DXE driver with Ghidra
```

### 4.2 CHIPSEC

```bash
# CHIPSEC — Intel's platform security assessment tool
pip install chipsec

# Check SPI flash write protection:
sudo python3 -m chipsec.main -m chipsec.modules.common.spi_lock
# Should report: protected → PASS
# If unprotected: firmware can be reflashed from userspace (LoJax attack possible)

# Check SMRAM (SMM memory) lock:
sudo python3 -m chipsec.main -m chipsec.modules.common.smm

# Check Secure Boot configuration:
sudo python3 -m chipsec.main -m chipsec.modules.common.secureboot.variables

# Full platform security sweep:
sudo python3 -m chipsec.main
# Produces a report of all platform security checks
```

### 4.3 Reading a UEFI Image in Ghidra

```
GHIDRA UEFI ANALYSIS

1. Install efiSeek plugin:
   https://github.com/DSecurity/efiSeek
   → Adds UEFI-specific analysis: identifies GUID lookups, protocol installs,
     event handlers, UEFI Boot Services calls

2. Import the DXE driver (.efi) into Ghidra:
   Import as "PE COFF" format
   Architecture: x86/x64 (most modern UEFI)

3. Key functions to find:
   UefiMain / EfiEntry  → driver entry point (equivalent to DllMain)
   gBS->HandleProtocol  → accessing UEFI protocols (attack surface)
   gRT->SetVariable     → writing NVRAM variables (persistence mechanism)
   gBS->CreateEvent     → registering callbacks (rootkit hook point)

4. Look for patched code:
   Compare two versions of the same DXE module (clean vs. implanted)
   BinDiff/Ghidra Version Tracking → find exactly which bytes changed
   Changed bytes in a DXE driver that is not from the vendor update = implant
```

---

## 5 — Secure Boot and Its Bypass Conditions

```
SECURE BOOT — BYPASS CONDITIONS

SECURE BOOT MODEL (when working correctly):
  SPI flash contains: PK (Platform Key), KEK, DB (allowed), DBX (revoked)
  Before OS loader executes: firmware checks its signature against DB
  If signature valid: proceed. If not: halt.

BYPASS CONDITION 1: Outdated revocation list (DBX not updated)
  Historical signed bootloaders with known vulnerabilities remain in DB
  Attacker uses an old, signed-but-vulnerable GRUB2 to exploit Secure Boot
  Example: BootHole (CVE-2020-10713) — signed GRUB2 with buffer overflow
           allowed arbitrary code execution in Secure Boot context

BYPASS CONDITION 2: DXE execution before Secure Boot
  DXE modules run BEFORE Secure Boot verifies the OS loader
  If an attacker can modify a DXE module (LoJax/CosmicStrand pattern):
  → Their code runs before Secure Boot and can disable it from within

BYPASS CONDITION 3: MOK (Machine Owner Key) misuse
  On Linux systems: users can add their own keys to the MOK database
  Social engineering or malware with sufficient privileges can add attacker keys
  → Their signed bootloader or kernel module will pass Secure Boot

BYPASS CONDITION 4: Test signing / debug mode
  Some UEFI implementations have a "test mode" that allows unsigned code
  Enabled for development; should never be deployed
  Check: uefi-firmware-parser or CHIPSEC → testmode check

DEFENCE:
  Enable Secure Boot + update DBX regularly (Windows Update does this)
  Protect SPI flash write access (CHIPSEC spi_lock check)
  Monitor for NVRAM variable modifications (SetVariable calls from OS)
  Enterprise: use Trusted Platform Module (TPM) attestation to detect
             firmware changes via measured boot (PCR values)
```

---

## Key Takeaways

1. **UEFI rootkits survive everything except reflashing the SPI chip.** OS
   reinstall, hard drive replacement, and memory wipes have no effect on a
   persistent DXE implant. The only detection path is reading the SPI flash
   and comparing to a known-good baseline — which almost no organisation does.
2. **CosmicStrand and MoonBounce demonstrate that in-memory UEFI implants
   are operationally viable.** MoonBounce leaves zero artefacts on disk. The
   only evidence of its presence is in the firmware image. This is the endpoint
   security detection gap of our era.
3. **CHIPSEC closes the assessment gap.** Most platform security audits stop
   at the OS layer. CHIPSEC assesses the firmware layer — SPI write protection,
   SMRAM lock, Secure Boot configuration — that is invisible to every OS-level
   tool. Run it in your lab environment and understand what the checks mean.
4. **The SPI flash dump from Day 701 is the artefact that matters most.** For
   the most sophisticated adversaries, the question is not "what is in memory?"
   or "what is on disk?" — it is "what is in the firmware?" The researcher
   who can answer that question is operating at a level that most incident
   responders never reach.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q742.1, Q742.2 …).

---

## Navigation

← Previous: [Day 741 — Security Research Publication](DAY-0741-Security-Research-Publication.md)
→ Next: [Day 743 — Cloud-Native Security](DAY-0743-Cloud-Native-Security.md)
