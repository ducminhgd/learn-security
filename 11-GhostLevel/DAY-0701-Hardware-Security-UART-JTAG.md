---
title: "Hardware Security — UART, JTAG, and Firmware Extraction"
tags: [hardware-security, uart, jtag, firmware-extraction, embedded, iot,
  module-11-ghost-level]
module: 11-GhostLevel
day: 701
prerequisites:
  - Day 700 — Module 10 Competency Check (Gate)
  - Day 250 — Linux Privilege Escalation
  - Day 432 — Ghidra: Static Reverse Engineering Fundamentals
related_topics:
  - Day 702 — Firmware Analysis: binwalk and Squashfs
  - Day 730 — Ghost Level Competency Gate
---

# Day 701 — Hardware Security: UART, JTAG, and Firmware Extraction

> "Software vulnerabilities live in code. Hardware vulnerabilities live in
> the physical device — in a header on the PCB that the manufacturer left
> exposed, in a debug interface that was never disabled, in a bootloader
> that trusts a UART console before authentication. Before you can attack
> an IoT device, you have to understand the hardware. Today we open the box."
>
> — Ghost

---

## Goals

Understand the UART and JTAG debug interfaces found on embedded devices.
Learn how to identify them on a PCB without documentation. Understand the
firmware extraction workflow from hardware interfaces. Apply the methodology
to a development board target.

**Prerequisites:** Day 700 (Module 10 Gate passed). Days 250, 432.
**Estimated study time:** 4 hours.

---

## 1 — The Embedded Device Attack Surface

```
EMBEDDED/IoT ATTACK SURFACE

REMOTE:
  Web interface (HTTP/HTTPS) — admin panel CVEs
  Network services (Telnet, SSH, MQTT, CoAP) — default credentials
  Firmware update mechanism — unsigned OTA
  Cloud API — account takeover, IDOR

LOCAL (physical access):
  UART console — unauthenticated root shell (very common)
  JTAG interface — memory read/write, halt execution
  SPI/I2C flash chip — direct flash dump (requires soldering)
  SD card slot — filesystem access
  USB debugging port — ADB (Android) or vendor debug protocol

SUPPLY CHAIN:
  Firmware download portal — unsigned firmware packages
  Dependency confusion in build system
```

The physical interfaces are often the fastest path to full control:
many consumer IoT devices have an active UART root shell that requires
only a UART adapter and a few capacitors to access.

---

## 2 — UART: The Embedded Developer's Escape Hatch

### 2.1 What UART Is

UART (Universal Asynchronous Receiver/Transmitter) is a serial communication
protocol. On embedded Linux devices, it is almost always connected to the
kernel's serial console — meaning it outputs boot logs and provides a root
shell when the device boots.

```
UART SIGNAL LINES

TX  (Transmit)   → sends data from device
RX  (Receive)    → receives data into device
GND (Ground)     → reference voltage
VCC (Power)      → 3.3V or 5V (sometimes absent — device is powered separately)

Wiring to a USB UART adapter (e.g., CH340, FTDI, CP2102):
  Device TX → Adapter RX
  Device RX → Adapter TX
  Device GND → Adapter GND
  DO NOT connect VCC if the device is already powered
```

### 2.2 Finding UART on a PCB

Common visual indicators of UART pads/headers:

```
UART IDENTIFICATION CHECKLIST

1. Look for:
   [ ] 3–4 pin header on the PCB edge (unpopulated or populated)
   [ ] Pads labeled TX, RX, GND (or TXD, RXD)
   [ ] Pads labeled CON1, J1, DEBUG, SERIAL, UART

2. Use a multimeter (voltage probe):
   [ ] Power on the device
   [ ] Probe each pad against GND
   [ ] TX pad: shows 3.3V at rest, pulses to 0V during boot
       (logic analyser shows the UART traffic)
   [ ] GND: 0V always
   [ ] VCC: 3.3V or 5V constant

3. Use a logic analyser (Saleae Logic, sigrok):
   [ ] Clip probe to the TX candidate pad
   [ ] Set to UART protocol auto-detect
   [ ] Power cycle the device
   [ ] If UART: you will see framed data at 115200 / 57600 / 9600 baud
```

### 2.3 Connecting and Getting the Shell

```bash
# Connect via screen (simple) or minicom
# Common baud rates: 115200, 57600, 38400, 9600
screen /dev/ttyUSB0 115200

# Or with minicom
minicom -D /dev/ttyUSB0 -b 115200

# If the device does not present a login prompt but outputs boot text:
# Hit Enter at the end of boot — many devices drop to a shell
# If a login prompt appears: try root/root, admin/admin, root/(blank)
# Note: credentials are often in the firmware (see Day 702)
```

### 2.4 Example Boot Log Artefacts

```
# What you see on a typical OpenWRT-based router UART output:
U-Boot 2019.07 (Jul 10 2023 - 14:22:31)
DRAM: 128 MiB
Flash: 16 MiB
Net:   eth0
Hit any key to stop autoboot: 3

# If you hit a key within 3 seconds:
=> printenv   # U-Boot environment variables
              # Check: bootcmd, bootargs (kernel command line), serverip

# Key attack: set bootargs to include init=/bin/sh
=> setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock2 init=/bin/sh'
=> boot       # boots to single-user mode with a root shell
```

---

## 3 — JTAG: Debug Interface for Firmware Researchers

### 3.1 What JTAG Is

JTAG (Joint Test Action Group) is a hardware debugging standard (IEEE 1149.1)
present on almost all modern processors. It provides:

- **Memory read/write:** dump or modify RAM and flash
- **Register access:** read/write CPU registers
- **Execution control:** halt, single-step, resume
- **Boundary scan:** test PCB connections

JTAG is the most powerful hardware interface for security research — it
effectively gives you a hardware debugger equivalent to GDB.

### 3.2 JTAG Signal Lines

```
JTAG SIGNALS

TCK  — Test Clock (generated by debug probe)
TMS  — Test Mode Select (controls state machine)
TDI  — Test Data In (data into device)
TDO  — Test Data Out (data from device)
TRST — Test Reset (optional — resets JTAG state machine)
GND  — Ground reference

A minimal JTAG adapter needs: TCK, TMS, TDI, TDO, GND
```

### 3.3 Finding JTAG

```
JTAG IDENTIFICATION

Visual search:
  [ ] 10–20 pin connector with standard pinout:
      ARM 20-pin JTAG: common on ARM Cortex-M devices
      MIPS EJTAG: common on MIPS routers (Broadcom, Qualcomm)
  [ ] Pads labeled JTAG, TCK, TMS, TDI, TDO

Automated: JTAGulator (hardware tool)
  - Connects to all candidate pads via 24 channels
  - Sends JTAG sequences and identifies which pads respond
  - Identifies UART baud rates simultaneously

OpenOCD with JTAG adapter:
  openocd -f interface/jlink.cfg -f target/imx6.cfg
  telnet localhost 4444
  > halt
  > dump_image /tmp/ram.bin 0x80000000 0x20000000
  > md 0x80000000 16    # memory display at address
```

### 3.4 Extracting Firmware via JTAG

```
# OpenOCD session — dump entire flash
# (adjust memory range for the target SoC)
openocd -f interface/ftdi/jtagkey.cfg \
        -f board/tplink_tl-wr841n.cfg

# In the OpenOCD telnet session:
telnet localhost 4444
> halt
> flash list       # list flash banks
> dump_image /tmp/firmware.bin 0x9F000000 0x1000000
```

---

## 4 — SPI Flash: Direct Chip Dump

When UART is password-protected and JTAG is not accessible, the firmware
can be read directly from the SPI flash chip:

```
SPI FLASH DUMP METHOD

Hardware needed:
  - SPI flash programmer: Bus Pirate, CH341a, Pomona 5250 clip
  - Pomona clip: attaches directly to an 8-pin SPI chip without desoldering

Identify the flash chip:
  - Look for 8-pin chip near the CPU
  - Read the chip marking: e.g., W25Q128FVSIG = Winbond 128Mbit SPI flash

Dump with flashrom:
  # Connect Pomona clip (in-circuit)
  flashrom -p ch341a_spi -r /tmp/firmware.bin

  # Identify chip first
  flashrom -p ch341a_spi
  # Expected: "Found Winbond flash chip W25Q128.V" or similar

Verify dump:
  md5sum /tmp/firmware.bin
  file /tmp/firmware.bin
  # Expected: "data" (compressed) or "u-boot legacy uImage" (bootloader)
```

---

## 5 — Lab Exercise

**Target:** Use a spare development board (Raspberry Pi, ESP32 dev board,
any OpenWRT router dev board, or a Banana Pi). Do NOT practise on production
devices or devices you do not own.

```
HARDWARE SECURITY LAB

Device: _______________________________
PCB markings visible: _________________

UART LAB:
  [ ] Located TX, RX, GND pads (describe location on board): ________
  [ ] Connected UART adapter: adapter type: _________________________
  [ ] Baud rate identified: ________ (used minicom / screen)
  [ ] Boot log captured: Y / N
  [ ] Root shell obtained: Y / N  Method: _________________________
  [ ] U-Boot environment dumped: Y / N

JTAG LAB (if applicable):
  [ ] Located JTAG connector/pads: ________________________________
  [ ] Adapter used: _______________________________________________
  [ ] OpenOCD connected: Y / N
  [ ] halt command successful: Y / N
  [ ] RAM dump complete: size _____________ bytes
  [ ] Flash dump complete: size _____________ bytes

FIRMWARE EXTRACTION:
  [ ] Firmware extracted from: UART / JTAG / SPI flash / Web download
  [ ] File type: _________________________________________________
  [ ] Size: _________________________ bytes
  [ ] Ready for Day 702 firmware analysis: Y / N
```

---

## Key Takeaways

1. **UART is the first thing to check on any IoT device.** The majority of
   consumer routers and IoT devices have an active UART shell with zero
   authentication. Finding the 4 pads and connecting a $5 UART adapter gives
   you a root shell before the attacker even touches the network stack.
2. **JTAG gives hardware-level access that software cannot defend against.**
   With JTAG attached and the CPU halted, no software protection — Secure Boot,
   encrypted storage, signed firmware — can prevent memory dump. Hardware root
   of trust must be burned into the silicon (eFuses) to resist JTAG attacks.
3. **The boot log is a goldmine.** U-Boot and Linux kernel boot logs disclose
   memory map, flash layout, filesystem type, network configuration, and often
   the full kernel command line. Capture it in full before doing anything else.
4. **The SPI flash dump is the baseline.** When all else fails, clip onto the
   flash chip. The firmware is stored in plaintext on almost all consumer IoT
   devices. Once you have the dump, Day 702 analysis begins.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q701.1, Q701.2 …).

---

## Navigation

← Previous: [Day 700 — Module 10 Competency Check](../10-VulnResearch-01/DAY-0700-Module-Competency-Check.md)
→ Next: [Day 702 — Firmware Analysis: binwalk, Squashfs, and Backdoor Hunting](DAY-0702-Firmware-Analysis.md)
