---
title: "Container Security Vulnerabilities — runc Escape and Namespace Bypass"
tags: [container-security, docker, runc, namespace, cve, vulnerability-research,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 695
prerequisites:
  - Day 250 — Linux Privilege Escalation
  - Day 656 — Patch Diffing and CVE Reproduction
  - Day 662 — Bug Class: Integer Overflow and Format String
related_topics:
  - Day 700 — Module 10 Competency Check
  - Day 704 — Zero-Day Mindset
---

# Day 695 — Container Security Vulnerabilities: runc Escape and Namespace Bypass

> "A container is a process with extra restrictions. It is not a VM. The
> kernel is shared. When the container runtime itself has a vulnerability —
> like runc, like the kernel's namespace implementation — those restrictions
> become a politely worded suggestion. Today we study what happens when
> someone forgets that."
>
> — Ghost

---

## Goals

Understand the attack surface of container runtimes and Linux namespaces.
Analyse CVE-2019-5736 (runc overwrite) and CVE-2022-0185 (Linux kernel fsconfig
heap overflow). Apply the vulnerability research methodology to a container
escape scenario. Understand what defenders can do (seccomp, AppArmor, rootless).

**Prerequisites:** Days 250, 656, 662.
**Estimated study time:** 3 hours.

---

## 1 — Container Security Model

```
CONTAINER ISOLATION LAYERS

1. Namespaces: separate the container's view of the system
   - Mount (mnt): separate filesystem view
   - PID:          separate process tree
   - Network (net): separate network stack
   - User:          separate UID/GID mapping
   - UTS:           separate hostname
   - IPC:           separate IPC objects
   - Cgroup:        separate cgroup hierarchy

2. Cgroups: limit resource usage (CPU, memory, I/O)

3. Seccomp: whitelist/blacklist system calls
   - Default Docker seccomp profile blocks ~44 syscalls

4. Capabilities: fine-grained privilege (not all-or-nothing root)
   Default Docker: drops CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.

5. AppArmor/SELinux: MAC policies for file access

WHAT CONTAINERS DO NOT ISOLATE:
  - The kernel itself (shared between host and containers)
  - Kernel vulnerabilities affect ALL containers
```

---

## 2 — CVE-2019-5736: runc Container Escape

**MITRE ATT&CK:** T1611 — Escape to Host

### 2.1 What It Is

A use-after-free / race condition in `runc` (the OCI container runtime used by
Docker, Kubernetes, etc.) allowed a malicious container to overwrite the host's
`runc` binary by exploiting `/proc/self/exe`.

**CWE:** CWE-362 (Race Condition) / CWE-552 (Files accessible to External Parties)

### 2.2 Why It Works

When `runc exec` is used to run a process inside an existing container:

```
1. runc opens /proc/<runc_pid>/exe  (a file descriptor to the runc binary itself)
2. runc opens the container's target binary
3. runc calls exec() to replace itself with the container process

RACE WINDOW:
   Between step 1 (runc opens its own binary via /proc/self/exe)
   and step 3 (exec replaces runc)...

   A malicious process inside the container can open /proc/<runc_pid>/exe
   (which is the runc binary) as a WRITABLE file descriptor through
   /proc/<outer_pid>/fd/<N>

   Then write to it — overwriting the runc binary on disk.
```

### 2.3 Minimal PoC Concept (Educational)

```c
/* This is educational pseudocode — not a working exploit.
   DO NOT run against production systems. */

/*
 * In the container:
 * 1. Find the PID of the runc process (it appears in the container's /proc)
 * 2. Open /proc/<runc_pid>/exe  — this is a symlink to the runc binary
 * 3. Open it for writing via /proc/<runc_pid>/fd/<N>
 *    (requires timing to catch the window)
 * 4. Write a malicious payload to replace runc
 *
 * On next runc exec invocation, the malicious binary runs as root on the host.
 */

// Simplified signal handler approach:
// The malicious container binary installs itself as /bin/sh equivalent,
// waits for runc to call it, then in the entrypoint:

int main(void) {
    /* poll for /proc/*/exe pointing to runc */
    while (true) {
        /* find runc pid from /proc/<N>/exe */
        /* try to open /proc/<runc_pid>/exe writable */
        int fd = open("/proc/<runc_pid>/exe", O_RDWR);
        if (fd >= 0) {
            /* overwrite with payload */
            write(fd, payload, sizeof(payload));
            close(fd);
            break;
        }
        /* retry */
    }
    return 0;
}
```

### 2.4 Patch Analysis

The fix (runc commit `f7dd52b`) uses `memfd_create` to create an anonymous
in-memory copy of the runc binary and executes from that, rather than from the
on-disk binary — removing the writable file descriptor window.

```c
/* BEFORE the fix (vulnerable) */
exec_path = "/proc/self/exe";   /* points to on-disk runc binary */

/* AFTER the fix (patched) */
/* Create an anonymous in-memory executable */
int memfd = memfd_create("runc", MFD_CLOEXEC);
/* Copy runc binary into memfd */
copy_binary_to_fd(memfd);
/* Execute from memory — no on-disk file to overwrite */
exec_path = "/proc/self/fd/" + memfd;
```

---

## 3 — CVE-2022-0185: Linux Kernel Heap Overflow via fsconfig

**MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation

### 3.1 What It Is

A heap buffer overflow in the Linux kernel's `legacy_parse_param()` function
(filesystem context API, introduced in Linux 5.1). Reachable from unprivileged
user namespaces on many Linux distributions.

**CWE:** CWE-122 — Heap-based Buffer Overflow

### 3.2 Why It Works

```c
/* VULNERABLE CODE (simplified) */
static int legacy_parse_param(struct fs_context *fc,
                               struct fs_parameter *param) {
    struct legacy_fs_context *ctx = fc->fs_private;
    unsigned int size = ctx->data_size;

    /* param->string is user-controlled */
    /* size grows by strlen(param->string) + 2 */
    if (size + strlen(param->string) + 2 > PAGE_SIZE)
        return -E2BIG;       /* check is present BUT... */

    /* BUG: check is on the new total, but the append uses the OLD size.
       Off-by-one: when size is exactly at PAGE_SIZE - 1, this check
       passes but the append writes past the buffer. */
    memcpy(ctx->legacy_data + size, param->string,
           strlen(param->string));
    ctx->legacy_data[size + strlen(param->string)] = ',';
    ctx->data_size = size + strlen(param->string) + 1;
}
```

### 3.3 Exploitation Path

```
1. Create a user namespace (unprivileged, allowed on Ubuntu/Fedora/Arch)
2. Call fsopen("ext2")  → allocates a kernel heap buffer
3. Call fsconfig(fd, FSCONFIG_SET_STRING, key, value, 0)  → triggers the overflow
   with a crafted value that overflows the PAGE_SIZE-boundary
4. Overwrite adjacent kernel heap objects (e.g., a kernel credential struct,
   a timer, or a file_operations pointer)
5. Escalate to root in the user namespace → escape to host namespace
```

**Real-world context:** Ubuntu, Fedora, Arch Linux were all vulnerable until
January 2022. Exploited in CTFs and documented with working PoC by
@hackingthehacker (Notselwyn).

### 3.4 Patch

```c
/* THE FIX */
if (size + strlen(param->string) + 2 > PAGE_SIZE)
    return -E2BIG;

/* Add +1 to account for the off-by-one */
if (size + strlen(param->string) + 1 >= PAGE_SIZE)
    return -E2BIG;
```

---

## 4 — Container Escape Attack Surface Map

```
CONTAINER ESCAPE VECTORS (MITRE ATT&CK T1611)

1. RUNTIME VULNERABILITY (runc, containerd, CRI-O)
   CVE-2019-5736 (runc /proc/self/exe overwrite)
   CVE-2021-30465 (runc symlink-race on mount)
   Mitigation: Pin runtime versions; rootless containers

2. KERNEL VULNERABILITY (from inside container)
   CVE-2022-0185 (fsconfig heap overflow)
   CVE-2022-0847 (Dirty Pipe — pipe splice overwrite)
   CVE-2021-22555 (Netfilter heap OOB)
   Mitigation: Seccomp profile (blocks unshare for user namespaces)

3. PRIVILEGED CONTAINER MISCONFIG
   --privileged flag: disables all isolation
   --cap-add=SYS_ADMIN: grants full kernel access
   Mounted /var/run/docker.sock: control of Docker daemon
   Mounted /proc or /sys: kernel parameter exposure
   Mitigation: Never --privileged; use seccomp; AppArmor

4. SHARED VOLUME / BIND MOUNT ESCAPE
   Writable host paths mounted into container
   /etc/cron.d, /root/.ssh, /etc/passwd writable
   Mitigation: Read-only bind mounts; verify mount points

5. IMAGE SUPPLY CHAIN
   Malicious base image from Docker Hub
   Typosquatting (ubuntu vs ubuuntu)
   Mitigation: Use official images; sign with Docker Content Trust
```

---

## 5 — Lab: Container Escape Analysis

**Environment:** Use a VM — never run container escape PoCs on a shared host.

```
CONTAINER ESCAPE LAB

STEP 1: VERIFY ATTACK SURFACE
[ ] Docker/container runtime version: _____________________
    Is it vulnerable to CVE-2019-5736? (runc < 1.0-rc6) Y / N
[ ] Kernel version: ____________________
    Is it vulnerable to CVE-2022-0185? (< 5.16.2) Y / N
[ ] User namespaces enabled:
    sysctl kernel.unprivileged_userns_clone = ______
[ ] Default seccomp profile: Y / N

STEP 2: ENUMERATE CONTAINER CONFIGURATION
Run from inside the container (start with: docker run -it ubuntu bash):
[ ] cat /proc/1/status | grep Cap  → capability set
[ ] ls /proc/*/exe 2>/dev/null     → runc pid visibility
[ ] mount | grep -v tmpfs          → what is bind-mounted?
[ ] env | grep -i docker           → Docker socket in env?
[ ] cat /proc/mounts               → any writable host paths?

STEP 3: IDENTIFY ESCAPE VECTOR
Most likely vector: _______________________________________
Feasibility: High / Medium / Low
Reason: _________________________________________________

STEP 4: DOCUMENT AS A FINDING
CWE: _____________________ CVE (if applicable): __________
Severity (CVSS): _________________________________________
Mitigation: ______________________________________________
```

---

## Key Takeaways

1. **Containers are process isolation, not VM isolation.** Every kernel
   vulnerability applies to containers. CVE-2022-0185 required only unprivileged
   user namespaces — a default-enabled feature on most Linux distributions.
   Container security is only as strong as the kernel.
2. **`--privileged` negates all container security.** A privileged container
   has `CAP_SYS_ADMIN` and effectively full kernel access. Treat a privileged
   container as equivalent to a root shell on the host.
3. **The runtime's privilege is the attack surface.** runc runs as root to
   perform namespace and cgroup setup. Any vulnerability in runc that is
   exploitable from inside the container gives host root access. Pin your
   runtime versions and apply patches immediately.
4. **Seccomp profiles are the most effective mitigation for kernel-level
   exploits.** A profile that blocks `unshare` prevents user namespace creation,
   which eliminates the primary unprivileged attack vector for most kernel CVEs.
   Deploy custom seccomp profiles — the default Docker profile is a good start
   but not sufficient for high-security workloads.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q695.1, Q695.2 …).

---

## Navigation

← Previous: [Day 694 — Dynamic Binary Instrumentation](DAY-0694-Dynamic-Binary-Instrumentation.md)
→ Next: [Day 696 — Targeted Practice: Malware Analysis Gap Closure](DAY-0696-Practice-Malware-Analysis-Gap-Closure.md)
