---
title: "Frida for Reverse Engineering"
tags: [reverse-engineering, frida, dynamic-instrumentation, hooking, tracing, javascript]
module: 07-RE-01
day: 437
related_topics:
  - Dynamic Analysis with GDB (Day 436)
  - Android Dynamic Analysis Frida (Day 214)
  - Windows PE Format (Day 438)
---

# Day 437 — Frida for Reverse Engineering

> "GDB is a scalpel. Frida is a surveillance system. GDB stops the process
> and lets you look. Frida runs alongside the process, hooking every function
> call, reading every return value, without stopping anything.
> In RE, non-intrusive observation is often what you need."
>
> — Ghost

---

## Goals

Use Frida to hook function calls and observe arguments and return values at runtime.
Trace all calls to a set of library functions without modifying the binary.
Write a Frida script that extracts the key from a crackme at runtime.

**Prerequisites:** Day 436 (GDB dynamic analysis), Day 214 (Frida basics for Android).
**Time budget:** 3 hours.

---

## Part 1 — Frida Architecture

Frida injects a JavaScript runtime into a running process. You write scripts
in JavaScript that execute inside the target process's memory space.

```
frida CLI (Python) ─── gum injection ──→ Target process
       ↑                                      ↓
  Your JS script                      JS engine inside target
       ↑                                      ↓
  stdout / file               Interceptor, Memory, NativeFunction APIs
```

**Three modes:**

| Mode | Command | When to use |
|---|---|---|
| Spawn | `frida -f ./binary -l script.js` | Start and instrument from the beginning |
| Attach | `frida -p PID -l script.js` | Instrument a running process |
| USB | `frida -U -n appname -l script.js` | Android/iOS (Day 214 covered this) |

---

## Part 2 — Core Frida APIs for RE

### Interceptor.attach — Hook a Function

```javascript
// hook_strcmp.js
// Hook strcmp and print both arguments
Interceptor.attach(Module.getExportByName(null, 'strcmp'), {
    onEnter: function(args) {
        var s1 = args[0].readUtf8String();
        var s2 = args[1].readUtf8String();
        console.log('[strcmp] "' + s1 + '" vs "' + s2 + '"');
    },
    onLeave: function(retval) {
        console.log('[strcmp] returned: ' + retval.toInt32());
    }
});
```

```bash
frida -f ./crackme2 -l hook_strcmp.js -- <<< "test_input"
# Output:
# [strcmp] "..." vs "osggrqUWeZlk"
# [strcmp] returned: -1
```

### Read Arbitrary Memory

```javascript
// Read 16 bytes at an address as a hex dump
var addr = ptr('0x555555601060');
console.log(hexdump(addr, { length: 16 }));
```

### Hook a Native Function by Address

```javascript
// Hook a function at a known address (from Ghidra)
// Base address must be computed at runtime if PIE is on
var base = Process.enumerateModulesSync()[0].base;
var target_func = base.add(0x1156);  // Ghidra offset

Interceptor.attach(target_func, {
    onEnter: function(args) {
        console.log('[check_password] input: ' + args[0].readUtf8String());
    },
    onLeave: function(retval) {
        console.log('[check_password] result: ' + retval.toInt32());
    }
});
```

### Modify Return Value

```javascript
// Force check_password to always return 1 (success)
Interceptor.attach(target_func, {
    onLeave: function(retval) {
        console.log('Forcing return value to 1');
        retval.replace(1);
    }
});
```

This bypasses the password check entirely. Useful for finding what the program
does AFTER a successful check without knowing the password.

---

## Part 3 — Tracing Library Calls

```javascript
// trace_all.js
// Trace calls to common interesting functions
var functions_to_trace = [
    'strcmp', 'strncmp', 'memcmp',
    'fgets', 'scanf',
    'malloc', 'free',
    'fopen', 'fread',
    'system', 'execve',
    'ptrace'
];

functions_to_trace.forEach(function(name) {
    var sym = Module.findExportByName(null, name);
    if (sym === null) return;
    Interceptor.attach(sym, {
        onEnter: function(args) {
            var display = name + '(';
            // Show first two args as strings if possible
            try { display += '"' + args[0].readUtf8String(64) + '"'; }
            catch(e) { display += args[0]; }
            display += ')';
            console.log('[CALL] ' + display);
        }
    });
});
```

```bash
frida -f ./crackme2 -l trace_all.js -- <<< "wrong_key"
# Shows every intercepted call in order — gives you the execution sequence
```

---

## Part 4 — Frida Stalker (Execution Tracing)

Stalker traces every instruction a thread executes. Useful for understanding
obfuscated code where the decompiler is unhelpful.

```javascript
// stalk.js — trace a single thread's execution
Thread.backtrace;
Stalker.follow(Process.enumerateThreadsSync()[0].id, {
    events: {
        call: true,   // log every CALL instruction
        ret: false,
        exec: false   // true = every instruction (very verbose)
    },
    onReceive: function(events) {
        var parsed = Stalker.parse(events);
        parsed.forEach(function(event) {
            if (event[0] === 'call') {
                console.log('CALL ' + event[1] + ' → ' + event[2]);
            }
        });
    }
});

// Run for 3 seconds then print
setTimeout(function() {
    Stalker.unfollow(Process.enumerateThreadsSync()[0].id);
    console.log('Done.');
    Process.exit(0);
}, 3000);
```

---

## Part 5 — Full Lab: Extract crackme2 Key with Frida

```javascript
// extract_key.js
// Hook strcmp, capture the expected (second) argument → that is our key

Interceptor.attach(Module.getExportByName(null, 'strcmp'), {
    onEnter: function(args) {
        var s1 = args[0].readCString();
        var s2 = args[1].readCString();
        // The TRANSFORMED constant is the second arg passed to strcmp
        if (s2 !== null && s2.length > 4) {
            console.log('[*] Expected (TRANSFORMED): ' + JSON.stringify(s2));
            // We need to reverse: input[i] = (TRANSFORMED[i] - i) ^ 0x13
            var key = '';
            for (var i = 0; i < s2.length; i++) {
                var b = ((s2.charCodeAt(i) - i) & 0xff) ^ 0x13;
                key += String.fromCharCode(b);
            }
            console.log('[*] Recovered key: ' + key);
        }
    }
});
```

```bash
# Patch the anti-debug first (or use the patched binary)
frida -f ./crackme2_patched -l extract_key.js -- <<< "aaaaaaaaaaaaa"
# Output:
# [*] Expected (TRANSFORMED): osggrqUWeZlk
# [*] Recovered key: backdoor_key
```

---

## Part 6 — Frida vs GDB for RE

| Task | Frida | GDB |
|---|---|---|
| Hook a function | 3 lines of JS | `break + commands` |
| Trace all strcmp calls | Easy (`Module.getExportByName`) | Tedious |
| Modify return values | `retval.replace()` | `set $rax = N` |
| Non-intrusive (no stop) | Yes | No — always pauses |
| Execution tracing | Stalker API | `record + replay` (limited) |
| Mobile binaries | Native (Android/iOS) | Difficult |
| Anti-frida detection | Possible to bypass | N/A |

**When to use Frida over GDB in RE:**
- You need to trace multiple function calls across a long execution.
- You do not want to stop the process (UI apps, network clients).
- You want to hook and modify behaviour without binary patching.

---

## Key Takeaways

1. Frida's `Interceptor.attach` hooks any function — by name (exported symbols)
   or by address. Both `onEnter` (arguments) and `onLeave` (return value) are
   accessible.
2. Forcing a return value with `retval.replace()` bypasses checks without
   touching the binary. This is the fastest way to see post-auth behaviour.
3. Stalker records every call/instruction. Use it sparingly — it is extremely
   verbose. Filter to call events only for readable output.
4. `Module.getExportByName(null, 'strcmp')` searches all loaded modules. Pass
   a module name (e.g., `'libc.so.6'`) to narrow the search.
5. Frida does not work against anti-Frida binaries out of the box. Those
   require Frida customisation or static analysis — covered in Day 454.

---

## Exercises

1. Hook `fgets` in crackme1. Print the input as it is read. Verify that your
   hook fires before the comparison function.
2. Force `check_password` in crackme1 to always return 1 using Frida. Confirm
   you can provide a wrong password and still get "Access granted."
3. Use Stalker on crackme2 to trace every CALL instruction in the main thread.
   Count how many calls occur before the strcmp. Map them to Ghidra functions.
4. Write a Frida script that hooks `memcmp` and prints both buffers as hex
   dumps when the comparison length is greater than 4.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q437.1, Q437.2 …).

---

## Navigation

← Previous: [Day 436 — Dynamic Analysis with GDB and PWNDBG](DAY-0436-Dynamic-Analysis-with-GDB-and-PWNDBG.md)
→ Next: [Day 438 — Windows PE Format](DAY-0438-Windows-PE-Format.md)
