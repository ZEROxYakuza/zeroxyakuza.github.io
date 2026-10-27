---
title: "Practical LLDB for iOS Vulnerability Research & Exploitation"
date: 2026-09-26 18:00:00 +0200
description: "This guide details essential LLDB workflows, commands, scripting capabilities, and memory inspection techniques tailored for iOS research."
---

# Practical LLDB for iOS Vulnerability Research & Exploitation

LLDB is the standard debugger for Apple platforms. In iOS vulnerability research, whether you are analyzing userland daemons (`mach-o` binaries) or debugging the XNU kernel via debug kernels or hypervisors (e.g., Corellium), LLDB is an indispensable tool for inspecting state, bypassing checks, dynamic analysis, and developing primitives.

---

## 1. Setting Up the Target Context

Before inspecting memory or setting breakpoints, you must establish connection to your debug target.

### 1.1 Remote Userland Debugging (`debugserver`)

To debug iOS binaries on a jailbroken or research device, attach using Apple's `debugserver`:

```bash
# On the iOS Device (via SSH)
debugserver 127.0.0.1:2222 --attach=SpringBoard
# OR attach to a specific PID
debugserver 127.0.0.1:2222 --attach=1337
```

```bash
# On your macOS host (forward port via USB first using iproxy)
iproxy 2222 2222

# Launch LLDB on macOS
lldb
(lldb) process connect connect://127.0.0.1:2222
```

### 1.2 Kernel Debugging (KDK / Corellium)

When debugging the XNU kernel via debug ports or Corellium:

```bash
lldb /path/to/vmlinux_or_kernel.development
(lldb) gdb-remote <IP>:<PORT>
```

> **Pro Tip:** Always load symbol files (`.dSYM`) matching your build using `target symbols add /path/to/Kernel.dSYM` for full register/symbol resolution.

---

## 2. Register Inspection & Manipulation

Understanding ARM64 register state during instruction execution is critical during vulnerability analysis.

### 2.1 Reading Registers

```text
(lldb) register read
(lldb) reg read x0 x1 x2          ; Read specific registers
(lldb) reg read --all             ; Display GPRs, floating point, and system registers
(lldb) reg read pc sp lr          ; Inspect Execution Pointer, Stack Pointer, Link Register
```

### 2.2 Writing Registers

Modifying register state on the fly allows you to bypass checks or force specific execution paths during analysis:

```text
(lldb) reg write x0 0x1           ; Force return value or parameter to 1
(lldb) reg write pc 0x19283f040   ; Redirect execution pointer
(lldb) reg write w0 0             ; Set 32-bit register w0 to zero
```

---

## 3. Advanced Memory Inspection & Dumping

Manipulating and reading raw memory addresses is key to reverse engineering structure layouts, vtables, and heap chunks.

### 3.1 Reading Memory (`memory read` / `x`)

Use `memory read` (or shorthand `x`) formatted for specific data types:

```text
; Format options: -f <format> (-f x for hex, -f i for instruction, -f s for string)
; Size options:   -s <bytes> (-s 8 for 64-bit quadwords)
; Count options:  -c <count>

(lldb) memory read -f x -s 8 -c 16 $sp               ; Read 16 quadwords (64-bit hex) from Stack
(lldb) x/16gx $sp                                    ; GDB shorthand equivalent
(lldb) memory read -f i -c 10 $pc                    ; Disassemble 10 instructions from PC
(lldb) x/10i $pc                                     ; GDB shorthand equivalent
(lldb) memory read --size 1 --format c --count 32 $x0 ; Read 32-byte string pointed to by x0
```

### 3.2 Writing to Memory

```text
(lldb) memory write $x0 0x4141414141414141          ; Write 64-bit integer payload
(lldb) memory write 0x10293040 --size 4 0x90909090  ; Write raw bytes
(lldb) memory write 0x10293040 "Hello\0"             ; Write string into target address
```

### 3.3 Searching Memory

Find pointers, signatures, or specific values in active memory regions:

```text
; Search for a specific byte sequence or pointer
(lldb) memory search --string "AppleVulnerableService" -- 0x10000000 0x20000000
(lldb) memory search -s 8 -v 0x4141414141414141 -- 0x100000000 0x200000000
```

---

## 4. Breakpoints and Control Flow Traps

Effective usage of conditional and hardware breakpoints allows you to isolate bugs without manual stepping through execution.

### 4.1 Address & Symbol Breakpoints

When ASLR/KASLR is enabled, set breakpoints relative to module bases or symbols:

```text
(lldb) b malloc                                      ; Symbol breakpoint
(lldb) breakpoint set -a 0x19283f420                 ; Absolute address breakpoint
(lldb) breakpoint set -s libsystem_c.dylib -n strcpy  ; Symbol in specific module
```

### 4.2 ASLR/KASLR Slide Calculation

Calculate the ASLR slide dynamically to compute target addresses:

```text
(lldb) image list -o -f                             ; List image load addresses and slides
```

Once you know the slide (`0x10000`), set breakpoints via address expressions:

```text
(lldb) breakpoint set --address "0x0000000100004210 + 0x0000000005000000"
```

### 4.3 Conditional Breakpoints & Auto-Commands

Trigger execution pauses only under precise conditions (e.g., specific argument values in `x0` or `x1`):

```text
; Break on malloc only when allocation size (x0) > 0x1000 bytes
(lldb) breakpoint set -n malloc --condition '$x0 > 0x1000'

; Run an LLDB command automatically when breakpoint hits and continue
(lldb) breakpoint command add 1
Enter your debugger command(s).  Type 'DONE' to end.
> reg read x0
> continue
> DONE
```

### 4.4 Hardware Watchpoints (Data Access Breakpoints)

Watchpoints trigger when memory is read or written. This is crucial for tracking heap corruption, vtable overwrites, or race conditions:

```text
; Set a watchpoint for write access on a specific address
(lldb) watchpoint set expression -w write -- 0x10283f010

; Set a watchpoint for read/write access on a 8-byte buffer
(lldb) watchpoint set variable -s 8 my_global_var
(lldb) watchpoint modify -c '$x0 == 0x41414141'     ; Add condition to watchpoint
```

---

## 5. ARM64 Instruction Execution & Disassembly

Stepping through low-level assembly in LLDB requires instruction-level commands rather than source-level commands.

### 5.1 Stepping Controls

| Command | Action | Description |
| --- | --- | --- |
| `stepi` / `si` | Instruction Step Into | Executes a single ARM64 instruction, stepping *into* `bl` / `blr` calls. |
| `nexti` / `ni` | Instruction Step Over | Executes a single ARM64 instruction, stepping *over* `bl` / `blr` calls. |
| `finish` | Step Out | Executes until the current stack frame returns (`ret`). |
| `thread return 0` | Early Return | Immediately returns from current function with specified return value (`x0=0`). |

### 5.2 Disassembling Code

```text
(lldb) disassemble --pc                             ; Disassemble current frame around PC
(lldb) disassemble -a 0x19283f000                   ; Disassemble entire function at address
(lldb) disassemble -c 20 -s 0x19283f000             ; Disassemble 20 instructions starting at address
```

---

## 6. Python Automation with LLDB API

LLDB features a built-in Python API (`sbprocess`, `sbframe`, `sbregister`, etc.) ideal for crafting automated exploit triggers, unpacking layers, or logging pointer authentication (PAC) state.

### 6.1 Interactive Python Shell

```text
(lldb) script
>>> process = lldb.debugger.GetSelectedTarget().GetProcess()
>>> thread = process.GetSelectedThread()
>>> frame = thread.GetSelectedFrame()
>>> print(hex(frame.GetPC()))
>>> print(hex(frame.FindRegister("x0").GetValueAsUnsigned()))
```

### 6.2 Writing Custom LLDB Commands in Python

Save this script as `inspect_pac.py`:

```python
import lldb

def inspect_pac(debugger, command, result, internal_dict):
    """Simple helper to check if a pointer in x0 has PAC bits set."""
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    
    x0_val = frame.FindRegister("x0").GetValueAsUnsigned()
    # Mask out top PAC bits (assuming 39-bit VA space)
    ptr_masked = x0_val & 0x0000007FFFFFFFFF
    
    print(f"[+] Original x0 : {hex(x0_val)}")
    print(f"[+] Stripped Pointer: {hex(ptr_masked)}")
    if x0_val != ptr_masked:
        print("[!] PAC Signature Detected in Register x0!")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f inspect_pac.inspect_pac checkpac')
    print('[+] Custom LLDB Command `checkpac` Loaded Successfully.')
```

Load and run the script in LLDB:

```text
(lldb) command script import ./inspect_pac.py
[+] Custom LLDB Command `checkpac` Loaded Successfully.
(lldb) checkpac
[+] Original x0 : 0x807f80010283f000
[+] Stripped Pointer: 0x10283f000
[!] PAC Signature Detected in Register x0!
```

---

## 7. Quick Reference Cheat Sheet

| Task | LLDB Command |
| --- | --- |
| Print register $x0 in Hex | `p/x $x0` |
| View call stack | `bt` / `thread backtrace` |
| Select stack frame 2 | `frame select 2` |
| Print dynamic ASLR slide | `image list -o -f` |
| Read string at pointer $x0 | `x/s $x0` |
| Dereference pointer in $x0 | `x/1gx $x0` |
| Set register $pc | `reg write pc 0x1000` |
| Set conditional breakpoint | `b malloc -c '$x0 > 0x100'` |
| Set watchpoint on memory write | `watchpoint set expression -w write -- 0xADDR` |
| Step single assembly instruction | `si` |
| Step over assembly instruction | `ni` |
