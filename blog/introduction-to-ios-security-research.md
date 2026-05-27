---
title: "Introduction to iOS Security Research"
date: "27 May 2026"
readTime: "20 min"
excerpt: "A practical AArch64 reference for security researchers: registers, assembly, calling conventions, and exploit primitives."
tags: ["iOS", "Security Research", "arm64"]
---


# ARM64 for Security Researchers: Architecture, Assembly, Registers & Calling Conventions

> A practical deep-dive into AArch64 internals for vulnerability research, reverse engineering, and exploit development.

---

## 1. Why ARM64 Matters for Security Research 

ARM64 (also called AArch64) has become the dominant architecture for mobile devices (iOS, Android), embedded systems, and increasingly for servers and desktops (Apple Silicon, AWS Graviton, Qualcomm Snapdragon X). If you're auditing iOS apps, hunting kernel bugs on Android, or doing firmware analysis, you *must* speak ARM64.

Key differences from x86-64 that affect your research workflow:

| Property | x86-64 | ARM64 |
|---|---|---|
| Instruction encoding | Variable (1–15 bytes) | Fixed 4 bytes |
| Register count | 16 GP registers | 31 GP registers |
| Memory access | Any instruction | Only load/store |
| Calling convention | System V AMD64 / MS x64 | AAPCS64 |
| Pointer authentication | No | Yes (PAC, ARMv8.3+) |
| Branch Target ID | No | Yes (BTI, ARMv8.5+) |

---

## 2. Architecture Overview 

ARM64 is a **load/store** architecture: arithmetic operations only work on registers, not directly on memory. This simplifies instruction decoding but means exploit primitives (like arbitrary read/write chains) look different than on x86.

### Execution State

The processor runs in one of several **Exception Levels (EL)**:

```
EL3  — Secure Monitor (TrustZone, firmware)
EL2  — Hypervisor
EL1  — Kernel / OS
EL0  — Userspace
```

For userspace exploitation and app-layer research, you'll mostly operate at EL0 and occasionally pivot to EL1 (kernel exploits). TrustZone research targets EL3.

### Instruction Encoding

Every ARM64 instruction is exactly **32 bits wide**, aligned to a 4-byte boundary. This is a critical detail:

- ROP gadget density is lower than x86 (no mid-instruction gadgets).
- However, the fixed width makes disassembly trivial and reliable — no ambiguity.
- JOP (Jump-Oriented Programming) is often more practical than ROP on ARM64.

---

## 3. Register File 

### General-Purpose Registers

ARM64 has **31 general-purpose registers**, addressable in two widths:

| 64-bit name | 32-bit name | Notes |
|---|---|---|
| `x0`–`x7` | `w0`–`w7` | Function arguments / return values |
| `x8` | `w8` | Indirect result register (syscall number on Linux) |
| `x9`–`x15` | `w9`–`w15` | Caller-saved temporaries |
| `x16`–`x17` | `w16`–`w17` | Intra-procedure-call scratch (IP0, IP1) |
| `x18` | `w18` | Platform register (reserved on iOS; TEB on Windows) |
| `x19`–`x28` | `w19`–`w28` | Callee-saved |
| `x29` | `w29` | Frame pointer (FP) |
| `x30` | `w30` | Link register (LR) — holds return address |
| `xzr` / `wzr` | — | Zero register (reads always return 0) |
| `sp` | `wsp` | Stack pointer |
| `pc` | — | Program counter (not directly writable) |

> **Security note:** The link register (`x30`) holds the return address. On x86 the return address lives *on the stack*; on ARM64 it lives *in a register* — at least until the function prologue pushes it. This changes how stack overflows work: overwriting a saved `x30` on the stack is still the classic target.

Writing to `wN` (32-bit) **zero-extends** into `xN` — there's no partial register stall like on x86. This is important when reading decompiler output.

### Special-Purpose Registers

```
NZCV  — Condition flags (Negative, Zero, Carry, oVerflow)
FPCR  — Floating-point control
FPSR  — Floating-point status
TPIDR_EL0 — Thread pointer (userspace TLS base)
```

### SIMD / Floating-Point Registers

The 32 vector registers `v0`–`v31` are 128-bit wide, accessed via aliases:

```
qN   — 128-bit (quad)
dN   — 64-bit (double)
sN   — 32-bit (single)
hN   — 16-bit (half)
bN   — 8-bit (byte)
```

These matter when analyzing cryptographic code, media codecs, or when looking for uninitialized data leaks in SIMD paths.

---

## 4. Instruction Set Fundamentals 

### Data Movement

```asm
mov  x0, x1          // x0 = x1
mov  x0, #0x1337     // x0 = immediate
movk x0, #0xdead, lsl #16  // keep other bits, insert 0xdead at [31:16]
movz x0, #0x4141     // zero other bits, set low 16
```

`movz` + `movk` combinations are how compilers synthesize 64-bit constants — you'll see these constantly in disassembly.

### Arithmetic

```asm
add  x0, x1, x2      // x0 = x1 + x2
add  x0, x1, #0x10   // x0 = x1 + 16
sub  x0, x1, x2      // x0 = x1 - x2
mul  x0, x1, x2      // x0 = x1 * x2 (low 64 bits)
umulh x0, x1, x2     // x0 = (x1 * x2) >> 64 (useful for overflow checks)
```

### Load / Store

```asm
ldr  x0, [x1]        // x0 = *(uint64_t*)x1
ldr  x0, [x1, #8]    // x0 = *(uint64_t*)(x1 + 8)
ldr  x0, [x1, x2]    // x0 = *(uint64_t*)(x1 + x2)
ldr  x0, [x1, x2, lsl #3]  // x0 = *(uint64_t*)(x1 + x2*8)  — scaled index

str  x0, [x1]        // *(uint64_t*)x1 = x0
str  x0, [x1, #8]!   // pre-index: x1 += 8; *(x1) = x0
str  x0, [x1], #8    // post-index: *(x1) = x0; x1 += 8

ldp  x0, x1, [sp]    // load pair: x0=*(sp), x1=*(sp+8)
stp  x29, x30, [sp, #-16]!  // store pair + update sp (classic prologue)
```

The **scaled index** addressing (`lsl #3` for 64-bit loads) is critical for understanding array accesses and spotting out-of-bounds bugs.

### Branching

```asm
b    label            // unconditional branch
bl   func             // branch + link (x30 = next PC)
br   x0               // branch to register (JOP target!)
blr  x0               // branch + link to register (indirect call)
ret                   // branch to x30 (equivalent to: br x30)
ret  x19              // branch to x19 (non-standard, used in hardened code)
```

> **JOP note:** `br xN` and `blr xN` are your primary Jump-Oriented Programming gadget targets. On iOS, PAC (Pointer Authentication Codes) is designed specifically to prevent forging these targets.

### Conditional Branches

```asm
cmp  x0, #0          // sets NZCV flags (x0 - 0)
b.eq label           // branch if equal (Z=1)
b.ne label           // branch if not equal
b.lt label           // less than (signed)
b.lo label           // less than (unsigned — "lower")
b.gt label           // greater than (signed)
b.hi label           // higher (unsigned)

cbz  x0, label       // branch if x0 == 0 (no flags needed)
cbnz x0, label       // branch if x0 != 0
tbz  x0, #3, label   // branch if bit 3 of x0 is zero
tbnz x0, #3, label   // branch if bit 3 of x0 is nonzero
```

`cbz`/`cbnz`/`tbz`/`tbnz` are extremely common in compiled code. They're great gadget building blocks.

### Bitwise & Shifts

```asm
and  x0, x1, x2      // AND
orr  x0, x1, x2      // OR
eor  x0, x1, x2      // XOR
bic  x0, x1, x2      // bit clear: x1 & ~x2
lsl  x0, x1, #3      // logical shift left
lsr  x0, x1, #3      // logical shift right (unsigned)
asr  x0, x1, #3      // arithmetic shift right (signed)
ror  x0, x1, #3      // rotate right
```

### System Instructions

```asm
svc  #0              // syscall (supervisor call)
mrs  x0, TPIDR_EL0   // read system register into x0
msr  TPIDR_EL0, x0   // write x0 to system register
isb                  // instruction synchronization barrier
dsb  sy              // data synchronization barrier
```

`mrs`/`msr` access system registers and are gold in kernel exploit chains.

---

## 5. Calling Conventions (AAPCS64) 

The **ARM Architecture Procedure Call Standard for AArch64 (AAPCS64)** governs how functions communicate. Understanding this is essential for:

- Reading disassembly without source
- Writing shellcode / ROP chains
- Fuzzing and tracing with custom harnesses

### Argument Passing

Integer and pointer arguments are passed in `x0`–`x7` (up to 8 arguments):

```c
// C prototype:
long foo(int a, long b, void *c, int d, int e, int f, int g, int h);
//        x0     x1      x2      x3     x4     x5     x6     x7
```

Arguments beyond the 8th go on the **stack** (pushed right-to-left, 8-byte aligned).

Floating-point / SIMD arguments use `v0`–`v7`.

### Return Values

```
Integer/pointer ≤ 64 bits  → x0
Integer 128 bits            → x0 (low) + x1 (high)
Float / double              → s0 / d0
Struct ≤ 16 bytes           → x0 + x1 (packed)
Struct > 16 bytes           → caller allocates, address passed in x8
```

### Caller-Saved vs. Callee-Saved

| Register | Convention | Implication for exploits |
|---|---|---|
| `x0`–`x15` | Caller-saved | May be clobbered across calls |
| `x19`–`x28` | Callee-saved | Preserved; pivoting these = persistence |
| `x29` (FP) | Callee-saved | Reliable frame chain for stack walking |
| `x30` (LR) | Callee-saved | Saved to stack on non-leaf functions — **overflow target** |
| `sp` | Special | Must be 16-byte aligned at all public interfaces |

### Typical Function Prologue / Epilogue

```asm
; Prologue
sub  sp, sp, #0x30           ; allocate 48 bytes on stack
stp  x29, x30, [sp, #0x20]  ; save frame pointer and link register
add  x29, sp, #0x20          ; set frame pointer

; ... function body ...

; Epilogue
ldp  x29, x30, [sp, #0x20]  ; restore FP and LR
add  sp, sp, #0x30           ; deallocate stack frame
ret                           ; branch to x30
```

> **Buffer overflow target:** If there's a stack buffer in the frame, the saved `x30` at `[x29, #8]` is your overwrite target — same concept as x86, different layout.

### Stack Alignment

The stack pointer **must be 16-byte aligned** at any `bl`/`blr` call boundary. Violating this causes an alignment fault. Keep this in mind when crafting ROP chains.

---

## 6. Stack Layout & Frame Analysis 

A typical non-leaf function frame looks like this (stack grows downward):

```
High addresses
┌─────────────────────────┐
│   caller's frame        │
├─────────────────────────┤  ← x29 (frame pointer)
│   saved x29 (prev FP)   │  [x29 + 0]
│   saved x30 (ret addr)  │  [x29 + 8]   ← overflow target
├─────────────────────────┤
│   callee-saved regs     │  x19–x28 if used
├─────────────────────────┤
│   local variables       │
│   buffers               │  ← overflow source
├─────────────────────────┤  ← sp
Low addresses
```

The frame pointer chain (`x29` → saved `x29` → ...) enables reliable stack unwinding, which matters both for crash analysis and for understanding exploit reliability.

---

## 7. Security Features & Mitigations 

### Pointer Authentication Codes (PAC) — ARMv8.3+

PAC embeds a cryptographic signature into the unused high bits of a pointer. Used to authenticate:

- Return addresses (`pacibsp` / `autibsp`)
- Function pointers (`pacia` / `autia`)

```asm
; Hardened prologue on iOS
pacibsp              ; sign x30 using SP as context, store in x30
stp  x29, x30, [sp, #-16]!

; Hardened epilogue
ldp  x29, x30, [sp], #16
retab                ; authenticate x30 before branching
```

**Research implications:** Forging a PAC requires the signing key (`APIAKey`, `APIBKey`, etc.) which lives in system registers only accessible at EL1+. PAC bypass techniques include:

- Oracle attacks (brute-force 16-bit PAC via fault handling)
- Type confusion to reach a context where PAC isn't checked
- Signing gadgets (`pacia x0, x1`) used out of context

### Branch Target Identification (BTI) — ARMv8.5+

Restricts indirect branches (`br`/`blr`) to only land on `bti` instructions. Reduces JOP gadget availability dramatically.

```asm
bti  c    ; valid target for blr (call)
bti  j    ; valid target for br (jump)
bti  jc   ; valid target for both
```

### Stack Canaries

Same concept as x86 — compiler inserts a random value between locals and saved registers, checked before returning. Bypasses are the same: info leak + overwrite, or brute force.

### ASLR / PIE

Address randomization is universal on modern ARM64 platforms. Note that on iOS, the kernel slide is separate from the userspace ASLR slide. PAC keys are randomized per-process on iOS.

### MTE — Memory Tagging Extension (ARMv8.5+)

Each 16-byte "granule" of heap/stack gets a 4-bit tag. The top byte of a pointer carries the expected tag. On access mismatch → fault. This is a hardware-assisted use-after-free and heap overflow mitigation.

---

## 8. Common Vulnerability Patterns 

### Stack Buffer Overflow

Classic. Overflow a local buffer to reach saved `x30`:

```c
void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);   // no bounds check
    // saved x30 is at buf + 72 (or wherever the compiler placed it)
}
```

Find the offset: `cyclic` (pwntools), or just count bytes from the buffer start to `[x29 + 8]`.

### Use-After-Free (UAF)

Same semantics as x86. The attacker controls heap layout to overlap a freed chunk with a controlled allocation. On ARM64, class vtables are function pointer tables — hijacking `x8` (indirect result register) or vtable entries gives you `blr xN` control.

### Integer Overflow → OOB Write

The fixed-width instructions and zero-extension behavior of `wN` writes make it easy to miss truncation bugs:

```c
uint32_t idx = user_input;   // 32-bit
array[idx * 8] = value;      // idx * 8 computed in 64-bit, no overflow
                              // but idx itself might wrap if derived from subtraction
```

### Format String

Uncommon today but still appears in embedded targets. On ARM64, the first 8 `%p` / `%x` reads dump `x0`–`x7` (register args), not the stack, because arguments are register-passed. The stack leak starts after those.

### Kernel: Arbitrary Read/Write Primitives

Standard iOS/Android kernel exploitation pattern:

1. UAF or OOB on a kernel object with function pointers
2. Overwrite a pointer to control `blr xN`
3. Use a kernel read/write primitive to defeat PAC (read signing keys or find unsigned regions)
4. Achieve PC control → kernel code execution

---

## 9. Tooling 

### Disassemblers / Decompilers

- **Ghidra** — free, solid ARM64 support, good decompiler
- **IDA Pro** — industry standard, excellent ARM64 + PAC analysis
- **Binary Ninja** — great for scripting and automation
- **Hopper** — lightweight, great for macOS/iOS work
- **Capstone** — disassembly library for custom tooling

### Debuggers

- **LLDB** — native on macOS/iOS; `register read` for register state
- **GDB + GEF / pwndbg** — Linux ARM64 targets
- **Frida** — dynamic instrumentation, indispensable for iOS/Android

### Emulation

- **QEMU** — full system + user-mode emulation
- **Unicorn** — CPU emulation library (Unicorn Engine), based on QEMU
- **Corellium** — virtual iOS/Android devices for research

### Exploit Development

- **pwntools** — `context.arch = 'aarch64'`; full ARM64 support
- **ROPgadget** / **ropper** — gadget search in ARM64 binaries
- **one_gadget** — won't work directly, but the concept applies to finding useful `blr` targets

### Quick Reference

```bash
# Assemble ARM64
echo "mov x0, #1; ret" | aarch64-linux-gnu-as -o /tmp/t.o -
aarch64-linux-gnu-objdump -d /tmp/t.o

# Disassemble a blob
objdump -D -b binary -m aarch64 shellcode.bin

# GDB on QEMU user-mode ARM64
qemu-aarch64 -g 1234 ./target &
gdb-multiarch ./target -ex "target remote :1234"

# Frida trace all calls
frida-trace -U -n "TargetApp" -i "malloc"
```

---

*Happy hunting. Stay curious, stay ethical.*



