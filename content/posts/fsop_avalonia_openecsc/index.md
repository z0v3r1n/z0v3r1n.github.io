---
title: "openECSC – avalonia: intro to file struct exploitation!"
date: 2025-10-15
toc: true
---

![](https://github.com/user-attachments/assets/1d984a88-3fd5-419b-aca0-5e64948618d9)

> *From: security@exitnction.ctf
> 
> To: pwn@exitnction.ctf
>
> Subject: Scheduled Security Test for Mail Application* 
>
> *Date: Tue, 21 September 2025 13:37:00 +0200* 
>
> *MIME-Version: 1.0* 
>
> *Content-Type: text/plain; charset="UTF-8"* 
>
> *Hello Team,* 
>
> *As discussed, we have scheduled a full-scale security test on the mail application currently in use. This particular application has been identified as the same platform exploited during the recent* 
>
> *...SNIP...*
>
> *window and that no configuration changes are introduced until the testing phase is complete. Let me know if you have any questions or concerns.* 
>
> *Best regards,* 
>
> *Security Team - Exitnction Limited*

## TL;DR

Used `_IO_wfile_seekoff` as the vtable entry point for fsop to pivot into `_wide_data->_wide_vtable->__overflow`, bypassing glibc's vtable validation and achieving code execution through house of cat technique.

## Background

Before diving in — quick disclaimer. I’m **not** an FSOP wizard or a heap master or any of that. This was literally my _first proper_ `FILE` structure exploitation challenge. I learned the whole `fsop / house of cat` stuff _just to solve this chall_, so if you spot something off, feel free to message me on discord!

This writeup was made as a submission in best writeup competition for openECSC 2025, and I tried to make it as clean and beginner-readable as possible — explaining every decision I made while debugging. I also mixed in some glibc internals exploration since I wanted to understand what was actually happening rather than just cargo-culting someone else’s PoC.

So yeah — if something looks cursed, it probably is, but it worked :)


We were given the following files:

```bash
$ tar xzvf extinction.tar.gz 
exitnction/
exitnction/Dockerfile
exitnction/docker-compose.yml
exitnction/flag.txt
exitnction/exitnction

$ cd extinction
$ file ./extinction | tr ',' '\n'
./exitnction: ELF 64-bit LSB pie executable
 x86-64
 version 1 (SYSV)
 dynamically linked
 interpreter /lib64/ld-linux-x86-64.so.2
 BuildID[sha1]=f531e50a36ad71168e198a5682ddd066791db04b
 for GNU/Linux 3.2.0
 not stripped

$ pwn checksec ./extinction
[*] '/home/kali/exitnction/exitnction'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Running the binary we are presented by a simple menu:

```bash
$ ./exitnction       
Welcome to the 'Exitnction' mail client!

Exitnction Mail Client Commands:
  read          - Read emails
  write         - Write an e-mail
  server        - Print mail server information
  help          - Show this help message
  exit          - Exit


> ^C
```
