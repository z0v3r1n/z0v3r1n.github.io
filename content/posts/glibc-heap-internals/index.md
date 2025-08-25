---
title: "Glibc Heap Explained: From Chunks to Bins"
date: 2025-08-25
toc: true
---

## Introduction

The heap is a region of memory used for **dynamic memory allocation**, where memory can be requested at runtime and freed when no longer needed. Unlike the stack, heap allocations are **long-lived** and persist beyond function calls.  

There are multiple heap implementations across different platforms, but in this blog, we will focus on **glibc’s ptmalloc2 implementation**, which is widely used in Linux systems.  

![](https://github.com/user-attachments/assets/1c356e7b-1adc-47fb-a3bc-b6fa4bb53812)  
As you can see, the heap grows from **lower addresses to higher addresses**.  

The heap is managed using functions like `malloc`, `free`, `calloc`, `realloc`, etc. These functions are **wrappers around syscalls** like `brk/sbrk`, `mmap`, and `munmap`. In this blog, we'll focus only on `malloc` and `free`, as they are the functions most commonly referenced in **CTF binaries**.


## Inside malloc: memory chunks and their allocation

```
+------------------+
| prev_size        |   (only valid if prev chunk is free)
+------------------+
| size + flags     |
+------------------+
| user data        |   <-- pointer returned by malloc()
| ...              |
| padding (align)  |
+------------------+
```

When you call something like `malloc(10)`, glibc doesn’t simply hand back a pointer to 10 raw bytes. Instead, it has to do extra work to manage memory safely and efficiently. Each allocation on the heap comes wrapped inside a **chunk**, which contains both metadata and user data.

### Chunk Metadata

Every chunk has a small header in front of the user data. This metadata records the size of the chunk and other information needed to manage it. On **x86-64**, the metadata is 16 bytes (two 8-byte `size_t` fields), and on **x86** it is 8 bytes. The structure looks like this:

```c
struct malloc_chunk {
    size_t prev_size;  // only if previous chunk is free
    size_t size;       // size of this chunk + flags in lowest bits
    // user data starts here
    // padding to align the chunk size
};
```

The `size` field also packs in some important flags in its lowest 3 bits:

* `0x1 → PREV_INUSE` (whether the previous chunk is allocated)
* `0x2 → IS_MMAPPED` (whether this chunk was allocated via `mmap`)
* `0x4 → NON_MAIN_ARENA` (whether this chunk belongs to a thread arena instead of the main one)

### Alignment and Rounding

Since most CPUs work best with aligned memory, glibc ensures that allocations are rounded up:

* On **x86-64**, all chunks are aligned to multiples of 16 bytes
* On **x86**, to multiples of 8 bytes

That means if you ask for `malloc(10)` on x86-64, malloc first adds 16 bytes for metadata (total = 26) and then rounds it up to the nearest 16-byte boundary, giving a final chunk size of **32 bytes**. The pointer returned to the program points to the user data region just after the metadata.

### Where the Memory Comes From

Now that we understand how malloc calculates the chunk size, the next question is: *where does it actually find space for this chunk?* glibc tries multiple strategies:

* **Reuse freed chunks**: malloc first looks into its free lists (fast bins, small/large bins, the unsorted bin, and the per-thread tcache). If a suitable free chunk exists, it is reused. We'll cover how this recyling works later on in the blog. 
* **Use the top chunk**: if no free chunk fits, malloc takes memory from the “top chunk,” which is the unused space at the end of the current heap.
* **Request more from the kernel**: if even the top chunk isn’t enough, malloc asks the kernel for more memory. This can happen in two ways:

  * extending the heap with `sbrk`
  * mapping fresh pages with `mmap` for very large allocations.

### Large Allocations via `mmap`

One special case is very large allocations. Instead of using the regular heap, glibc directly calls `mmap`:

* On **32-bit systems**, this is usually for allocations larger than 128 KB up to 512 KB
* On **64-bit systems**, for allocations larger than 32 MB

These chunks bypass the bin system entirely, and when freed, they are returned directly to the kernel with `munmap`.


