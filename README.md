# pwntools cheatsheet

## Installation

```
pip install pwntools
```

## Setup

```python
from pwn import *
BINARY_PATH = './challenge_elf'
binary = ELF(BINARY_PATH)

context.binary = binary
```

`context` stores a global configuration used by some pwntools functions. `context.binary = binary` automatically sets :

- The architecture (x86, amd64, ...)
- The endianness
- The bit-width (32 or 64 bits)

## Tubes

### Local binary

```python
with process(BINARY_PATH) as p:
    # use p to interact with the binary
```

With arguments or environment variables:

```python
with process([BINARY_PATH, arg1, arg2], env={"env_variable1":"value1", "env_variable2": "value2"}) as p:
    # use p to interact with the binary
```

### Local binary with gdb

```python
with gdb.debug(BINARY_PATH) as p:
    # use p to interact with the binary
```

With ASLR disabled:

```python
with gdb.debug(BINARY_PATH, aslr=False) as p:
    # use p to interact with the binary
```

You can pass some commands to gdb::

```python
with gdb.debug(BINARY_PATH, "b main\nc") as p:
    # use p to interact with the binary
```

It is also possible to attach gdb to a running process:

```python
with process(BINARY_PATH) as p:
    gdb.attach(p)
    # use p to interact with the binary
```

### Remote through TCP

```python
with remote('challenge.ctf.com', 1337) as p:
    # use p to interact with the binary
```

### Tubes output

```python
output = p.recv(NUMBER_OF_BYTES)
```

- Gets NUMBER_OF_BYTES bytes.
- Returns immediately if there is some data available.
- Only blocks if there is no data available.

---

```python
output = p.recvline()
```

Gets a line

---

```python
output = p.recvline(keepends=False)
```

Gets a line without the newline character

---

```python
output = p.recvuntil(STRING, drop=True)
```

- Gets data until a specific string is found
- `drop` decides if the string is included in the output or not

---

```python
p.stream()
```
- Prints all the data received from the tube
- Blocks until EOF

### Tubes input

```python
p.send(b"some text")
```

```python
p.sendline(b"some text")
```

### Interactive

```python
p.interactive()
```
- Prints all the data received from the tube
- You can type text and it will be sent to the tube
- Blocks until EOF

## Packing and unpacking

Converts an integer to its byte representation and vice-versa, with respect to endianness and bit-width defined in `context`.

```python
packed_data = pack(0xff1111)
# if context is 32 bits little endian, packed_data is b'\x11\x11\xff\x00'
```

```python
value = unpack(b'\x11\x11\xff\x00')
# if context is 32 bits little endian, value is 0xff1111
```