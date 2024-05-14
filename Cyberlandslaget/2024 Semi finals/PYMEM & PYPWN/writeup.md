## PYMEM WARMUP

### Oppgave

Oppgaven er å hente ut flagget lagret i minnet ved hjelp av et pythonscript som lar deg lese minneadressene.

```
Welcome to a series of forensics challenges to understand memory layout of a running python process
pymem warmup: Let's get you warmed up!
id=0x7f2f75953440
read from memory address:
```

### Løsning

Min løsningen var å automatisere minneavlesningen med pwntools ved å starte med første addresse og be om å få lese hver 16. addresse. Til slutt dekoder jeg strengen til ascii-tegn.

```py
from pwn import *

# Connect to the remote service
io = remote('pymemwarmup.ept.gg', 1337, ssl=True)

io.recvuntil(b"=")
startAddr = int(bytes.decode(io.recvuntil(b"\n", drop=True)), 16)

result = b""
for i in range(50):
    # Send address
    addr = hex(startAddr + i*8)
    io.sendlineafter(b":", addr)

    # Read data and concat
    io.recvuntil(b": ")
    result += io.recvuntil(b"\n", drop=True)
    
# Decode bytestring
print(bytes.fromhex(bytes.decode(result)))

# Close the connection
io.close()
```

Resultatet fra koden over gir flagget i klartekst gjemt i minnedumpen:

```
b"\x01\x00\x00\x00\x00\x00\x00\x00\x80\xf1o#\xb1U\x00\x00J\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xffflag{xxx}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xb7o#\xb1U\x00\x002\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xe4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00unclosed file <_io.BufferedReader name='flag.txt'>\x00\x01\x10\x03\x10\x01\x08\x02\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\xc0\xb7o#\xb1U\x00\x00:\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xe4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00All callers to this function MUST hold self._waitpid_lock.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xa0\xbbo#\xb1U\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00p\x00\xfe1\x12\x7f\x00\x00pp\xe81\x12\x7f\x00\x00\xb0\xdb\x182\x12\x7f\x00\x00"
```

<details>
  <summary>Flagg</summary>
  
  `flag{did_you_do_a_simple_memorydump?_tha7_will_not_work_on_the_next_chal!}`
</details>