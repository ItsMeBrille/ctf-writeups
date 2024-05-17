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

Min løsningen var å automatisere minneavlesningen med pwntools ved å starte med første addresse og be om å få lese hver 8. addresse. Til slutt dekoder jeg strengen til ascii-tegn.

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



## PYMEM POINTERS

### Oppgave

Oppgaven er å hente ut flagget lagret i en 2d-liste i python. Lister i python lagres som et array av pointers, derav navnet på oppgaven.

```
pymem pointers: brute-force will not work here, read pointers like CPython!
id=0x7fc61e1d0800
read from memory address:
```

### Løsning

Som vi kan se i [kildekoden](https://github.com/python/cpython/blob/5c22476c01622f11b7745ee693f8b296a9d6a761/Include/listobject.h#L22) til CPython lagres lister som et objekt med denne strukturen (forenklet):

```
   # PyListObject       # ob_item (array of pointers to other objects):
+------------------+                    +----------+
| ob_refcnt  num   |                    | 0x111111 |
+------------------+                    +----------+
| ob_type   type*  |           / - - -> | 0x222222 |
+------------------+          /         +----------+
| ob_size    num   |         /          | 0x333333 |
+------------------+        /           +----------+
| ob_item    ptr*  | - - - /
+------------------+
| allocated  num   |
+------------------+
```

Lista vi skal finne er i to dimensjoner. Vi går gjennom `ob_item` til den ytterste lista for å gå igjennom alle underlistene. Vi gjentar prosessen for underlistene, men denne gangen vet vi at det kun ligger én pointer i `ob_item`. I dette feltet finner vi en tallverdi som også står oppført i [kildekoden](https://github.com/python/cpython/blob/5c22476c01622f11b7745ee693f8b296a9d6a761/Include/longobject.h) til CPython (forenklet):

```
+-------------------+
| ob_refcnt:   num  | 
+-------------------+
| ob_type:    type* |
+-------------------+
| ob_size      num  |
+-------------------+
| ob_digit[0]  num  |
+-------------------+
```

Koden bruker pwntools for å iterere over den ytterste listen og leter gjennom hierarkiet for hver bokstav i flagget. For å lese minneadressene riktig må adressene i oppgaven konverteres fra **big-endian** til **little-endian**. Det skjer i `read_addr`-funksjonen.


```py
from pwn import *

# Read memory address
def read_addr(addr):
    io.sendlineafter(b":", addr)
    # Read data and concat
    io.recvuntil(b": ")
    value = bytes.fromhex(io.recvuntil(b"\n", drop=True).decode('utf-8'))[::-1].hex()
    return value

# Connect to the remote service
io = remote('pymempointers.ept.gg', 1337, ssl=True)

# Read flag object id
io.recvuntil(b"=")
f_list = int(bytes.decode(io.recvuntil(b"\n", drop=True)), 16)

f_ptr = read_addr( hex(    f_list   + 3*8) ) # First list of pointers

flag = ""
flag_length = read_addr( hex(f_list + 2*8) )
for i in range(int(flag_length, 16)):
    s_list    = read_addr( hex(int(f_ptr, 16)     + i*8) ) # Second list
    s_ptr     = read_addr( hex(int(s_list, 16)    + 3*8) ) # Second list of pointers
    long_elmt = read_addr( hex(int(s_ptr, 16)          ) ) # Long element
    number    = read_addr( hex(int(long_elmt, 16) + 3*8) ) # Number as hex
    flag += chr(int(number,16)) # Convert to character and append to flag

print(flag)

# Close the connection
io.close()
```

<details>
  <summary>Flagg</summary>
  
  `flag{PyTypeObject_in_CPython's_sourcecode_had_all_what_you_needed!}`
</details>