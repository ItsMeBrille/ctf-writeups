# Cyberlandslaget 2024

## PYTHON-KEYGEN
### Oppgave
https://python-intro-python-understanding.challs.cyberlandslaget.no/

### Løsning
#### Oppgave a
Første deloppgave ble løst med brute force. tallet viste seg å være av lav verdi, så prosessen gikk raskt. Try-except blokken er der for å overse eventuelle dele-med-null-feil:
```py
for tall in range(1000):  # Considering numbers up to 1000
    try:
        if c(f(b(a(tall)), e(tall))) == 13 and d(tall):
            print(tall) # 56
            break
    except:
        pass
```

Svaret leveres slik:
```ps
curl https://python-intro-python-understanding.challs.cyberlandslaget.no/part_a -X POST -d "part=56"
```
Tilbake får vi første del av flagget: `flag{v1rk3r`

#### Oppgave b
oppgave b består av 3 krav som må være oppfylt samtidig.
- 5 av tegnene skal være bokstaver i caps.
- Summen av ascii-verdien til alle tegnene skal bli 500.
- Strenger skal være 10 tegn langt.

Etter å ha valg tegnene `AAAAA` som et minstekrav for summen av ascii-tegnene som samtidig er bokstaver i caps, ser jeg at det mangler 175 på b-verdien for å oppfylle kravet om 500 totalt. Jeg vet også at det skal være 5 ekstra tegn, dermed: 175/5 = 35. ASCII-tegnet med verdi 35 er `#`.
Derfor er `AAAAA#####` en streng som bør gi et gyldig svar.

```py
print(gyldig(f"AAAAA#####")) # TRUE
```

Svaret leveres slik:
```ps
curl https://python-intro-python-understanding.challs.cyberlandslaget.no/part_b -X POST -d "part=AAAAA#####"
```
Tilbake får vi andre del av flagget: `_50m_0m_du_k4n_`

#### Oppgave c
Siste deloppgave krever at du leverer en string. For å forenkle oppgaven skrev jeg om pythonprogrammet slik at alle opperasjonene ligger i returneringen på funksjonen. Det gjør det enklere å visualisere.

Jeg forsøkte å tenke bakover for å finne ut hva hvert ledd måtte inneholde. (se kommentar i koden)
Videre satt jeg sammen bitene jeg hadde for a[] og dannet stringen " sveiehei     s!   "


```py
import base64

def gyldig(verdi):
    a = base64.b64decode(verdi).decode("ascii")
    return a[6] + a[7:-10] + a[0:5] + a[-5:-3] == "hei sveis!"
    #       h        ei     " svei"     "s!"

str = " sveiehei     s!   "
str = base64.b64encode(str.encode("ascii"))
print(str) # IHN2ZWllaGVpICAgICBzISAgIA==
print(gyldig(str)) # TRUE
```

Svaret leveres slik:
```ps
curl https://python-intro-python-understanding.challs.cyberlandslaget.no/part_c -X POST -d "part=IHN2ZWllaGVpICAgICBzISAgIA=="
```
Tilbake får vi siste del av flagget: `py7h0n}`

<details>
  <summary>Flagg</summary>
  
  `flag{v1rk3r_50m_0m_du_k4n_py7h0n}`
</details>


## DATA REPRESENTATION
### Løsning
Brukte CyberChef for å konvertere base64, men med et alternativt alfabet:
https://gchq.github.io/CyberChef/#recipe=From_Base64('hqOVkntvaFdU%C3%A6zEDXHiS%C3%B8fWrKy%C3%86QCBMbuIYwsglJoAeNZ%C3%85%C3%98mcjGxPp%C3%A5RTL%C3%A7%C3%A9%C3%BB295',true,false)&input=eWxqSXlSxUHG5cVnVXJEZ1VyZlrGV8VQVVdGSUPl%2BOV6T3BneeVm2EJ0akF5UlA9

<details>
  <summary>Flagg</summary>
  
  `flag{ikke-så-ulikt-base64-egentlig}`
</details>


## ENCODING
### Oppgave

### Løsning
Brukte ChatGPT for å generere 3 funksjoner som omgjør ordet til bin, hex og dec. Viktig å huske at desimaltallet skal finnes numerisk, og at det fort kan bli kluss med ferdigbakte funksjoner som omgjør med å slå opp i ascii-tabellen.
```py
def word_to_hex(word):
    return ''.join(hex(ord(char))[2:] for char in word)

def hex_to_binary(hex_string):
    return ''.join(bin(int(char, 16))[2:].zfill(4) for char in hex_string)

def hex_to_decimal(hex_string):
    return int(hex_string, 16)

word = "magi"
hex_ascii = word_to_hex(word)
binary_ascii = hex_to_binary(hex_ascii)
decimal_ascii = hex_to_decimal(hex_ascii)

print(f"flag{{{binary_ascii},{hex_ascii},{decimal_ascii}}}")
```

<details>
  <summary>Flagg</summary>
  
  `flag{01101101011000010110011101101001,0x6d616769,1835100009}`
</details>


## INTRO TO AES
### Løsning

Jeg skjønte fort at poenget med oppgaven var å bruke klarteksten man allerede vet for å kunne knekke krypteringen på det resterende. Jeg ser også at XOR operasjonen trolig er lagt inn som en svakhet med vilje, ettersom det er en operasjon det er enkelt å gjøre "baklengs".

Etter litt analyse av koden oppdager jeg at problemet ligger i kodesnutten `long_to_bytes((i//16)%16,4)`. Problemet er at lengden på teksten overgår lengden denne operasjonen er beregnet på. Etter at løkken har talt lengre enn 256 vil den derfor returnere det samme som tidligere. Dette kan utnyttes ved at jeg lagrer tidligere utregnede ct-verdier og gjenbruker for å finne flagget senere. Koden setter sammen alle bitene og returnerer hele teksten som ble kryptert.

```py
plaintext = open("shakespeare.txt","rb").read()[0:16*16+100]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

ciphertext = "8e7e24751f22bf36361a14f243beb4011469f9764108770874d5e7e0e1656d5e13b1f75a12ee8c972fbc1c31a2ac18b4f4088c5d3a61e2a204ebc1978cadcfa2786bec26f43480a796299a18ac57baf1b8b809af387cdc3f55420a479950351a4bd7da21a3ef6e53ac26c1ee43845f19b21e37775b8bf09b4bf5d220bb888a3d38fc280c972b837a107d98bb5aa1c41f43f6aa73ddd0f73bf16a9f5a41885aff4c4d230c2b22442225dc4a09d5c317d13946f447cd122b207c22c23092a0aa593258e20e978b573c3e6acea22d4ffb3db6d9ddcfc24f1db4fa966240c664631c6de34bb67c2da7b18bd1fd53b45875b06f99c144fa7a866c15dc3ea46b694685d03c07392d0a8a1b063d339724838c64102dd64e7a366d4153d5d9eadb64784e01a6cd266dc4909d30fd1839a7b709befd22"
ct = [0] * 256
flag = ""

for i in range(0, len(plaintext), 16):
    
    if(i<256):
        ct[i] = xor(plaintext[i:i+16], bytes.fromhex(ciphertext)[i:i+16])

    flag += bytes.decode(xor(bytes.fromhex(ciphertext[i*2:i*2+32]), ct[i%256]))

print(flag.strip())
```

<details>
  <summary>Flagg</summary>
  
  `flag{custom_AES-CTR_with_a_reuse_vulnerability}`
</details>


## INTRO TO PWNTOOLS

Den en av oppgaven løses gjennom at jeg venter på tekst fra serveren, før jeg svarer med forhåndsbestemt tekst.
Videre er oppgaven å kjøre en binary for å se hva resultatet blir når når den kjører. For å oppnå dette bruker jeg metoden `subprocess.run` og `subprocess.check_output`.
Siste oppgave er å finne adressen til **win_function** i hex. Det løses med en innebygget funksjon i pwntools, `elf.symbols['win_function']` samt pythons `hex()` for riktig format.

Når siste linje er sendt setter jeg konsollen til interactive-modus itillfelle det dukker opp flere ting jeg må svare på. Det er her flagget blir returnert.

```py
from pwn import *

# Set up the connection
host = 'pwn-intro-pwn-intro.challs.cyberlandslaget.no'
port = 31337

# Connect to the remote service
io = remote(host, port)

io.sendlineafter("[yes/no]", "yes")

io.recvuntil("Base64 ELF: ")
binary_data = b64d(io.recvuntil(b"[?] What is the output from running the binary?", True))

import subprocess

# Write the binary data to a temporary file
with open('temp_binary', 'wb') as f:
    f.write(binary_data)

# Make the temporary file executable
subprocess.run(['chmod', '+x', 'temp_binary'])

io.sendline(subprocess.check_output(['./temp_binary']).decode('utf-8'))

elf = ELF('./temp_binary')

win_function_address = elf.symbols['win_function']
io.sendlineafter(b"What is the address of win_function in hex?", hex(win_function_address))


# Done
io.interactive()

# Close the connection
io.close()
```

<details>
  <summary>Flagg</summary>
  
  `flag{pwntools_is_easy_to_learn_but_hard_to_master!}`
</details>