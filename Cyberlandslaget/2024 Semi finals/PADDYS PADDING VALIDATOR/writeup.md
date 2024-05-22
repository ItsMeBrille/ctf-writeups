## POKEGLYPHS

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