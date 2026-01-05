# Cybertalent

# KAPITTEL 1

## 1.11 Solveme

### Oppgave 1
- Første passord: `SuperSecretPass!`
- `decrypt(&flag1, &flag1)` dekrypterer flagget i minnet. Og printer *en del* av den dekrypterte strengen.

### Oppgave 2
- Passordet må matche en del av `"What a beautiful password you have chosen for yourself!"`: a beautiful pass
- `flag2` dekrypteres etter riktig passord.

### Oppgave 3
- Passordet må være nøyaktig 16 tegn.
- `checkPassword3` gjør bitvise operasjoner på 4-byte blokker av passordet og sammenligner med hardkodede verdier:
  1. Hver 4-byte blokk XOR’es og modifiseres med en fast formel.
  2. Resultatet sammenlignes med en kjent konstant (`0x8f745590`, `0x6b838889` osv.).
 - `flag2` dekrypteres etter riktig passord.

### Oppgave 4

Ethvert 4-bokstavs svar er godkjent, men flagget er kryptert med noe à la Salsa20. Derfor må passordet bruteforces. Det kan gjøres på to måter:
- Ta ut den logikken som gjør dekrypteringen og bruteforce den raskt
- Kjøre hele programmet mange ganger og teste ulike user inputs. Det siste er enklere, så kunne jeg se på andre oppgaver imens den jobbet: 

```py
from pwn import *
import string
import itertools
import time

context.log_level = "critical"

alphabet = string.ascii_lowercase

start = time.time()
attempts = 0
TOTAL = len(alphabet) ** 4  # 456976

for combo in itertools.product(alphabet, repeat=4):
    guess = "".join(combo).encode()
    attempts += 1

    io = process("./chall")

    io.sendlineafter(b"Enter your first password, please: ", b"SuperSecretPass!")
    io.sendlineafter(b"Enter your second password, please: ", b"a beautiful password...")
    io.sendlineafter(b"Enter your third password, please: ", b"n0PlaceLik3aH0m3")

    io.sendlineafter(b"Enter your fourth password, please: ", guess)
    io.recvuntil(b"?\n")
    result4 = io.recvline()
    
    io.close()

    if b"flag" in result4.lower():
        print(f"[FOUND] {guess.decode()} -> {result4.decode(errors='ignore').strip()}")
        break
```

Passordet viste seg å være "qbit"


### Ekstraoppgave

Flagg 1 dekrypterer en stor string, men printer bare de de første tegnene av strengen (til den ser "}")

Derfor bruker jeg gdb og setter breakpoint på rett etter "decrypt", og leser ut minnet på dette tidspunktet. Da finner jeg 2 flagg i den samme blokken.



## 1.12 Ubalansert

RsaCtfTool løste denne uten problem.

Deretter er det bare å dekryptere:

```py
from Crypto.PublicKey import RSA

# Load private key
with open("priv.pem", "rb") as f:
    key = RSA.import_key(f.read())

# Ciphertext as integer
c = 672897534458289166611755724602906...


m = pow(c, key.d, key.n)

# Convert to bytes
plaintext = m.to_bytes((m.bit_length() + 7) // 8, "big").decode()

print(plaintext)
```

Ut får du flagget :)


## 1.13 RSA7777

RsaCtfTool kunne bruks for å knekke public key og lage en private key fra det. Deretter kunne dette brukes for å logge på med ssh med privatnøkkelen.



## 1.15 Missile Command

Åpnet programmet i https://github.com/dnSpyEx/dnSpy. Der fant jeg en "win" funksjon som kunne kalles for å vinne spillet automatisk:

```c#
LoadScene("Win")
```

Det var litt knot å få kompilert programmet på nytt, men etter å ha fikset et par småfeil, som at noen av funksjonen måte defineres tydeligere med `UnityEngine.` foran.



## 1.16 Legend of Vexillum

Det første jeg tenkte var å forsøke å utforske spillet på vanlig måte. Da sjekket jeg ut hvordan jeg kunne scripte utforsking av kartet.

Jeg lagde et script som mappet alle rommene, og ting som fantes i dem. For å gjøre det enklest mulig så jeg om jeg kunne sende datapakkene direkte istedenfor igjennom spillklienten. Da fant jeg ut at jeg kunne sende TCP-pakker.

Når jeg så i gjennom dumpen med innholdet i de ulike rommene så jeg at det var et rom som het noe med Eyes, som ikke ble besøkt av scriptet fordi det ikke fulgte samme standard for rekkefølgen på ordene.

Derfor ville jeg prøve å besøke dette rommet direkte:

```py
import socket

DEST_IP = "131.163.89.47"
DEST_PORT = 2000           # replace with the actual port
DATA = b"ROOM:eye_room;ITEMS:;COMMAND:look room\n"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect((DEST_IP, DEST_PORT))
sock.sendall(DATA)

response = sock.recv(4096)
print(response)

sock.close()
```

Det viste seg at det var her flagget var gjemt.



# 1.8 Kryptogram

Monoalphabetic substitution cipher. Brukte først dcode.fr, men innså at den ikke hadde æøå, så gikk over til manuell løsing på en annen nettside:

![alt text](images/Kapittel 1/1.8 Kryptogram/image.png)

Kodeordet er `atterloom`

Skriv det inn i programmet som kjører og få flagget.


## 1.9 NoSQL

Her er en litt forenklet versjon av `/validate`-endepunktet

```js
app.post('/validate', async (req, res) => {
    let { flag } = req.body;

    let [rows] = await db.query('SELECT flag FROM flags WHERE flag = ? LIMIT 1', [flag]);
    flag = rows.length ? rows[0].flag : null;

    return res.json({ ok: true, message: `${flag} is a valid flag!` });
});
```

Payloaden som sendes til dette endepunktet er:

```json
{ "flag": "input" }
```

Da blir utrykket i sql slik: `... WHERE flag = 'input' LIMIT 1`

Men det skjer noe interessant i måten de bruker prepared statement. Ettersom flagget brukes i statementen med klammer: `[flag]`, blir den lest inn som et objekt som også kan ha en annen form. For eksempel slik:

```json
{ "flag": { "id": "0" } }
```

Da tolkes utrykket i sql slik: `... WHERE id = '0' LIMIT 1`.

Da matcher den det første elementet i lista, som er flagget. Vi er også så heldige at flagget printes ut selv om vi ikke klarte å gjette det.



