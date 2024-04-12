# NPST 2023

## Oppgave dag 4

Målet med denne oppgaven var å gjøre en rekke operasjoner baklengs. Oppgaven ble hovedsaklig løst av ChatGPT:

```py
otp = [23, 2, 0, 5, 13, 16, 22, 7, 9, 4, 19, 21, 18, 10, 20, 11, 12, 14, 6, 1, 3, 8, 17, 15]

def implode(fragments):
    reordered_fragments = [''] * len(otp)
    
    for i, fragment in zip(reversed(otp), fragments):
        reordered_fragments[i] = fragment
    
    return ''.join(reordered_fragments)

def unexplode(eksplosjon, antall):
    eksplosjon = [chr(ord(c) - 2) for c in eksplosjon]
    størrelse = len(eksplosjon) // antall
    fragments = []
    
    for i in range(0, len(eksplosjon), størrelse):
        fragment = ''.join(eksplosjon[i:i+størrelse])
        fragments.append(fragment)
    
    return fragments

with open("pinneved.txt", "r") as file:
    pinneved = file.read()

eksplosjon = unexplode(pinneved, 24)
reconstructed_slede = implode(eksplosjon)

with open("slede.txt", "w") as file:
    file.write(reconstructed_slede)
```

Programmet gjør om fila til en tegning i ASCII-art. Nederst i tegningen står flagget:

```
 /$$$$$$$   /$$$$$$  /$$$$$$$$ /$$$  /$$$$$$   /$$$$$$   /$$$$$$  /$$$$$$ /$$$$$$                             /$$                              /$$                 /$$   /$$    /$$$
| $$__  $$ /$$__  $$|__  $$__//$$_/ /$$__  $$ /$$__  $$ /$$__  $$|_  $$_/|_  $$_/                            | $$                             | $$                | $$  | $$   |_  $$
| $$  \ $$| $$  \__/   | $$  | $$  | $$  \ $$| $$  \__/| $$  \__/  | $$    | $$          /$$$$$$   /$$$$$$  /$$$$$$        /$$$$$$   /$$$$$$  | $$   /$$ /$$   /$$| $$ /$$$$$$   | $$
| $$$$$$$/|  $$$$$$    | $$  /$$$  | $$$$$$$$|  $$$$$$ | $$        | $$    | $$         |____  $$ /$$__  $$|_  $$_/       /$$__  $$ /$$__  $$ | $$  /$$/| $$  | $$| $$|_  $$_/   | $$$
| $$____/  \____  $$   | $$ |  $$  | $$__  $$ \____  $$| $$        | $$    | $$          /$$$$$$$| $$  \__/  | $$        | $$$$$$$$| $$  \__/ | $$$$$$/ | $$  | $$| $$  | $$     | $$/
| $$       /$$  \ $$   | $$  \ $$  | $$  | $$ /$$  \ $$| $$    $$  | $$    | $$         /$$__  $$| $$        | $$ /$$    | $$_____/| $$       | $$_  $$ | $$  | $$| $$  | $$ /$$ | $$
| $$      |  $$$$$$/   | $$  |  $$$| $$  | $$|  $$$$$$/|  $$$$$$/ /$$$$$$ /$$$$$$      |  $$$$$$$| $$        |  $$$$/    |  $$$$$$$| $$       | $$ \  $$|  $$$$$$/| $$  |  $$$$//$$$/
|__/       \______/    |__/   \___/|__/  |__/ \______/  \______/ |______/|______//$$$$$$\_______/|__/         \___//$$$$$$\_______/|__//$$$$$$|__/  \__/ \______/ |__/   \___/ |___/
                                                                                |______/                          |______/            |____
```

<details>
  <summary>Flagg</summary>
  
  `PST{ASCII_art_er_kult}`
</details>


## Oppgave dag 11

Oppgaveteksten til denne oppgaven ble sendt i 2 deler. Den ene inneholdt data for AES kryptering, den andre inneholdt en bit av AES nøkkelen.

```
{"nonce": "iGfRlHEx5cYvehl2YYZv9w==", "ciphertext": "E3nvYDlJHG7R0XBQevJEBAHmoaqOdaI1sfX64d5bF+82cvzdZXhS9IVYVmXgE72kvdkZ+h92mGZ0YLx9pX+PbPPtB/JS", "tag": "nAjcHbhnjYtwMAHSHrcHsA=="}
```

For å løse oppgaven må du få tak i de andre delene. Det gjør man med å sammarbeide med personer fra de andre "lagene", NPST, NISM og kriapos:

```
Hemmelighet #1 (NPST)
980daad49738f76b80c8fafb0673ff1b
Hemmelighet #2 (NISM)
a3c5a5a81ebc62c6144a9dc1ae5cce11
Hemmelighet #3 (KRIAPOS)
fc78e6fee2138b798e1e51ed15e0a109
```

Oppgaven kan løses med cyberchef eller med python. Nøkkelbitene kan kombineres ved å bruke bitwise XOR, `^`. Videre settes dataene fra fila inn, og plaintexten blir dekryptert. 

```py
from Crypto.Cipher import AES
from base64 import b64decode
import json

key = hex( 0x980daad49738f76b80c8fafb0673ff1b ^ 0xa3c5a5a81ebc62c6144a9dc1ae5cce11 ^ 0xfc78e6fee2138b798e1e51ed15e0a109 )
key=key[2:]
print(key)

with open("melding.enc", "rb") as f:
    try:
        data = json.loads(f.read())
        nonce = b64decode(data["nonce"])
        ciphertext = b64decode(data["ciphertext"])
        tag = b64decode(data["tag"])
        cipher = AES.new(bytes.fromhex("c7b0e9826b971ed41a9c36d7bdcf9003"), AES.MODE_GCM, nonce = nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print("Dekryptert melding: " + plaintext.decode('utf-8'))
    except (ValueError, KeyError) as e:
        print(f"An error occurred: {e}")
```

<details>
  <summary>Flagg</summary>
  
  `NSM{9c7cac722d55da1dbfa13025d85efeed45e9ddea2796c0e5ea2fda81ea4de17d}`
</details>


## Oppgave dag 13

Denne OSINT-oppgaven som skal frem til et sted, løses ved å scanne koden på bildet:

![Bilde](assets/bilde.png)

Den enkleste måten å få til dette er å redigere bildet slik at QR-koden blir flat, for så å scanne med en telefon. Scanner du koden får du opp navnet på et wifinettverk til en resturant. Navnet på resturanten er flagget.