# S2G

## CRYPTOGRAPHY

## JULIUS CEASAR

### Oppgave

Hele oppgaven finnes [her](cryptography/julius_ceasar/challenge.md)

### Løsning

Rot 7 for å finne flagget.
L2Z{b_axkxur_lpxtk_mh_ux_t_gxkw}

<details>
<summary>Flagg</summary>

`S2G{i_hereby_swear_to_be_a_nerd}`
</details>


## SUBSTITUTE

### Oppgave

Hele oppgaven finnes [her](cryptography/substitute/challenge.md)

### Løsning

Limer Chipertext og encoda flagg inn i samme tekst og bruker chiperanalyse for å løse:
https://www.boxentriq.com/code-breaking/cryptogram

<details>
<summary>Flagg</summary>

`S2G{well_well_well_how_the_turntables}`
</details>



## OSINT

## BLUE BUS

### Oppgave

Hele oppgaven finnes [her](osint/blue_bus/challenge.md)

### Løsning

Finner først byen ved å søk opp fargen på bussen.

Så bruker jeg rutenummeret på bussen for å finne ut hvilken rute bussen kjører.

Vi ser i gjenskinnet fra bussen at bildene er fra det er Street View i 2024.

Derfor plasserer jeg streetview-mannen i starten av ruten og følger bussens rute i streetview helt til jeg møter den blå bussen med burger på siden. Det gjør jeg på stasjonen Odenplan som ligger i riktig gate.

<details>
<summary>Flagg</summary>

`S2G{Karlbergsvägen}`
</details>


## BUILDING

### Oppgave

Hele oppgaven finnes [her](osint/building/challenge.md)

### Løsning

Kjenner igjen stedet som ble rammet av flom. Det er ved Strandtorget i Lillehammer

<details>
<summary>Flagg</summary>

`S2G{mcdonalds}`
</details>


## ICY CITY

### Oppgave

Hele oppgaven finnes [her](osint/icy_city/challenge.md)

### Løsning

Et søk på Svalbard Kirke og Greenland Church gir et par kirker å sammenlikne med. Et av bildene jeg får opp matcher kirken på bildet. Da har jeg riktig sted.

<details>
<summary>Flagg</summary>

`S2G{Ilulissat}`
</details>


## MR SPY

### Oppgave

Hele oppgaven finnes [her](osint/mr_spy/challenge.md)

### Løsning

Googlesøk gir en linkedinbruker: `mr ntnu spy`

Brukeren har flere innlegg på linkedin, blant annet [ dette innlegget](https://www.linkedin.com/posts/mr-ntnu-spy-b6a429218_r0vuic9iywnrzg9vci9ydw4y21kpwvjag8rilmyr3tpbl9legnoyw5nm19mmhjfcg93zxjfav9smhn0x215x2hhmxj9iis-activity-6825812105749426176-Y6vD?utm_source=share&utm_medium=member_desktop).
```
R0VUIC9iYWNrZG9vci9ydW4/Y21kPWVjaG8rIlMyR3tpbl9leGNoYW5nM19mMHJfcG93ZXJfaV9sMHN0X215X2hhMXJ9Iis+K2ZsYWcudHh0IEhUVFAvMS4xCkhvc3Q6IG50bnUubm8KQ29va2llOiBQSFBTRVNTSUQ9M2U0dXBxdDlyYm02dTFtdXVpOTZqdnBnZTEKQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS93ZWJwLCovKjtxPTAuOApBY2NlcHQtTGFuZ3VhZ2U6IGVuLVVTLGVuO3E9MC41CkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZQpDb25uZWN0aW9uOiBjbG9zZQoK
```

<details>
<summary>Flagg</summary>

`S2G{in_exchang3_f0r_power_i_l0st_my_ha1r}`
</details>


## RESTAURANT

### Oppgave

Hele oppgaven finnes [her](osint/restaurant/challenge.md)

### Løsning

Bildet er fra et spill.
Reverse image serach gir ingen resultater, men dersom vi ser på spesifikke områder av bildet får vi et par resultater fra steam workshop.

Da vet vi at spillet er CS2, og at kartet det er fra er Memento.

En kjapp titt innom noen youtubevideoer med gameplay fra kartet avslører navnet over døre på resturanten.

<details>
<summary>Flagg</summary>

`S2G{la serra}`
</details>



## REVERSE_ENGINEERING

## FLAG DOT TEXT

### Oppgave

Hele oppgaven finnes [her](reverse_engineering/flag_dot_text/challenge.md)

### Løsning

Ghidra analyserer binary-fila.

Funksjonen write_to_file() inneholder et array som kan dekodes fra Charcode. Dette kan til og med gjøres bare ved å peke på strengen i Ghidra.

<details>
<summary>Flagg</summary>

`S2G{i_H8_j0ffrey_b4rath30n}`
</details>



## STEGANOGRAPHY

## SOUND CREEP

### Oppgave

Hele oppgaven finnes [her](steganography/sound_creep/challenge.md)

### Løsning

Lydfila kan analyseres med spektrumanalyse for å vise frekvensene i lydfila. I slutten av lydfila ser vi mange suspekte tegn og ordet flag, som hinter om av vi er på riktig spor.

Etter mye letning finner jeg at tegnene er Pigpen

Dekrypteres hvert tegn med Pigpen får vi et navn. Dette er flagget.

<details>
<summary>Flagg</summary>

`S2G{jeremiah_denton}`
</details>



## WEB

## SAFE KEY

### Oppgave

Hele oppgaven finnes [her](web/safe_key/challenge.md)

### Løsning

Under `flag.txt` finner vi flagget som skal crackes

I `hints.txt` finner vi ut at vi ser etter en vigenere.key, og `Apache HTTP Server version is: 2.4.49` avslører hvilken webserver som hoster filene.

Denne Apache versjonen har en kritisk sårbarhet som vi kan utnytte: [CVE-2021-41773](https://www.exploit-db.com/exploits/50383).

Videre finner jeg et pythonskript som kan brukes for hente ut en fil gjennom sårbarheten:
[script på github](https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution/blob/main/exploit.py)

```bash
python exploit.py 10.212.138.23 10872 file '/etc/vigenere.key''
```

Nå har vi både chipertext og key, så nå kan denne [løses i CyberChef med Vigenere Decode](https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('zxcvbnmasdfnugrrjaklbdpwkanfuelsnuqwerjklanbuekfgasleibgmear')).

<details>
<summary>Flagg</summary>

`S2G{apieceofclothusuallyrectangularandattachedtoapoleatoneedge}`
</details>


## SHAREZ

### Oppgave

Hele oppgaven finnes [her](web/sharez/challenge.md)

### Løsning

Vi ser at det ikke er noen restriksjoner på hvilke filer vi kan laste opp og at vi blir presentert alle filene vi laster opp.

Derfor laster vi opp en ondsinnet PHP-fil som forsøker å finne en fil kalt `flag.txt`:

```php
<?php echo file_get_contents('/flag.txt');?>
```

Åpner scriptet vi laster opp kjører det på serveren og gir oss flagget.

<details>
<summary>Flagg</summary>

`S2G{d0Nt_tRuST_4rB1tRArY_f1l3_uPL04dz}`
</details>


