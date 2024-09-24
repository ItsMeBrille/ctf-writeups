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