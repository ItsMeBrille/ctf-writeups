## POKEGLYPHS

### Oppgave

Vi ble gitt en nettside som kjører Flask i python, samt kildekoden til siden. I kildemappen ligger det en `flag.txt`-fil, men det er ingen kode i `app.py`-scriptet som henter fila. Derfor må vi forsøke å angripe nettsiden med egen kode for å hente fila.


### Løsning

Vi kan utnytte at scriptet rendrer teksten vi skriver inn på en uforsiktig måte:

```py
content.format(name=name, text=text, ...)
```

Denne funksjonen er sårbar for Flask injection som lar oss kjøre egen pythonkode (med noen restriksjoner). Koden henter ut flagget fra filen `flag.txt`, men klipper ut første bokstav for å omgå filteret i python-scriptet:

```py
{{ get_flashed_messages.__globals__.__builtins__.open("flag.txt").read()[3:] }}
```

Koden kan plasseres i en av feltene name eller message, og vil gi flagget uten `flag`-prefiksen, så denne setter vi på selv etterpå.

<details>
  <summary>Flagg</summary>
  
  `flag{SSTI_or_Super_Snuggly_Tabby_Infatuation}`
</details>