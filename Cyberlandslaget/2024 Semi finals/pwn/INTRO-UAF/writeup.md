## INTRO-UAF

### Oppgave

```
##########  ##########  ##########  ##########  ##########
#00000000#  #00000000#  #00000000#  #00000000#  #00000000#
#00000000#  #00000000#  #00000000#  #00000000#  #00000000#
#00000000#  #00000000#  #00000000#  #00000000#  #00000000#
#00000000#  #00000000#  #00000000#  #00000000#  #00000000#
##########  ##########  ##########  ##########  ##########

1. New command
2. Execute command
3. New thing on heap
4. Edit thing on heap
5. Delete thing on heap
6. Show my things
7. Exit
```

### Løsning

Trikset for å løse denne oppgaven er å starte med å lagre data i en blokk kun for å slette det igjen. Det gjør at vi kan redigere det senere. Når jeg nå oppretter en ny kommando fyller den den samme blokken. Siden det er den samme blokken som er allokert i minnet kan jeg oppdatere innholdet i blokken. Kjører jeg den nye, oppdaterte kommandoen får jeg flagget i klartekst.

1. Lagre tekst: `3` -> `0` -> `foo`
1. Slett tekst: `5` -> `0`
1. Ny kommando: `1` -> `1`
1. Oppdater blokk: `4` -> `0` -> `cat flag.txt`
1. Kjør kommando: `2`

<details>
  <summary>Flagg</summary>
  
  `flag{c1522fa2b3c1599b03b1391de70f68dc}`
</details>