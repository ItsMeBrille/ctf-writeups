## THE NORRINGTON CREW 1

### Oppgave

Oppgaven gir oss en E01-evidencemappe som inneholder et windowsfilsystem, samt en PDF som hinter til hvordan systemet er blitt infisert.

Første oppgave er å finne navnet på malwaren, samt navnet på programmet som har blitt infisert: `flag{NAMEOFMALWARE.exe,NAMEOFPROGRAM.exe}`


### Løsning

I PDFen får vi hint om hvilket program som blir infisert: `The DLL mimics wellknown DLLs associated with media player applications on the victim’s system`. Her er det snakk om VLC MediaPlayer (`vlc.exe`)

For å finne navnet på malwaren åpnet jeg E01-filen med FTK Imager, og lette rundt etter en eller annen mistenkelig executable. Jeg endte til slutt opp i listen over prosesser i `windows/prefetch` og fant en exe-fil med et veldig mistenkelig navn :)

<details>
<summary>Flagg</summary>

`flag{GratisFilmerForFree.exe,vlc.exe}`
</details>


## THE NORRINGTON CREW 2

### Oppgave

Oppgave bygger på vedleggene vi fikk i forrige oppgaven og vi skal frem til "registry key and domain that is beaconed at startup": `flag{registrykey,domain}`


### Løsning

I `Users/%usename%` finnes en fil, `NTUSER.DAT`. Denne filen inneholder informasjon om ulike registers på systemet. Denne filen kan eksporteres ut fra E01-mappen og åpnes i Windows Registry Editor.

Registeret vi er ute etter ligger i oppstartsmappen `SOFTWARE/Microsoft/Windows/CurrentVersion/Run`. Der finner jeg et register som forsøker å pinge et domene som kan knyttes til en av organisjasjonene det står om i PDFen. Flagget er navnet på registeret og domenet den forsøker å kontaktet satt sammen.


<details>
<summary>Flagg</summary>

`flag{WindowsUpdateTelemetry,filmpolitiet-icmp-beacon.no}`
</details>


## THE NORRINGTON CREW 3

### Oppgave

Oppgave bygger på vedleggene vi fikk i forrige oppgaven og krever at du undersøker hvil.
`flag{c:\path\to\fake\dll.dll,powershellscript.ps1,newnamelegitimatedll.dll}`


### Løsning

Jeg bruker et program for å åpne prefetch filene i `/windows/prefetch`-mappen. Den inneholder interessant informasjon om hvilke utvidelser (dll) ulike programmer interagerer med. De interessante filene å se på er `GratisFilmerForFree` og `vlc.exe`.

`GratisFilmerForFree.exe` interagerer med en fil med det mistenkelige navnet `libvlc.dll`. Den samme filen finnes også i lista til `vlc.exe`. `vlc.exe` laster filen fra mappen `/windows`. Itillegg kan vi også se at denne fila har filnavnet sitt skrevet i lowercase der de opprinnelige filene er i uppercase.
`GratisFilmerForFree.exe` interagerer lager også en fil kaldt `teitilopmlif.ps1` i mappen `/Windows/Temp`.

Den siste delen av utfordringen er å finne ut hvor det ble av den originale `libvlc.dll`-fila. Vi kan se at det i mappen `GratisFilmerForFree.exe` interagerer med det mistenkelig like navnet `libvlcx.dll`, uten at det er en del av en normal vlc-installasjon. Dette er originalfilen med nytt navn.

<details>
<summary>Flagg</summary>

`flag{c:\windows\libvlc.dll,teitilopmlif.ps1,libvlcx.dll}`
</details>


## THE NORRINGTON CREW 4

### Oppgave

Oppgave bygger på vedleggene vi fikk i forrige oppgaven og krever at du undersøker handlemåten til powershell-scriptet generert av malwaren.
`flag{decimalnumberofcommands,nameoffile.ext}`


### Løsning

PS1 scriptet kjører flere kommandoer og piper resultatet til en annen fil i `Temp`-mappen. Filens navn avslører at det er denne filen som inneholder dataen som blir sendt tilbake til TA.

<details>
<summary>Flagg</summary>

`flag{4,sendback.txt}`
</details>


## THE NORRINGTON CREW 5

### Løsning

Angrepsmetoden finner man lett ved å søke etter vlc på [attack.mitre.org](https://attack.mitre.org/), og jobbe ut ifra resultatene. Her er det to alternativer: [DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/) eller [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/). Ettersom malwaren ikke manipulerer hvilke DLL files som lastes må det være den siste.

SHA1 hashen er noe vanskeligere å finne ettersom vi ikke har filen som skal hashes. Derfor forsøker jeg å finne ut om filinfo kan ha blitt logget et sted. I `Windows/appcompst/Programs` finnes det Amcache.hve-logger. Disse filene kan parses til .CSV ved å bruke EricZimmermans [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser?tab=readme-ov-file). Resultatet blir et par CSV-filer. I en av listene finner jeg malwarefila kjent fra tidligere:

```csv
... SHA1,IsOsComponent,FullPath,Name, ...
... ff0b253e9315b7e869f6e33cc4865bcb4287ac34,True,c:\windows\system32\em.exe,EM.exe ...
... a30e4111e183514def89d2bc31071231deabc4df,True,c:\windows\explorer.exe,explorer.exe ...
... 607a5beeb5c316fd95ba43acd641eb487fe77f2f,False,c:\users\jacques\downloads\gratisfilmerforfree.exe,GratisFilmerForFree.exe ...
...
```

<details>
<summary>Flagg</summary>

`flag{607a5beeb5c316fd95ba43acd641eb487fe77f2f,T1574.001}`
</details>