## BAD BLOOD

### Oppgave



*PS: Hele oppgaven finnes [her](challenge.md)*

### Løsning

```py
from pwn import *

while True:
    io = remote("chal.pctf.competitivecyber.club", 10001)

    solutions = [
        b"Invoke-P0wnedshell.ps1",
        b"Invoke-UrbanBishop.ps1",
        b"WinRM",
        b"Covenant"
    ]
    for solution in solutions:
        io.sendlineafter(b">> ", solution)

    io.interactive()

    io.close()
```

<details>
<summary>Flagg</summary>

`pctf{3v3nt_l0gs_reve4l_al1_a981eb}`
</details>