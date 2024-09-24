## INTRO TO PWNTOOLS

Den en av oppgaven løses gjennom at jeg venter på tekst fra serveren, før jeg svarer med forhåndsbestemt tekst.
Videre er oppgaven å kjøre en binary for å se hva resultatet blir når når den kjører. For å oppnå dette bruker jeg metoden `subprocess.run` og `subprocess.check_output`.
Siste oppgave er å finne adressen til **win_function** i hex. Det løses med en innebygget funksjon i pwntools, `elf.symbols['win_function']` samt pythons `hex()` for riktig format.

Når siste linje er sendt setter jeg konsollen til interactive-modus itillfelle det dukker opp flere ting jeg må svare på. Det er her flagget blir returnert.

```py
from pwn import *

# Set up the connection
host = 'pwn-intro-pwn-intro.challs.cyberlandslaget.no'
port = 31337

# Connect to the remote service
io = remote(host, port)

io.sendlineafter("[yes/no]", "yes")

io.recvuntil("Base64 ELF: ")
binary_data = b64d(io.recvuntil(b"[?] What is the output from running the binary?", True))

import subprocess

# Write the binary data to a temporary file
with open('temp_binary', 'wb') as f:
    f.write(binary_data)

# Make the temporary file executable
subprocess.run(['chmod', '+x', 'temp_binary'])

io.sendline(subprocess.check_output(['./temp_binary']).decode('utf-8'))

elf = ELF('./temp_binary')

win_function_address = elf.symbols['win_function']
io.sendlineafter(b"What is the address of win_function in hex?", hex(win_function_address))

# Done
io.interactive()

# Close the connection
io.close()
```

<details>
  <summary>Flagg</summary>
  
  `flag{pwntools_is_easy_to_learn_but_hard_to_master!}`
</details>