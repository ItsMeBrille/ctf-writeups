## MAKING BAKING PANCAKES

### Oppgave

```
Welcome to the pancake shop!
Pancakes have layers, we need you to get through them all to get our secret pancake mix formula.
This server will require you to complete 1000 challenge-responses.
A response can be created by doing the following:
1. Base64 decoding the challenge once (will output (encoded|n))
2. Decoding the challenge n more times.
3. Send (decoded|current challenge iteration)
Example response for challenge 485/1000: e9208047e544312e6eac685e4e1f7e20|485
Good luck!
```

*PS: Hele oppgaven finnes [her](challenge.md)*

### Løsning

```py
from pwn import *

io = remote("chal.pctf.competitivecyber.club", 9001)

for i in range(1000):
    # Read challenge
    io.recvuntil(b"Challenge: ")
    challenge = b64d(io.recvline())
    challenge = challenge.split(b"|")
    
    # Read challenge number
    io.recvuntil(b"(")
    chall_num = io.recvuntil(b"/", drop=True)
    
    # Decrypt n times
    for n in range(int(challenge[1])):
        challenge[0] = b64d(challenge[0]).decode("utf-8")

    # Concat answer
    answer = (challenge[0] + "|" + str(int(chall_num))).encode('utf-8')
    print(answer)

    # Send answer
    io.sendlineafter(b">>", answer)

io.interactive()
```

<details>
<summary>Flagg</summary>

`pctf{store_bought_pancake_batter_fa82370}`
</details>