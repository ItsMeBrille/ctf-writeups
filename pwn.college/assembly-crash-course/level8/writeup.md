## Solution

Task was solved using python:

import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
mov al, dil
mov bx, si
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())```

<details>
    <summary>Flag</summary>

pwn.college{8xc85qUZMipZ9O-XhYwAyLzXTiM.0VO5EDL5ETN1QzW}</details>
