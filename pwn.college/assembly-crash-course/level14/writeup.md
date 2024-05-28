## Solution

Task was solved using python:

import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
MOV rax, [0x404000]
ADD DWORD PTR [0x404000], 0x1337
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())```

<details>
    <summary>Flag</summary>

pwn.college{M6sGcYJzfGl70U--A0HN3MLapSY.01MwIDL5ETN1QzW}</details>
