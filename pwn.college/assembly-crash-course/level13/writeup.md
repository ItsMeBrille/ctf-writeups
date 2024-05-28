## Solution

Task was solved using python:

import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
MOV [0x404000], rax
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())```

<details>
    <summary>Flag</summary>

pwn.college{0ujoyUojax6bXvuXJ2JL-yEVRJZ.dNTM4MDL5ETN1QzW}</details>
