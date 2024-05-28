## Solution

Task was solved using python:

import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
shr rdi, 0x20
mov al, dil
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())```

<details>
    <summary>Flag</summary>

pwn.college{oSmjizAd_GQAzvstfn0RZKRdOdg.0FMwIDL5ETN1QzW}</details>
