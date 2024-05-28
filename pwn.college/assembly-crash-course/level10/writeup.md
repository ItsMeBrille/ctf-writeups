## Solution

Task was solved using python:

import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
AND rax, rdi
AND rax, rsi
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())```

<details>
    <summary>Flag</summary>

pwn.college{cVSHEfuuzg8miwArM_SWUtWDJDM.0VMwIDL5ETN1QzW}</details>
