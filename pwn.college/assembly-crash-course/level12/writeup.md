## Solution

Task was solved using python:

import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
MOV rax, [0x404000]
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())```

<details>
    <summary>Flag</summary>

pwn.college{IkEaCL-rqKBGv8zmZZ9krYtMZTS.dJTM4MDL5ETN1QzW}</details>
