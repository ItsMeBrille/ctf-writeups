## Solution

Task was solved using python:

import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
AND rax, rdi
AND rax, 0x01
XOR rax, 0x01
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())```

<details>
    <summary>Flag</summary>

pwn.college{ItJQdfTa_Q4Sv5vUmkhXwLdLnZp.0lMwIDL5ETN1QzW}</details>
