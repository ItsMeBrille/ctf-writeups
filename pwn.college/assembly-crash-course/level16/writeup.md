## Solution

Task was solved using python:

```py
import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
MOV rax, 0x00
MOV al, [0x404000]
MOV rbx, 0x00
MOV bx, [0x404000]
MOV rcx, 0x00
MOV ecx, [0x404000]
MOV rdx, [0x404000]
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())
```

<details>
    <summary>Flag</summary>

pwn.college{spQ_UkFG8wL6swz5EZvMZ8NBAgY.0FNwIDL5ETN1QzW}</details>
