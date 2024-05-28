## Solution

Task was solved using python:

```py
import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
MOV rax, 0xdeadbeef00001337
MOV [rdi], rax
MOV rax, 0xc0ffee0000
MOV [rsi], rax
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())
```

<details>
    <summary>Flag</summary>

pwn.college{Y7jPmpB9mm_GoG__j0xywKnB5gk.0VNwIDL5ETN1QzW}</details>
