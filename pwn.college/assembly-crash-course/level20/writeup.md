## Solution

Task was solved using python:

```py
import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
PUSH rdi
PUSH rsi
POP rdi
POP rsi
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())
```

<details>
    <summary>Flag</summary>

pwn.college{s2FuSpjt4FYib36Xa1JMMPWKiUT.0FOwIDL5ETN1QzW}</details>
