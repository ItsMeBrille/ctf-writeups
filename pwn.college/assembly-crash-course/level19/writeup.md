## Solution

Task was solved using python:

```py
import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
POP rax
SUB rax, rdi
PUSH rax
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())
```

<details>
    <summary>Flag</summary>

pwn.college{Au9L-06e5YovfjEzlGhdHAKoLZp.01NwIDL5ETN1QzW}</details>
