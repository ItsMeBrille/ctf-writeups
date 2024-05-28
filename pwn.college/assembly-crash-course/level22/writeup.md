## Solution

Task was solved using python:

```py
import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
MOV rax, 0x403000
JMP rax
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())
```

<details>
    <summary>Flag</summary>

    `pwn.college{8J3T-p114GRyx6LhmoYL1AsDZLJ.dVTM4MDL5ETN1QzW}`
</details>
