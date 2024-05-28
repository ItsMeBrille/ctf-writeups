## Solution

Task was solved using python:

```py
import pwn
pwn.context.update(arch="amd64")
code = pwn.asm(f"""
JMP .+0x53
{"nop;"*int("51", 16)}
MOV rax, 0x01
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())
```

<details>
    <summary>Flag</summary>

    `pwn.college{YshrYt0tKQQntKn--V6b11fYZLD.dZTM4MDL5ETN1QzW}`
</details>
