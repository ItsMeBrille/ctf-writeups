## Solution
This task was solved using pwntools in python:
```
import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
add rdi, 0x331337
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())
```

<details>
    <summary>Flag</summary>

    pwn.college{INzQ8ewxXVqpF75GENmODlxI6O5.0VN5EDL5ETN1QzW}
</details>
