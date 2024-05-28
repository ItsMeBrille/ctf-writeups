## Solution

Task was solved using python:

```py
import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
MOV rax, [rdi]
MOV rbx, [rdi+8]
ADD rax, rbx
MOV [rsi], rax
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())
```

<details>
    <summary>Flag</summary>

pwn.college{sZndsKd7Se4vyPwdrY6jI7NW5zX.0lNwIDL5ETN1QzW}</details>
