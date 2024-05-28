## Solution

Task was solved using python:

import pwn
pwn.context.update(arch="amd64")
code = pwn.asm("""
mov rax, rdi
div rsi
mov rax, rdx
""" )
process = pwn.process("/challenge/run")
process.write(code)
print(process.readall())```

<details>
    <summary>Flag</summary>

pwn.college{Am0yRC0FDuhGipNQt6wvvvRzHOg.0FO5EDL5ETN1QzW}</details>
