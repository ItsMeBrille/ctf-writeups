## DATA REPRESENTATION

### Løsning
Brukte CyberChef for å konvertere base64, men med et alternativt alfabet:
https://gchq.github.io/CyberChef/#recipe=From_Base64('hqOVkntvaFdU%C3%A6zEDXHiS%C3%B8fWrKy%C3%86QCBMbuIYwsglJoAeNZ%C3%85%C3%98mcjGxPp%C3%A5RTL%C3%A7%C3%A9%C3%BB295',true,false)&input=eWxqSXlSxUHG5cVnVXJEZ1VyZlrGV8VQVVdGSUPl%2BOV6T3BneeVm2EJ0akF5UlA9

<details>
  <summary>Flagg</summary>
  
  `flag{ikke-så-ulikt-base64-egentlig}`
</details>


## ENCODING

### Løsning
Brukte ChatGPT for å generere 3 funksjoner som omgjør ordet til bin, hex og dec. Viktig å huske at desimaltallet skal finnes numerisk, og at det fort kan bli kluss med ferdigbakte funksjoner som omgjør med å slå opp i ascii-tabellen.
```py
def word_to_hex(word):
    return ''.join(hex(ord(char))[2:] for char in word)

def hex_to_binary(hex_string):
    return ''.join(bin(int(char, 16))[2:].zfill(4) for char in hex_string)

def hex_to_decimal(hex_string):
    return int(hex_string, 16)

word = "magi"
hex_ascii = word_to_hex(word)
binary_ascii = hex_to_binary(hex_ascii)
decimal_ascii = hex_to_decimal(hex_ascii)

print(f"flag{{{binary_ascii},{hex_ascii},{decimal_ascii}}}")
```

<details>
  <summary>Flagg</summary>
  
  `flag{01101101011000010110011101101001,0x6d616769,1835100009}`
</details>