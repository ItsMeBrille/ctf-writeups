## INTRO TO AES

### Løsning

Jeg skjønte fort at poenget med oppgaven var å bruke klarteksten man allerede vet for å kunne knekke krypteringen på det resterende. Jeg ser også at XOR operasjonen trolig er lagt inn som en svakhet med vilje, ettersom det er en operasjon det er enkelt å gjøre "baklengs".

Etter litt analyse av koden oppdager jeg at problemet ligger i kodesnutten `long_to_bytes((i//16)%16,4)`. Problemet er at lengden på teksten overgår lengden denne operasjonen er beregnet på. Etter at løkken har talt lengre enn 256 vil den derfor returnere det samme som tidligere. Dette kan utnyttes ved at jeg lagrer tidligere utregnede ct-verdier og gjenbruker for å finne flagget senere. Koden setter sammen alle bitene og returnerer hele teksten som ble kryptert.

```py
plaintext = open("shakespeare.txt","rb").read()[0:16*16+100]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

ciphertext = "8e7e24751f22bf36361a14f243beb4011469f9764108770874d5e7e0e1656d5e13b1f75a12ee8c972fbc1c31a2ac18b4f4088c5d3a61e2a204ebc1978cadcfa2786bec26f43480a796299a18ac57baf1b8b809af387cdc3f55420a479950351a4bd7da21a3ef6e53ac26c1ee43845f19b21e37775b8bf09b4bf5d220bb888a3d38fc280c972b837a107d98bb5aa1c41f43f6aa73ddd0f73bf16a9f5a41885aff4c4d230c2b22442225dc4a09d5c317d13946f447cd122b207c22c23092a0aa593258e20e978b573c3e6acea22d4ffb3db6d9ddcfc24f1db4fa966240c664631c6de34bb67c2da7b18bd1fd53b45875b06f99c144fa7a866c15dc3ea46b694685d03c07392d0a8a1b063d339724838c64102dd64e7a366d4153d5d9eadb64784e01a6cd266dc4909d30fd1839a7b709befd22"
ct = [0] * 256
flag = ""

for i in range(0, len(plaintext), 16):
    
    if(i<256):
        ct[i] = xor(plaintext[i:i+16], bytes.fromhex(ciphertext)[i:i+16])

    flag += bytes.decode(xor(bytes.fromhex(ciphertext[i*2:i*2+32]), ct[i%256]))

print(flag.strip())
```

<details>
  <summary>Flagg</summary>
  
  `flag{custom_AES-CTR_with_a_reuse_vulnerability}`
</details>