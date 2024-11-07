# S2G

# CRYPTOGRAPHY

## ENCODED TWIST

### Oppgave

Hele oppgavebeskrivelsen finnes [her](cryptography/encoded_twist/challenge.md)

### Løsning

```py
import string
import base64

input_string = "Z4OMj4eqRrOoS4mmRId6TYioR4KpRLR+RIh3TIV7SIF3eIp1kV=="
shift = -5

# Define the custom alphabet
alphabet = string.ascii_uppercase +  string.ascii_lowercase + string.digits + "+/"
alphabet_size = len(alphabet)  # The size of the alphabet (62)

# Prepare the result as a list (for efficiency in appending characters)
result = []

for char in input_string:
    if char in alphabet:
        original_index = alphabet.index(char)
        new_index = (original_index + shift) % alphabet_size
        result.append(alphabet[new_index])
    else:
        result.append(char)

# Join the result list into a string and return
print(base64.b64decode(''.join(result)).decode("utf-8"))
```

<details>
<summary>Flagg</summary>

`S2G{6e2bc78a06597c31d0c>072846402d90}`
</details>


