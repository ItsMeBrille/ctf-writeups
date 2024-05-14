## POKEGLYPHS

### Oppgave

Vi ble gitt en fil, glyphs.txt, med emojier og navn på Pokemons. Vi får også et hint til hva dette kan bety i oppgaveteksten: "Some are big and strong, while others are small and fast."

```
🔮 Vespiquen 🗡️ Carracosta 🛡️ Sandy Shocks 🪄 Bellibolt 🏃 Meowscarada 🪄 Appletun 🪄 Manectric 🛡️ Arctovish 🏃 Minun 🗡️ Tyrantrum 🪄 Salazzle 🗡️ Avalugg 🗡️ Poliwrath 🛡️ Solgaleo 🩸 Reuniclus 🏃 Scream Tail 🛡️ Tyrantrum 🪄 Chimecho 🏃 Heliolisk 🪄 Salazzle 🔮 Tapu Lele 🔮 Primarina 🗡️ Gliscor 🛡️ Durant 🩸 Gastrodon 🛡️ Solgaleo 🔮 Stakataka 🏃 Walking Wake 🏃 Scream Tail 🪄 Latias 🛡️ Seadra 🗡️ Hippowdon 🏃 Swoobat 🪄 Empoleon 🔮 Vespiquen 🗡️ Houndstone 🛡️ Suicune 🩸 Baxcalibur 🩸 Brute Bonnet 🩸 Amoonguss 🪄 Cacturne 🔮 Vaporeon 🏃 Raticate 🏃 Swoobat 🩸 Aromatisse 🔮 Tapu Bulu 🩸 Emboar 🏃 Raticate 🏃 Heliolisk 🩸 Aromatisse 🩸 Dunsparce 🩸 Miltank 🪄 Noivern 🛡️ Vespiquen 🗡️ Cinderace 🗡️ Houndstone 🛡️ Iron Bundle 🔮 Silvally 🔮 Bronzong 🔮 Polteageist 🛡️ Obstagoon 🩸 Aromatisse 🏃 Persian 🏃 Crabrawler 🪄 Gardevoir
```

### Løsning

Løsningen på denne oppgaven er å løse emoji og pokemon i par. Emojien symboliserer en stat for pokemonen. Eksempelvis 🗡️ for attack-stat og 🛡️ for defence-stat. Tallene for hver egenskap tilsvarer asciibokstaver.

Jeg bruker [pokeapi](https://pokeapi.co/) for å finne egenskapene for alle pokemonene. Noen av pokemonene er ikke oppført i apien på vanlig måte, derfor krever noen at jeg gjør et ekstra søk for å hente et gyldig navn på den pokemonen som kan brukes i APIet. Her er løsningen i python:

```py
import requests

def fetch_pokemon_data(pokemon_name):
    url = f"https://pokeapi.co/api/v2/pokemon/{pokemon_name}"
    response = requests.get(url)

    if response.status_code == 200:
        # If the request is successful, return the JSON data
        return response.json()
    else:
        # If pokemon does not exist search as spicies instead
        url = f"https://pokeapi.co/api/v2/pokemon-species/{pokemon_name}"
        response = requests.get(url)
        if response.status_code == 200:
            # If the request is successful try getting the default pokemon for found species
            return fetch_pokemon_data(response.json()[varieties][0]["name"])


# List of emojies (ordered as they appear in the api)
emojis = ["🩸", "🗡️", "🛡️", "🪄", "🔮", "🏃"]

# Open data
with open("glyphs.txt", 'r', encoding='utf-8') as file:
    text = file.readline()

# Split at each emoji
for e in emojis:    
    text = text.replace(e, f"!{e}?")
text = text.split('!') # Lag et array med alle emojier og pokemons.
        
string = ""
for i in range(1, len(text)):
    emoji = text[i].split("?")[0]
    pokemon = text[i].split("?")[1].strip().lower().replace(" ", "-")
    
    data = fetch_pokemon_data(pokemon)

    # Check each emoji
    for n, e in enumerate(emojis):
        if(emoji == e):
            string+=chr(data["stats"][n]["base_stat"])
            break

print(string) # Print result
```

Programmet printer ut en lang tekst der flagget ligger i klartekst.

<details>
  <summary>Flagg</summary>
  
  `flag{did_you_know_most_pokemon_professors_are_named_after_trees?}`
</details>