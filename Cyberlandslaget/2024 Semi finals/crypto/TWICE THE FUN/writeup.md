## TWICE THE FUN

### Oppgave

Oppgaven gir et flagg kryptert med en variasjon av RSA. Målet blir å finne `p` og `q`, som er faktorer vi må ha for å løse opp kryptoen, der vi er gitt `n`. 


### Løsning

Sårbarheten ligger i måten `n` er regnet ut fordi det er mulig å faktorisere det. Vi vet at `n = p*p*q`. Og at q regnes ut ifra verdien til `p`. Vi kan derfor anslå at `p` er ca. kuberoten til `n`. I python bruker jeg `gmpy2` for å regne ut kubroten siden tallet er for stort til å regne på normalt vis.

Videre regner vi ut en q for den anslåtte verdien og sjekker om det gir riktig n. Vi vet at siden q skal være større enn 2p vil p sansynligvis være mindre enn `p` vi nettopp anslo. Derfor trekker vi fra 1. på `p` og gjentar prosessen helt til vi finner riktig verdier for både `p` og `q`.

Når vi har `p` og `q` kan vi dekryptere RSA på normalt vis.

```py
from Crypto.Util.number import inverse, isPrime, long_to_bytes
import gmpy2

# Derive p and q from n
def find_p_q_from_n(n):
    p = gmpy2.iroot(n // 2, 3)[0] # Approximate p
    while True:
        q = 2*p+1
        while not isPrime(q):
            q+=2

        if(n==p*p*q): # We use formula for n to know when we hit right numbers
            return p, q
        p-=1

n = 1504669465049250683772825812578432054507293469234421835013894405310029960001983693956912395839709925438318274076100369116441789151651472045481303645596451178044586947308741326342766946348630525172225455603087171717275879906781697990672417080309828718603899890408758061554793354470946237190153046132595139051833787905084525716653409952939965245932629241867891105816295312963551089357342449126371563191942303757697572037235418723425388339389144253372697659489780008584869576092272222910562814998683399481883646227829886163589601081060863166903096435784100163915678274553319845314634193005315230701522142083632691208361739899372423774622550914730653670856567925991737570190700269083750650059188495925847590358041692543397415444779391909829587672451139072901892332418440718339037451719206793643432918776943522136979576087474253202699170303465845463979782634173216861141355335128763721879090387732568316702463122261502225660041393
p, q = find_p_q_from_n(n)

# Decrypt RSA
def rsa_decrypt(ciphertext, p, q, e):
    # Decrypt
    n = p * q # Step 1: Calculate n
    phi_n = (p - 1) * (q - 1) # Step 2: Calculate phi(n)
    d = inverse(e, phi_n) # Step 3: Calculate d
    plaintext = pow(ciphertext, d, n)# Step 4: Decrypt the ciphertext
    # Convert
    plaintext_bytes = long_to_bytes(plaintext)# Convert plaintext to bytes
    return plaintext_bytes

# Example values (replace these with actual values)
ct = 1304424190919978876516800524936732535532889212279025759778938075403767104703994460355369908632042199926149864229966072220749061756015880633984287139530817670037731556700936668736014989128856941038121333449588710935013940725082131681654786817546535502072597057812967566401390904999857172755875652077686441199446358707719166532919322359752139647281271460380115732970033292260235562514459742596317748033907941341286128923469731299426798487768259349309102647352830542470415205883224743817436632111612977604456791428544839714257697225218521957257406883183240852084583257505766030666213438250352938521045852442046803332778113751573967669159177519544254188988368501518323140661079215900643367288348959601085977045971903041287754216564261136081134377929847610332430007367178900393794281046030435979302273565405946127574246195294766619502018813897322043850150369281085460873488367977594234564181865623144922047666987103613594370175407
e = 65537

# Decrypt the ciphertext
plaintext = rsa_decrypt(ct, p, q, e)
print(f"Decrypted message: {plaintext.decode()}")
```

<details>
<summary>Flagg</summary>

`flag{hvis_n_kan_faktoreres_blir_det_problemer}`
</details>