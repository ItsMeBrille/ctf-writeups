# OSINTRO

Here's a crash course in OSINT/Open Source Intelligence - the art of research through public sources like search engines, social media, databases and more.

The flag is in three parts. Assemble them in lowercase letters, separated by underscores, like this: flag{nameofaplace_keyword_carbrand}. Ie. flag{oslo_tittentei_tesla}.

Part 1 is GEOINT, deriving where an image is shot from visual cues. Find the right city by looking for shop names, unusual flora, road signs, logos etc. to narrow the search, and confirm your hypothesis with Google Street View.

Part 2 is so called pivoting. Use existing information like a target's username, interests, profile pictures or real name to find other online profiles and gather information.

Part 3 is about classic research. Google and other search engines are often times your best friends in a CTF, whether you search with text or images.

Remember: Even though there are a lot of nifty tools and shortcuts, the most important OSINT technique is thinking like a detective. Gather and compare clues to make your own hypothesis about what is the right path, and more importantly: what isn't :)

---

## Del 1

Google bildesøk gir treff på "Kragerø Rådhus".

- <https://www.google.com/maps/place/Krager%C3%B8+kommune/@58.8679828,9.4108379,3a,75y,29.96h,86.23t/data=!3m6!1e1!3m4!1soBOV8wK5cCGgmcTXdgY6-A!2e0!7i16384!8i8192!4m14!1m7!3m6!1s0x4647040ed571386b:0x518a658191cba0b0!2sKrager%C3%B8+kommune!8m2!3d58.8679617!4d9.4110961!16s%2Fg%2F1vnrp68n!3m5!1s0x4647040ed571386b:0x518a658191cba0b0!8m2!3d58.8679617!4d9.4110961!16s%2Fg%2F1vnrp68n?entry=ttu>

Svar: `kragerø`

## Del 2

Et søk etter `xsecrom4nc3rx` med Sherlock gir:

```
sherlock xsecrom4nc3rx
[*] Checking username xsecrom4nc3rx on:

[+] Archive.org: https://archive.org/details/@xsecrom4nc3rx
[+] BitCoinForum: https://bitcoinforum.com/profile/xsecrom4nc3rx
[+] CGTrader: https://www.cgtrader.com/xsecrom4nc3rx
[+] Coders Rank: https://profile.codersrank.io/user/xsecrom4nc3rx/
[+] Contently: https://xsecrom4nc3rx.contently.com/
[+] HackerEarth: https://hackerearth.com/@xsecrom4nc3rx
[+] Linktree: https://linktr.ee/xsecrom4nc3rx
[+] NationStates Nation: https://nationstates.net/nation=xsecrom4nc3rx
[+] NationStates Region: https://nationstates.net/region=xsecrom4nc3rx
[+] Oracle Community: https://community.oracle.com/people/xsecrom4nc3rx
[+] Reddit: https://www.reddit.com/user/xsecrom4nc3rx
[+] SoundCloud: https://soundcloud.com/xsecrom4nc3rx
[+] hunting: https://www.hunting.ru/forum/members/?username=xsecrom4nc3rx
[+] metacritic: https://www.metacritic.com/user/xsecrom4nc3rx
```

Oppgaven krever at man lager en konto et sted.

Etter å ha søkt etter brukernavnet på Google kommer det opp treff relatert til tise.com (relevant for shopping)

- <https://tise.com/xsecrom4nc3rx>

Den ene posten viser et bilde av en bok foran en macbook som er inne på <https://soundcloud.com/xsecrom4nc3rx>
Soundclouden lenker til Pintrest

- <https://gate.sc/?url=https%3A%2F%2Fwww.pinterest.com%2Fcoolinfosecromancer%2F&token=6a4fb5-1-1710234463950>

De 2 postene på profilen er av en Roblox-karakter. På en av postene står det:

> So hooked, surely the most trve kvlt game around >:) Find my profile and hit me up some time if you think you have what it takes >:)

`trve kvlt` fra ROT13 = `geir xiyg`. Hvis man bytter om `v` og `u` kan man få `true kult`.

Via <https://rblx.trade/u/coolinfosecromancer> kan man finne robloxprofilen::

- <https://www.roblox.com/users/5516008762/profile>
- <https://www.roblox.com/games/16185491960/coolinfosecromancers-Place>

Må laste ned spillet for å se mappet

Flagget lå på profilen. I biografien står det:

>  Guess you found me, that means you're a part of the most secro inner circle on the planet right now >:) The flag part you're looking for is "blackhatmorelikewackhat" >:) l8r 

Svar: `blackhatmorelikewackhat`

## Del 3

Refererer til Olsenbanden.

Deres biler: <https://no.wikipedia.org/wiki/Olsenbanden_(Norge)#Bandens_biler>

Denne artikkelen sier at Benny sin favorittbil var `Mercury Monterey`: <https://www.abcnyheter.no/motor/bil/2019/11/03/195623412/benny-fra-olsenbanden-favoriserte-en-biltype?nr=1>

Flesteparten av bilene i artikkelen er Chevrolet.

Svar: `chevrolet`

Flagg: `flag{kragerø_blackhatmorelikewackhat_chevrolet}`
