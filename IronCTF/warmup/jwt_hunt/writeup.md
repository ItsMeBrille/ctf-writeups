## JWT HUNT

### Task



*PS: Task can be found here [here](challenge.md)*

### Solution

First part is found in a robots.txt:
`6yH$#v9Wq3e&Zf8L`

Second part in a cookie:
`pRt1%Y4nJ^aPk7Sd`

Third in sitemap.xml:
`2C@mQjUwEbGoIhNy`

In robots.txt we also get a hint that the fourth part can be found at /secretkeypart4, but a normal get regquest gives BAD REQUEST. The same goes for POST. Therefore the solution is a HEAD request:

```bash
curl -X POST https://jwt-hunt.1nf1n1ty.team/secretkeypart4
```
`0T!BxlVz5uMKA#Yp`

Secret key then becomes:
`6yH$#v9Wq3e&Zf8LpRt1%Y4nJ^aPk7Sd2C@mQjUwEbGoIhNy0T!BxlVz5uMKA#Yp`

[JWT.io](https://jwt.io/) can now be used to alter the username in the token to admin. You then get redirected to /admin and you get the flag.

<details>
<summary>Flag</summary>

`ironCTF{W0w_U_R34lly_Kn0w_4_L07_Ab0ut_JWT_3xp10r4710n!}`
</details>