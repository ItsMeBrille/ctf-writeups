# IRONCTF

## CRYPTO

## ALGEBRA EXAM

### Task

```
x=-3{-6<y<-4}
x=-1{-6<y<-4}
-x-7{-3<x<-2}
x-3{-2<x<-1}
2x+10{-5<=x<=-4}
-2x-6{-4<=x<=-3}
y=1{-4.5<=x<=-3.5}
y=-7{2<x<4}
x=3{-9<y<-7}
x=-1{-3<=y<=-1}
x=0{-3<=y<=-1}
y=-2{-1<=x<=0}
y=-1{1<=x<=2}
y=-3{1<=x<=2}
x=1.5{-3<=y<=-1}
(x-0.5)^2+(y+7.5)^2=.25{y>-7.5}
(x-0.5)^2+(y+7.5)^2=.25{x<.5}
(x-0.5)^2+(y+8.5)^2=.25{x>.5}
y=-1{-5<=x<=-4}
y=-2{-5<=x<=-4.25}
x=-5{-3<=y<=-1}
x=5{-8.5<y<-7}
x=6{-8.5<y<-7}
(x-5.5)^2+(y+8.5)^2=.25{y<-8.5}
x=0{-6<y<-4}
(-4/3)x-4 {0<x<1.5}
x=1.5{-6<y<-4}
```

*PS: The task can be found [here](crypto/algebra_exam/challenge.md)*

### Solution

ChatGPT created functions for drawing the equations:

![alt text](plot.png)

But this plot doesnt make to much sense, therefore I went through the lines one by one to see what lines drew which letter. And got the letters in order:

```py
import matplotlib.pyplot as plt
import numpy as np

# Create figure and axis
fig, ax = plt.subplots(figsize=(10, 10))

# Function to draw vertical lines
def vertical_line(x, y_min, y_max, color='black', lw=2):
    plt.plot([x, x], [y_min, y_max], color=color, lw=lw)

# Function to draw horizontal lines
def horizontal_line(y, x_min, x_max, color='black', lw=2):
    plt.plot([x_min, x_max], [y, y], color=color, lw=lw)

# Function to draw line with given slope and intercept
def linear_line(slope, intercept, x_min, x_max, color='black', lw=2):
    x = np.linspace(x_min, x_max, 100)
    y = slope * x + intercept
    plt.plot(x, y, color=color, lw=lw)

# Function to draw circles
def circle(x_center, y_center, radius, condition=None, color='black', lw=2):
    theta = np.linspace(0, 2 * np.pi, 100)
    x = x_center + radius * np.cos(theta)
    y = y_center + radius * np.sin(theta)
    
    if condition == 'y>-7.5':
        plt.plot(x[y > -7.5], y[y > -7.5], color=color, lw=lw)
    elif condition == 'x<0.5':
        plt.plot(x[x < 0.5], y[x < 0.5], color=color, lw=lw)
    elif condition == 'x>0.5':
        plt.plot(x[x > 0.5], y[x > 0.5], color=color, lw=lw)
    elif condition == 'y<-8.5':
        plt.plot(x[y < -8.5], y[y < -8.5], color=color, lw=lw)
    else:
        plt.plot(x, y, color=color, lw=lw)

# Plotting based on the list of equations with ranges

# M
vertical_line(-3, -6, -4)     # x=-3 {-6<y<-4}
vertical_line(-1, -6, -4)     # x=-1 {-6<y<-4}
linear_line(-1, -7, -3, -2)   # -x-7 {-3<x<-2}
linear_line(1, -3, -2, -1)     # x-3 {-2<x<-1}

#A
linear_line(2, 10, -5, -4)    # 2x+10 {-5<=x<=-4}
linear_line(-2, -6, -4, -3)   # -2x-6 {-4<=x<=-3}
horizontal_line(1, -4.5, -3.5) # y=1 {-4.5<=x<=-3.5}

# T
horizontal_line(-7, 2, 4)     # y=-7 {2<x<4}
vertical_line(3, -9, -7)      # x=3 {-9<y<-7}

# H
vertical_line(-1, -3, -1)     # x=-1 {-3<=y<=-1}
vertical_line(0, -3, -1)      # x=0 {-3<=y<=-1}
horizontal_line(-2, -1, 0)    # y=-2 {-1<=x<=0}

# I
horizontal_line(-1, 1, 2)     # y=-1 {1<=x<=2}
horizontal_line(-3, 1, 2)     # y=-3 {1<=x<=2}
vertical_line(1.5, -3, -1)    # x=1.5 {-3<=y<=-1}

# S
circle(0.5, -7.5, 0.5, condition='y>-7.5')  # (x-0.5)^2+(y+7.5)^2=0.25 {y>-7.5}
circle(0.5, -7.5, 0.5, condition='x<0.5')   # (x-0.5)^2+(y+7.5)^2=0.25 {x<0.5}
circle(0.5, -8.5, 0.5, condition='x>0.5')    # (x-0.5)^2+(y+8.5)^2=0.25 {x>0.5}

# F
horizontal_line(-1, -5, -4)   # y=-1 {-5<=x<=-4}
horizontal_line(-2, -5, -4.25) # y=-2 {-5<=x<=-4.25}
vertical_line(-5, -3, -1)     # x=-5 {-3<=y<=-1}

# U
vertical_line(5, -8.5, -7)    # x=5 {-8.5<y<-7}
vertical_line(6, -8.5, -7)    # x=6 {-8.5<y<-7}
circle(5.5, -8.5, 0.5, condition='y<-8.5')   # (x-5.5)^2+(y+8.5)^2=0.25 {y<-8.5}

# N
vertical_line(0, -6, -4)      # x=0 {-6<y<-4}
linear_line(-4/3, -4, 0, 1.5) # (-4/3)x-4 {0<x<1.5}
vertical_line(1.5, -6, -4)    # x=1.5 {-6<y<-4}

# Set axis limits and show grid
ax.set_xlim(-7, 7)
ax.set_ylim(-10, 2)
ax.set_aspect('equal')
plt.grid(True)
plt.title("Plot of Various Lines and Circles")
plt.xlabel("x")
plt.ylabel("y")
plt.axhline(0, color='grey', lw=0.5, ls='--')  # Add x-axis
plt.axvline(0, color='grey', lw=0.5, ls='--')  # Add y-axis
plt.show()
```

<details>
<summary>Flag</summary>

`ironCTF{MATHISFUN}`
</details>



## WARMUP

## INTROSPECTION

### Task

*PS: The task can be found [here](warmup/introspection/challenge.md)*

### Solution

Buffer overflow:

```bash
A * 1010 + " %p %p %p %p %s"
```

<details>
<summary>Flagg</summary>

`ironCTF{W0w!_Y0u_Just_OverWrite_the_Nul1!}`
</details>


## JWT HUNT

### Task

*PS: The task can be found [here](warmup/jwt_hunt/challenge.md)*

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


## MATH GONE WRONG

### Task

*PS: The task can be found [here](warmup/math_gone_wrong/challenge.md)*

### Solution

n1*10+n2*10 != (n1+n2)*10
Disse to sidene over må være ulike.
Matematisk er dette vanskelig ettersom det er det samme utrykket.

Meeeeeen, det er datamaskiner som gjør dette. 
Alle har vel sett hva python mener 0.1+0.2 er?  (spolier: det er 0.30000000000000004)
Setter n1 = 0.1 og n2 = 0.2

<details>
<summary>Flag</summary>

`ironCTF{s1mpl3_r3m4ind3r_70_b3w4r3_0f_fl047ing_p0in7_3rr0r}`
</details>


