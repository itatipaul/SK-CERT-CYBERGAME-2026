# RSA-Exponent — SK-CERT CTF Writeup

**Author:** Senpai  
**Category:** Cryptography  
**Points:** 496  
**Flag:** `SK-CERT{h0w_d035_f4c70r1n6_0f_m0dulu5_w17h_3xp0n3n7_r34lly_w0rk}`

---

## Challenge Description

> *"Why would somebody use such big numbers?"*

We're given three values: a modulus `N`, a public exponent `e`, and a ciphertext `ct`. At first glance this looks like standard RSA — but the hint is pointing directly at `e`. In textbook RSA, `e` is tiny (65537 is the classic choice). Here, `e` is **enormous** — a 23998-bit number compared to `N`'s 6000 bits. That's the entire vulnerability.

---

## Understanding the Weakness

In RSA the public and private exponents satisfy:

```
e · d ≡ 1  (mod φ(N))
```

Which means for some integer `k`:

```
e · d = 1 + k · φ(N)
```

When `e` is the normal small value, `d` ends up large (safe). But when `e` is inflated to be much larger than `N`, the math flips — `d` becomes **small** relative to `N`. This is the same structural class as the classic **Wiener attack**, which exploits the fact that a small private exponent leaks factoring information through the convergents of the continued fraction expansion of `e/N`.

Here the twist is that `e ≈ N⁴` in magnitude, meaning the attack is applied to `e/N⁴` instead of `e/N` — but the principle is identical.

---

## The Attack — Step by Step

### Step 1 — Continued Fraction Approximation

Because `e/N⁴` is very close to the rational number `b/a`, we can find `a` and `b` by computing the continued fraction expansion of `e/N⁴` and reading off a convergent:

```
e / N⁴  ≈  b / a      →     a = 985513,  b = 2417906
```

This means:

```
a · e  ≈  b · N⁴
```

The small residual `R = a·N⁴ − b·e` carries information about the primes.

### Step 2 — Recovering p⁴ + q⁴

Dividing the residual by `a` gives an approximation of `p⁴ + q⁴`:

```
X  ≈  p⁴ + q⁴  =  R / a
```

This works because the error introduced by the approximation `b/a ≈ e/N⁴` is small enough that `X` is very close to the true value.

### Step 3 — Quadratic to Isolate p⁴

We know two things:

```
p⁴ + q⁴  =  X          (just computed)
p⁴ · q⁴  =  (pq)⁴ = N⁴  (since N = p·q)
```

So `p⁴` and `q⁴` are the two roots of the quadratic:

```
t²  −  X · t  +  N⁴  =  0
```

Solving with the quadratic formula:

```
t  =  ( X  ±  √(X² − 4·N⁴) )  /  2
```

The larger root is `p⁴`.

### Step 4 — Fourth Root and Local Search

Taking the integer fourth root of `p⁴` gives an approximation of `p`. Because the continued fraction approximation introduces a tiny error, the true `p` sits within a narrow neighbourhood of this estimate. A brute-force scan of offsets from −1000 to +1000 finds it instantly:

```python
p_approx, _ = gmpy2.iroot(P4_approx, 4)

for offset in range(-1000, 1000):
    candidate = p_approx + offset
    if N % candidate == 0:
        p = candidate   # found at offset +1
        break
```

### Step 5 — Standard RSA Decryption

With `p` in hand the rest is textbook:

```python
q   = N // p
phi = (p - 1) * (q - 1)
d   = inverse(e, phi)
m   = pow(ct, d, N)
flag = long_to_bytes(m).decode()
```

---

## Solver

```python
#!/usr/bin/env python3
# RSA-Exponent — SK-CERT CTF
# Author: Senpai

import sys
sys.set_int_max_str_digits(0)

import gmpy2
from Crypto.Util.number import long_to_bytes, inverse

with open("data.txt") as f:
    exec(f.read())          # loads N, e, ct

# --- Continued-fraction coefficients (from CF expansion of e/N^4) ---
a = 985513
b = 2417906

# --- Recover X = p^4 + q^4 ---
R        = a * N**4 - b * e
X_approx = R // a

# --- Solve t^2 - X*t + N^4 = 0  (roots are p^4, q^4) ---
disc      = X_approx**2 - 4 * N**4
sqrt_disc = gmpy2.isqrt(disc)
P4_approx = (X_approx + sqrt_disc) // 2

# --- Fourth root + small local search ---
p_approx, _ = gmpy2.iroot(P4_approx, 4)
p = 0
for offset in range(-1000, 1001):
    candidate = p_approx + offset
    if candidate > 1 and N % candidate == 0:
        p = candidate
        break

# --- Decrypt ---
q    = N // p
phi  = (p - 1) * (q - 1)
d    = inverse(e, phi)
m    = pow(ct, d, N)
print(long_to_bytes(m).decode())
```

---

## Key Takeaways

**Never use an abnormally large public exponent.** When `e` is inflated to the scale of `N^k` for any integer `k`, the private exponent `d` shrinks proportionally. This makes the key pair vulnerable to continued-fraction factoring attacks that recover the primes from the public key alone — no brute force, no quantum computer required.

The standard safe choices for `e` remain 3, 17, or 65537 (Fermat primes), paired with a sufficiently large and randomly generated modulus.

---

*Writeup by Senpai · SK-CERT CTF*
