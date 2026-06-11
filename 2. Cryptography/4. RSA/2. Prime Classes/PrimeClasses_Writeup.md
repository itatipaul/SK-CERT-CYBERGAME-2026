# Prime Classes — SK-CERT CTF Writeup

**Author:** Senpai  
**Category:** Cryptography  
**Points:** 486  
**Flag:** `SK-CERT{l34k3d_57ruc7ur3_g1v35_6w6y_7h3_50lu710n}`

---

## Challenge Description

> *"These primes are dividing in some classes because some think that they are way better than others."*

We're given `main.py` and `output.txt`. The script performs RSA encryption on the flag, but before encrypting it validates that the plaintext integer has prime factors drawn from three predetermined "classes." That validation is the entire vulnerability.

---

## Recon: Reading the Source

```python
def main():
    flag = "SK-CERT{****}"
    m = bytes_to_long(flag.encode())
    isNiceNumber(m)      # ← validation happens here
    e = 3
    p = getPrime(502)
    q = getPrime(502)
    n = p * q
    c = pow(m, e, n)
```

Two things stand out immediately:

| Parameter | Value | Why it matters |
|---|---|---|
| `e` | `3` | Tiny exponent — classic low-exponent attack territory |
| `n` | ~1003 bits | Two 502-bit primes |
| `m` | ~391 bits | The flag integer |

The comment in the source is the real hint:

> *"I like when my numbers have a factor in each class, and also a large hidden extra factor"*

So `m` is guaranteed to be of the form:

```
m = (one small prime) × (one middle prime) × (one big prime) × (unknown hidden factor)
```

---

## The Three Prime Classes

`isNiceNumber()` checks that `m` is divisible by at least one prime from each of these sets:

| Class | Prime range | Approx. bit size | Unique primes |
|---|---|---|---|
| `smallClass` | 2 – 509 | 1 – 9 bits | 65 |
| `middleClass` | 11 – 8161 | 4 – 13 bits | 95 |
| `bigClass` | 234630371 – 33714707561 | 28 – 35 bits | 100 |

The three classes contribute a combined factor `k = s × mp × b` of at most **56 bits**. The hidden factor `r = m / k` carries the remaining ~335 bits of the flag.

---

## Why a Naive Cube Root Fails

With `e = 3`, the ciphertext is simply:

```
c ≡ m³  (mod n)
```

The textbook small-`e` attack is to check if `m³ < n` — if so, no modular reduction occurred and `m = ∛c` directly. But here `m` is 391 bits, so `m³` is ~1173 bits, wrapping around the 1003-bit `n` roughly **455 trillion times**. A direct cube root gives garbage.

Scanning `∛(c + j·n)` for small `j` also fails for the same reason — `j` would need to be astronomically large to land on the right value.

---

## The Attack: Divide Out the Known Structure

Since we know `m = k · r` where `k` is a product of one prime from each class, we can substitute into the RSA equation:

```
c ≡ (k · r)³  (mod n)
c ≡ k³ · r³   (mod n)
```

Rearranging:

```
r³ ≡ c · (k³)⁻¹  (mod n)
```

Let `c_reduced = c · (k³)⁻¹ mod n`. Now `r` is only ~335 bits, so `r³` is ~1004 bits — just barely over `n`. That means `r³` overflows `n` by exactly **one** time, so:

```
r³ = c_reduced + 1 · n
```

Taking the integer cube root of `c_reduced + n` gives `r` directly, and then `m = k · r`.

The only remaining task is finding the right combination of `(s, mp, b)` — one prime from each class. With 65 × 95 × 100 = 617,500 candidates and a trivial cube root check per candidate, the whole search runs in under 20 seconds.

---

## Solver

```python
#!/usr/bin/env python3
# Prime Classes — SK-CERT CTF
# Author: Senpai

from Crypto.Util.number import long_to_bytes
from sympy import integer_nthroot

c = 11734104621330122306051619458715549004966317444961687995511160662947540811139016172479786084339259250279133231484381252142572455923343441751909630006132634029551489956942278382797498244055166471670128996856518381928842972347156560863686418916083864033481250591063552682189700701642321082374834368254671
n = 77568798730065799432351396345551612226901205428287848997625975245113641493265848893286902516448430900148338393806704265615308335340205339876413650967390590557449703078900802918577489564020403891166774121888943505500213272896573003841536554648722172519028834575573537070337576785183121093654306011906187

smallClass = sorted(set([
    509,503,499,491,487,479,457,439,433,431,421,419,409,401,397,389,383,379,
    373,359,353,337,317,313,311,293,283,281,277,271,263,257,251,241,227,197,
    191,181,167,163,157,151,149,139,137,131,113,107,103,97,89,71,67,59,53,
    43,41,37,19,17,13,11,5,3,2
]))

middleClass = sorted(set([
    8161,8039,7937,7699,7639,7589,7517,7333,7331,7229,7013,6841,6719,6659,
    6577,6571,6481,6469,6343,6299,6263,6229,6197,6007,5857,5851,5639,5591,
    5501,5347,5309,5297,5167,4993,4987,4909,4903,4787,4657,4637,4597,4463,
    4447,4363,4231,4129,4099,4073,3881,3847,3767,3643,3613,3539,3527,3491,
    3323,3257,3191,3169,3037,2837,2803,2731,2719,2693,2557,2549,2389,2357,
    2011,1847,1789,1667,1619,1303,1129,1049,1039,1021,823,761,757,751,743,
    701,653,593,277,191,139,37,31,23,11
]))

bigClass = sorted(set([
    33714707561,33475189963,33180798359,32968219657,32753993861,32601998993,
    32354000431,31622210959,31463103443,31106171297,31026644791,30864000457,
    30555832451,30007127383,29679425119,29092782221,28965030907,28962105283,
    28788132787,28512646711,28435367731,28366379219,28323441217,28021435769,
    27943699733,26635017737,26567935297,26303239091,25608036371,25576881097,
    25395389471,25205052833,24596525977,24335124727,24229533397,24190929817,
    23954685889,23775654349,23675939747,23598824653,23309496157,22135955827,
    21806963513,21700899733,21143839061,20917551449,20816352043,20261287681,
    20012201381,19915512101,19661235553,19585405291,19129191649,18809753401,
    18624918629,18158829257,18121590569,17572665139,16580964929,16057692181,
    15575058607,15272351359,14981230513,14043779501,13980148361,12851947057,
    12851592671,12562954097,12175890931,11505311681,11145919879,11069320079,
    10463008123,10215147653,9627859369,9624045577,9331874807,9226461847,
    8995683889,8703841693,7452307061,7307945837,6893239153,6637300469,
    6545235847,5079964343,4959254497,4849767947,3524654227,3458365789,
    3288001447,3283570987,2668164817,2654685647,2577719497,1242720113,
    891228883,601919111,437723521,234630371
]))

found = False
for s in smallClass:
    if found: break
    for mp in middleClass:
        if found: break
        for b in bigClass:
            k      = s * mp * b
            k3_inv = pow(k ** 3, -1, n)
            c_red  = (c * k3_inv) % n

            # r^3 overflows n by at most a handful of times — check j=0,1,2
            for j in range(5):
                root, perfect = integer_nthroot(c_red + j * n, 3)
                if perfect:
                    msg = long_to_bytes(k * root)
                    try:
                        decoded = msg.decode()
                        if decoded.startswith("SK-CERT"):
                            print(f"s={s}  mp={mp}  b={b}  j={j}")
                            print(f"Flag: {decoded}")
                            found = True
                            break
                    except Exception:
                        pass
            if found: break
```

**Output:**

```
s=479  mp=5501  b=24190929817  j=1
Flag: SK-CERT{l34k3d_57ruc7ur3_g1v35_6w6y_7h3_50lu710n}
```

Runtime: ~17 seconds across 617,500 candidates.

---

## Key Takeaways

**Leaking the plaintext's factor structure is fatal.** Telling an attacker that `m` contains a factor from a small, known set doesn't just hint at the structure — it hands over enough of `m` to reduce the unknown remainder to a size where cube root recovery is trivial. The "hidden extra factor" comment in the source made the structure even more explicit.

**Small `e` amplifies any plaintext structure leak.** With a large `e`, recovering `m` from `c` requires the private key regardless. With `e = 3`, the problem collapses to finding `r` such that `k³ · r³ ≡ c (mod n)`, which is just an integer cube root once `k` is known.

**The search space looks intimidating but isn't.** 617,500 combinations sounds like brute force, but each iteration is a single modular inverse, a modular multiplication, and an integer cube root — all cheap. The real insight is recognizing that only `j = 0` or `j = 1` needs to be checked per candidate, keeping the whole attack under 20 seconds on any modern machine.

---

*Writeup by Senpai · SK-CERT CTF*
