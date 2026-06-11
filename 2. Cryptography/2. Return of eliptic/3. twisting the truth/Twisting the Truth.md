# Return of Elliptic: Twisting the Truth — SK-CERT CTF Writeup

**Author:** Senpai  
**Category:** Cryptography  
**Points:** 500  
**Flag:** `SK-CERT{qu4r71c_7w157s_4r3_v3ry_b34u71ful_bu7_u5ed_r4r3ly}`

---

## Challenge Description

> *"Who will believe Jacob now? He is just twisting the truth, so he would look cool."*

We receive a single JSON file (`enc.enc`) containing a field definition, a curve description, 14 rows of leakage data, and an encrypted payload. A flavor text hints that a single secret `k` passes through the same machinery 14 times, and each row is just a narrow modular slice of what remains. The sealed payload cannot be attacked directly — recover `k` first.

---

## Understanding the Setup

### The Field and Curve (Flavor, Not the Attack Vector)

The JSON describes an elliptic curve over a quartic extension field:

```
p  = 240216054091197400064972999812429686881    (128-bit prime)
F  = GF(p)[z] / (z^4 - 41857999666904709325391374420372856847)   (degree-4 extension)
E  : y² = x³ + a·x   over F,   a = 202528927977825293762893890130927217592
```

This is a Montgomery-form curve over a degree-4 extension — the "quartic twist" the title and flag allude to. The description is atmospheric. The actual attack lives entirely in the leakage rows.

### The Leakage

Each of the 14 rows gives two integers `m` and `s`. The hint reveals the relation:

```
s ≡ A·k + B  (mod m)
```

where `(A, B)` pairs are provided in the challenge. Every row is a different affine linear shadow of the **same** secret `k`, reduced modulo a different small modulus. This is a textbook setup for the **Chinese Remainder Theorem (CRT)**.

---

## The Attack

### Step 1 — Isolate k mod m for Each Row

Rearranging `s ≡ A·k + B (mod m)`:

```
k ≡ A⁻¹ · (s - B)  (mod m)
```

For each row we compute `A⁻¹ mod m` (modular inverse) then multiply by `(s − B) mod m`. This gives us 14 independent congruences:

```
k ≡ r₁  (mod m₁)
k ≡ r₂  (mod m₂)
     ⋮
k ≡ r₁₄ (mod m₁₄)
```

A quick sanity check confirms all 14 moduli are pairwise coprime — a required condition for CRT to produce a unique solution.

### Step 2 — Chinese Remainder Theorem

CRT states that if `m₁, m₂, …, m₁₄` are pairwise coprime, there exists a unique `k` modulo their product `M = m₁·m₂·…·m₁₄` satisfying all 14 congruences simultaneously.

The combined modulus:

```
M = 20486509 × 20173 × 129229 × … × 22926451
M ≈ 2²⁶⁷   (267-bit number)
```

Applying CRT directly recovers `k` (262 bits), which is strictly less than `M`, guaranteeing uniqueness.

```
k = 5337913728285739956091395719319401974310170459842094717044356163962253691968987
```

### Step 3 — Decrypt the Payload

With `k` recovered, the decryption procedure is:

```
seed      = SHA-256(str(k))  ||  "|"  ||  nonce
keystream = SHAKE-256(seed, length=len(ct))
plaintext = ciphertext XOR keystream
```

Breaking it down:

- `SHA-256(str(k))` converts the recovered secret to a fixed 32-byte key.
- Concatenating with the nonce (`a2edde60ebbcceb7a0d3a14c`) makes the seed unique per message.
- `SHAKE-256` is an extendable-output function (XOF) — it produces an arbitrary-length keystream, here 58 bytes to match the ciphertext.
- XOR decryption recovers the flag.

---

## Solver

```python
#!/usr/bin/env python3
# Return of Elliptic: Twisting the Truth — SK-CERT CTF
# Author: Senpai

import json
import re
import hashlib
from Crypto.Util.number import inverse
from sympy.ntheory.modular import crt

A_and_B = [
    (20351961, 13972866), (1121, 18695),     (41963, 125946),
    (13797, 26843),       (153168, 827907),  (974024, 985846),
    (1085609, 3427804),   (2019698, 24894321),(37418, 129373),
    (9508, 7191),         (4083, 93632),     (82129, 156223),
    (39537, 59977),       (771790, 20487579),
]

# Load enc.enc (has a trailing comma in JSON — fix it)
with open('enc.enc') as f:
    data = json.loads(re.sub(r',\s*([}\]])', r'\1', f.read()))

leakage = data['leakage']

# Step 1: recover k ≡ A⁻¹(s − B) (mod m) for each row
moduli, remainders = [], []
for i, row in enumerate(leakage):
    m, s = int(row['m']), int(row['s'])
    A, B = A_and_B[i]
    remainders.append(((s - B) * inverse(A, m)) % m)
    moduli.append(m)

# Step 2: Chinese Remainder Theorem
k, _ = crt(moduli, remainders)
print(f"[+] Recovered k = {k}")

# Step 3: key derivation + SHAKE-256 stream cipher
nonce      = bytes.fromhex(data['cipher']['nonce'])
ciphertext = bytes.fromhex(data['cipher']['ct'])
seed       = hashlib.sha256(str(k).encode()).digest() + b"|" + nonce
keystream  = hashlib.shake_256(seed).digest(len(ciphertext))
plaintext  = bytes(c ^ s for c, s in zip(ciphertext, keystream))

print(f"[+] Flag: {plaintext.decode()}")
```

**Output:**

```
[+] Recovered k = 5337913728285739956091395719319401974310170459842094717044356163962253691968987
[+] Flag: SK-CERT{qu4r71c_7w157s_4r3_v3ry_b34u71ful_bu7_u5ed_r4r3ly}
```

---

## Verification

All 14 leakage equations check out against the recovered `k`:

| Row | `(A·k + B) mod m` | `s` | Match |
|-----|-------------------|-----|-------|
| 1  | 18634872 | 18634872 | ✅ |
| 2  | 15972    | 15972    | ✅ |
| 3  | 3703     | 3703     | ✅ |
| … | … | … | ✅ |
| 14 | 19843815 | 19843815 | ✅ |

All 14 rows match, and the CRT solution is unique since all moduli are pairwise coprime.

---

## Key Takeaways

**Leaking affine linear shadows of a secret across multiple small moduli is fatal.** Each row `s ≡ A·k + B (mod m)` looks innocuous — `m` values top out around 25 million, nowhere near the size of `k`. But CRT doesn't need each modulus to be large; it needs their *product* to exceed `k`. Here `M ≈ 2²⁶⁷` comfortably covers the 262-bit secret.

**The elliptic curve and quartic field are set dressing.** The title ("Twisting the truth") and field description ("4-lane arithmetic core", degree-4 extension) are flavor. The actual attack is pure number theory — no elliptic curve arithmetic required. The flag itself acknowledges this: `qu4r71c_7w157s_4r3_v3ry_b34u71ful_bu7_u5ed_r4r3ly` — quartic twists are beautiful but used rarely, and here they weren't used at all.

**CRT as an attack tool, not just a construction.** Normally CRT is used to *build* a system (split a secret across residues for efficiency or threshold sharing). Here it's flipped: the defender accidentally created CRT-compatible leakage by reusing the same `k` across multiple modular reductions with known linear coefficients. Any time a single secret appears in multiple linear congruences with coprime moduli, CRT will reconstruct it exactly.

---

*Writeup by Senpai · SK-CERT CTF*
