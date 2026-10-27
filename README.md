# 🎯 One Click, One Redirect: DOM XSS → Account Takeover on a Payment Bounce Page

**How an unallowlisted `gatewayUrl` turned `window.location.replace` into a first-party session steal**

*by [cyrusthedev](https://github.com/cyrusthedev) · educational writeup · researcher handle: `cyrus__`*

> ⚠️ **Disclosure note.** Target hostnames are replaced with `REDACTED.SHOP` / `REDACTED.COM`. This post is for **education**. Only test systems you are authorized to test. I used **my own researcher accounts** for every demonstration. Do not point this at real customers.

---

## TL;DR

On a VPN / wallet SPA, the payment bounce page did the moral equivalent of:

```text
gateway = URLSearchParams.get("gatewayUrl")
window.location.replace(gateway)   // no scheme / host allowlist
```

So a first-party link with a non-`https` `gatewayUrl` ran in the **shop origin** — the same origin that keeps the SPA session JWT in `localStorage.accessToken`.

A logged-in customer who opens that link can lose:

- the Bearer JWT (short TTL, ~15 minutes in my tests)
- wallet UI access after the token is replayed
- VPN subscription objects from `GET /api/accounts` (including a **password** field in JSON)

**Class:** DOM XSS (CWE-79) → authentication bypass / ATO (CWE-287)  
**Impact:** one-click session hijack + credential disclosure on researcher accounts  
**Not:** RCE, password-hash dump of the whole user DB, or offline crypto break

---

## 🎯 Why I looked here

The product is a customer portal: wallet top-ups, subscriptions, VPN accounts. Session lives in the browser as a JWT in `localStorage`, not an `HttpOnly` cookie.

Payment flows often bounce through a thin HTML shim before the real gateway. Thin shims are where people forget allowlists.

I asked a boring question:

> What does `pay-redirect.html` do with `gatewayUrl` if it isn’t an `https` payment host?

---

## 🧩 Mapping the feature

Relevant surfaces (redacted):

| Host / path | Role |
|-------------|------|
| `https://REDACTED.SHOP/api/pay-redirect.html` | XSS sink + session origin (`localStorage`) |
| `https://REDACTED.COM/api/pay-redirect.html` | Same file pattern; **shop token is on `.shop`** |
| `https://REDACTED.SHOP/app/wallet` | Post-ATO app surface |
| `GET /api/accounts` | VPN / subscription objects (incl. password field) |
| `GET /api/payment/balance` | Wallet balance |
| `GET /api/wallet/transactions` | Payment history |

Happy path (what the UI intends):

1. User starts a top-up  
2. Backend picks a payment gateway URL  
3. Browser hits `pay-redirect.html?gatewayUrl=<https payment host>`  
4. Page navigates there

The bug is step 3–4 trusting the **query string**, not a server-issued ticket.

---

## 🧪 The bug in one diagram

```text
[Victim — logged in on REDACTED.SHOP]
   localStorage.accessToken = <JWT>
   │
   │  opens first-party link
   │  /api/pay-redirect.html?gatewayUrl=<unsafe>
   ▼
[pay-redirect.html]
   gateway = params.get("gatewayUrl")
   window.location.replace(gateway)   ❌ no allowlist
   │
   │  script runs in shop origin
   ▼
[attacker]
   receives token (+ optional /api/accounts JSON)
   replays Bearer / re-injects token → wallet session
```

Important control that **does not save you**:

- Moving the same bounce file to another registrable domain does **not** steal the shop JWT. `localStorage` is origin-scoped. The steal has to run on **`REDACTED.SHOP`**.

---

## 🔬 What I confirmed (researcher accounts only)

| Role | Meaning |
|------|---------|
| Account A | Victim (researcher uid — own test user) |
| Account B | Clean browser / attacker replay side (own test user) |

### 0) Baseline — no token, wallet refuses

Unauthenticated `GET /app/wallet` → redirect to login. Expected.

### 1) Sink accepts unallowlisted `gatewayUrl`

The bounce page takes `gatewayUrl` from the query string and feeds it straight into `window.location.replace(...)`.

There was **no** scheme allowlist, **no** host allowlist, and **no** useful CSP on that page. A non-`https` scheme inherits the document origin — classic DOM XSS, not “open redirect only.”

I demonstrated token readability in-origin on **my own** logged-in session. I am **not** publishing a copy-paste payload here; the sink is enough for a defender to reproduce safely in a lab.

### 2) Impact beyond `alert`

On my researcher session (2026-10-12), after the in-origin script could read `localStorage.accessToken`:

| Check | Result |
|-------|--------|
| Replay token → `/app/wallet` | Wallet UI (balance, packs, transactions) |
| `GET /api/payment/balance` | HTTP 200 |
| `GET /api/accounts/stats` | HTTP 200 |
| `GET /api/wallet/transactions` | HTTP 200 (includes victim user id) |
| `GET /api/accounts` | HTTP 200 — VPN accounts **including a password field** |
| JWT shape | RS256, `role=USER`, `identityType=phone`, `exp ≈ iat + 900` |

A temporary HTTPS collector received beaconed JSON from **my own** accounts only. That collector is **not live**. Rotate any token that ever appeared in screenshots.

### 3) ATO without a fake login page

The lure is a **first-party** `REDACTED.SHOP` URL. No phishing lookalike domain required for the XSS step. After token replay, the wallet session restores for the JWT lifetime (~15 minutes in my tests).

---

## 🧠 Root cause (plain English)

```javascript
const params = new URLSearchParams(window.location.search);
const gateway = params.get('gatewayUrl');
if (gateway) { window.location.replace(gateway); }
```

Someone built a “just bounce to the gateway” helper and treated the query string as trusted navigation input.

Two missing checks:

1. **Never** `location.replace` / `assign` / `href=` a raw user-controlled URL without parsing and allowlisting scheme + host.  
2. Don’t keep long-lived (or even short-lived) session secrets in `localStorage` if a single XSS anywhere on the origin is game over.

The password field on `GET /api/accounts` is a **second** finding-class issue: XSS impact should not include cleartext VPN passwords in JSON.

---

## 💥 Impact

Any logged-in customer who opens an attacker-controlled first-party bounce link can lose the active session for the token TTL:

| Asset | What leaks / breaks |
|-------|---------------------|
| Session JWT | Bearer replay → SPA as the victim |
| Wallet | Balance, packs, transaction history |
| VPN subscriptions | Usernames + **password field** via `/api/accounts` |

On a paid VPN portal, that is confidentiality + integrity of the customer account — **High**, not Critical (no evidence of minting arbitrary admin roles or breaking out of the USER JWT in my tests).

I did **not** test destructive wallet drains or mass credential stuffing. Don’t do that on a live program without clear rules.

---

## 🛠️ Remediation (what I’d tell the team)

1. Parse `gatewayUrl` with the URL API. Allow only `https:` and a **fixed** list of payment hosts. Reject `javascript:`, `data:`, `blob:`, and anything else.  
2. Prefer a **server-side 302** after validation instead of client `location.replace` on raw input.  
3. Move sessions from `localStorage` to `HttpOnly; Secure` cookies (with CSRF controls).  
4. Stop returning VPN passwords in `GET /api/accounts`.  
5. Put a tight CSP on `pay-redirect.html` (`default-src 'none'`; only the scripts you actually need).

---

## 🎓 Hunting lesson I’m keeping

> Payment bounce pages are tiny. Tiny pages skip allowlists.  
> If navigation target comes from the query string, assume XSS until proven otherwise.

Also: prove impact with **two browsers** — victim session vs clean replay — and treat `localStorage` XSS as ATO when APIs accept the stolen Bearer blindly.

---

## Timeline (personal)

- Mapped wallet / payment bounce surface on an authorized program  
- Confirmed DOM sink + own-account token impact (researcher uids only)  
- Wrote the program report (confidential PDF)  
- Published this **redacted** educational version for other hunters

---

## Legal / ethics

- Authorized bug bounty / own test accounts only  
- No third-party customer sessions in the PoC  
- Hostnames redacted here as `REDACTED.SHOP` / `REDACTED.COM`  
- If you reproduce on a program, follow **their** rules, rate limits, and disclosure policy  
- Rotate any JWT or VPN password that appeared in evidence screenshots

---

## Thanks

To every hunter who still opens the boring redirect helper and reads the ten lines of JS. That’s where this one lived.

— **cyrus__** / [cyrusthedev](https://github.com/cyrusthedev)

---

### Tags

`#bugbounty` `#domxss` `#ato` `#localstorage` `#jwt` `#brokenaccesscontrol` `#websecurity` `#writeup`
