# COOOKIES – Burp Suite Extension

![](./img/cookies.png)

![Burp Suite Pro](https://img.shields.io/badge/Burp%20Suite-Pro-orange) ![Version](https://img.shields.io/badge/version-2.0.0-blue)

Automate multi-step authentication flows and manage session tokens across multiple user accounts — all from inside Burp Suite.

---

## What it does

Build a pipeline of HTTP requests that logs in users in and extracts session tokens. Once the pipeline runs, extracted values can be injected into any Burp tool via patterns like `<__COOOKIES__:username>`. Responses are monitored for session expiration strings and the pipeline re-runs automatically when a session dies.

---

## Installation

**Requires:** Burp Suite Professional v2026.2.3+

1. Download `COOOKIES.jar` from Releases
2. In Burp: `Extensions → Installed → Add` → select the JAR

---

## Quick start

### 1 — Build a pipeline

1. Open the **COOOKIES** tab
2. `Add` a request, give it a name, paste the raw HTTP into the editor
3. In the **Extractions** tab, add rules to pull values from the response
4. Check **Patterns** to see what's injectable at each step
5. Repeat for each step in your flow

### 2 — Add credentials

| Method | How |
|--------|-----|
| Manual | `Credentials` tab → `Add` |
| File | One `username:password` per line → `Load file…` |
| Paste | Copy `username:password` lines → `Paste` |

### 3 — Run

Click **▶ Execute Pipeline**. The execution log shows each step and every extracted value. The pipeline list and credentials table highlight the active step while running.

### 4 — Use patterns in Burp tools

Paste patterns into Repeater, Intruder, Scanner, or any proxied tool — they are replaced automatically on send (requires **Request Interception** to be enabled).

```http
GET /api/profile HTTP/1.1
Host: auth.example.com
Authorization: Bearer <__COOOKIES__:guest>
```

You can also right-click in any request editor → `Extension → COOOKIES` to insert or copy a pattern from the context menu.

### 5 — Hotkeys

| Hotkey | Action |
|--------|--------|
| `Ctrl+Shift+C` | Cycle to next credential in the active editor |
| `Ctrl+Shift+Equals` | Re-run the pipeline from anywhere (e.g. Repeater) |

Both are rebindable in `Settings → Extensions → COOOKIES` (reload required). The COOOKIES tab is highlighted while the pipeline is running so you have a visual signal without switching tabs.

### 6 — Session auto-refresh

1. Enable **Resp Detect** in the header bar
2. Go to **Settings** → add expiration strings (e.g. `Session expired`, `401 Unauthorized`)
3. When a proxied response matches, the pipeline re-runs automatically and a `Coookies-Expiration: HIT` header is injected into the flagged response

### 7 — Static variables

`Static Variables` tab → add a name/value pair → use as `<COOOKIES:VAR_NAME>` inside any pipeline request. Useful for OAuth challenges, fixed headers, environment-specific values.

### 8 — Persist your config

`💾 Save` stores everything (pipeline, extractions, credentials, settings) directly into the Burp project file. It's restored automatically next time you open the project — no need to re-import a `.coookies` file.

For portability, use `⬆ Export` / `⬇ Import` to save and load `.coookies` files.

---

## Patterns reference

| Pattern | Where | Description |
|---------|-------|-------------|
| `<COOOKIES:USERNAME>` | Pipeline only | Current user's username |
| `<COOOKIES:PASSWORD>` | Pipeline only | Current user's password |
| `<COOOKIES:COOKIES>` | Pipeline only | Aggregated `Set-Cookie` values from the previous step |
| `<COOOKIES:VAR_NAME>` | Pipeline only | Any static variable or extracted value |
| `<COOOKIES:username:extractionName>` | Burp tools | Per-user extracted value |
| `<__COOOKIES__:username>` | Burp tools | Final auth value for a specific user |

---

## Extraction types

| Type | Value format | Example |
|------|-------------|---------|
| **Header** | Header name | `Set-Cookie` → aggregates all cookies |
| **JSON** | Path notation | `['data']['token']` |
| **Regex** | First capture group | `token=([^;]+)` |

For Regex extractions, click **Regex Builder** to open the regex builder: paste or load a sample response, highlight the value you want to extract, and a context-aware pattern is generated and tested live.

> **Note:** the builder is a best-effort helper and can produce inaccurate or fragile patterns depending on the context. Writing patterns by hand is still the more reliable option.

---

## Example pipeline

**Credentials:** `guest:1234`, `admin:Password`

**Step 1 — Get CSRF token**

```http
GET /api/token HTTP/1.1
Host: auth.example.com
```

Extractions:
- `Set-Cookie` → Header → `cookies`
- `token=([^;]+)` → Regex → `x-csrf`

**Step 2 — Login**

```http
POST /api/login HTTP/1.1
Host: auth.example.com
Cookie: <COOOKIES:cookies>
X-Csrf-Token: <COOOKIES:x-csrf>
Content-Type: application/x-www-form-urlencoded

username=<COOOKIES:USERNAME>&password=<COOOKIES:PASSWORD>
```

Extraction:
- `['access_token']` → JSON → **Final Auth Value**

**Use in Repeater:**

```http
GET /api/user/profile HTTP/1.1
Authorization: Bearer <__COOOKIES__:guest>

POST /api/user/editemail HTTP/1.1
Authorization: Bearer <__COOOKIES__:admin>
X-Csrf-Token: <COOOKIES:admin:x-csrf>
```

---

1. Build a working authenticated request with the context menu; use the Logger to verify pattern resolution

https://github.com/user-attachments/assets/22ee75a6-7559-4d7d-8fd7-ed124a5909a9

2. Using the hotkey to quickly switch between users (`admin` and `guest`)

https://github.com/user-attachments/assets/cc454ffa-789f-4776-9f79-37eb0db36431

3. Session Auto-Refresh in action

https://github.com/user-attachments/assets/c0207460-a3d4-4c15-bb99-e1f480cb980c

---

## Works great with LazyFlow

Configuring extraction rules manually for complex flows is tedious. **[LazyFlow](https://github.com/I-blank-I/LazyFlow)** automates it — select your login flow in Proxy, send to LazyFlow, and it generates a ready-to-import `.coookies` file with all placeholders and extraction rules pre-filled.

> Credentials are never filled automatically — you always add those yourself.

---

## Debugging

Open **Burp Logger** to verify patterns are being resolved correctly, both during pipeline execution and in Burp tools.

---

## Disclaimer

For authorized security testing only. Always obtain proper permission before testing systems you don't own.
