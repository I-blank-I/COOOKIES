# Patterns & Reference

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
```
```http
POST /api/user/editemail HTTP/1.1
Authorization: Bearer <__COOOKIES__:admin>
X-Csrf-Token: <COOOKIES:admin:x-csrf>
Content-Type: application/x-www-form-urlencoded

editedEmail=smth@smth.smth
```

---

1. Build a working authenticated request with the context menu; use the Logger to verify pattern resolution

https://github.com/user-attachments/assets/22ee75a6-7559-4d7d-8fd7-ed124a5909a9

2. Using the hotkey to quickly switch between users (`admin` and `guest`)

https://github.com/user-attachments/assets/cc454ffa-789f-4776-9f79-37eb0db36431

3. Session Auto-Refresh in action

https://github.com/user-attachments/assets/c0207460-a3d4-4c15-bb99-e1f480cb980c

---

See also: **[Guide](GUIDE.md)**