# Guide

## 1 — Build a pipeline

1. Open the **COOOKIES** tab
2. `Add` a request, give it a name, paste the raw HTTP into the editor
3. In the **Extractions** tab, add rules to pull values from the response
4. Check **Patterns** to see what's injectable at each step
5. Repeat for each step in your flow

**Checkpoint steps (optional):** click the `⌄` next to `Add` → **Checkpoint (manual pause)** to insert a manual pause in the pipeline — useful for OTP/2FA or anything that needs a human in the loop. Define one or more variables on the checkpoint; when the pipeline reaches that step it pauses (per credential) until you fill in the values and click **Continue ▶**. Those values are then usable in later steps the same way as extracted values: `<COOOKIES:VAR_NAME>`.

## 2 — Add credentials

| Method | How |
|--------|-----|
| Manual | `Credentials` tab → `Add` |
| File | One `username:password` per line → `Load file…` |
| Paste | Copy `username:password` lines → `Paste` |

## 3 — Run

Click **▶ Execute Pipeline**. The execution log shows each step and every extracted value. The pipeline list and credentials table highlight the active step while running.

## 4 — Use patterns in Burp tools

Paste patterns into Repeater, Intruder, Scanner, or any proxied tool — they are replaced automatically on send (requires **Request Interception** to be enabled).

```http
GET /api/profile HTTP/1.1
Host: auth.example.com
Authorization: Bearer <__COOOKIES__:guest>
```

You can also right-click in any request editor → `Extension → COOOKIES` to insert or copy a pattern from the context menu.

## 5 — Hotkeys

| Hotkey | Action |
|--------|--------|
| `Ctrl+Shift+C` | Cycle to next credential in the active editor |
| `Ctrl+Shift+Equals` | Re-run the pipeline from anywhere (e.g. Repeater) |

Both are rebindable in `Settings → Extensions → COOOKIES` (reload required). The COOOKIES tab is highlighted while the pipeline is running so you have a visual signal without switching tabs.

## 6 — Session auto-refresh

1. Enable **Resp Detect** in the header bar
2. Go to **Settings** → add expiration strings (e.g. `Session expired`, `401 Unauthorized`)
3. When a proxied response matches, the pipeline re-runs automatically and a `Coookies-Expiration: HIT` header is injected into the flagged response

## 7 — Static variables

`Static Variables` tab → add a name/value pair → use as `<COOOKIES:VAR_NAME>` inside any pipeline request. Useful for OAuth challenges, fixed headers, environment-specific values.

## 8 — Persist your config

`💾 Save` stores everything (pipeline, extractions, credentials, settings) directly into the Burp project file. It's restored automatically next time you open the project — no need to re-import a `.coookies` file.

For portability, use `⬆ Export` / `⬇ Import` to save and load `.coookies` files.

---

## Debugging

Open **Burp Logger** to verify patterns are being resolved correctly, both during pipeline execution and in Burp tools.

---

See also: **[Patterns & Reference](PATTERNS.md)**