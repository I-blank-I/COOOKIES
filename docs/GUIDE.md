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

### Auto-Authorization header

Instead of writing the session headers into every request, add one header naming the user:

```http
GET /api/profile HTTP/1.1
Host: auth.example.com
X-Auto-Authorization: admin
```

On send, COOOKIES removes `X-Auto-Authorization` and adds every row of **Settings → Auto-Authorization Headers** for that user. Rows are user-independent: write `USERNAME` where the user goes, and it is swapped for the requested one.

| Header Name | Header Value |
|-------------|--------------|
| `Authorization` | `Bearer <__COOOKIES__:USERNAME>` |
| `X-Csrf-Token` | `<COOOKIES:USERNAME:x-csrf>` |

A header with the same name already in the request is replaced. If the user has no COOOKIES session yet (the login pipeline hasn't run for them), the trigger header is still removed but nothing is added, and the reason is written to the extension's error log. `X-Auto-Authorization: 1` still applies the rows exactly as written, for configs made before this change.

## 5 — Hotkeys

| Hotkey | Action |
|--------|--------|
| `Ctrl+Shift+C` | Cycle to next credential in the active editor |
| `Ctrl+Shift+Equals` | Re-run the pipeline from anywhere (e.g. Repeater) |

Both are rebindable in `Settings → Extensions → COOOKIES` (reload required). The COOOKIES tab is highlighted while the pipeline is running so you have a visual signal without switching tabs.

## 6 — Keeping sessions alive

The **Session** selector in the header bar picks how sessions are kept alive. Only one way can be active at a time, or none:

| Mode | What it does |
|------|--------------|
| **Off** | Nothing: sessions last as long as the server allows |
| **Expiration strings** | When a response contains one of the strings in **Settings → Session Expiration Strings** (e.g. `Session expired`, `401 Unauthorized`), the login pipeline re-runs automatically and a `Coookies-Expiration: HIT` header is added to the flagged response |
| **Login timer** | Re-runs the login pipeline every `N` minutes, for apps with no refresh logic where a new login is the only way to a fresh session |
| **Refresh timer** | Runs the refresh pipeline every `N` minutes (see section 7). Needs a Refresh Token Extraction in the login pipeline |

How the two timers work:

- **The countdown starts only when a login run finishes** with a timer mode selected. Picking a timer mode after logging in does not start it; run the login pipeline once. Each timed run then sets the next deadline (`next run at HH:MM` next to the selector).
- **A failed timed run stops the timer** and keeps every user's previous values. For the login timer, a run fails if any user's login errors out or extracts no Final Auth Value. Run the login pipeline again to restart it.
- **Changing the interval** shifts the running countdown, it doesn't restart it. Switching mode, or to **Off**, stops any running timer.
- **Timed runs are unattended**: no popups, everything goes to the execution log. If the login pipeline has a checkpoint (MFA), a timed login pauses there until you fill it in.
- **The selected mode and interval are saved in the Burp project** as soon as you change them. Tokens are not: after reopening the project, run the login pipeline once and the timer picks up from there.

## 7 — Token refresh (refresh pipeline)

For flows that hand out a refresh token (OAuth and similar): instead of logging in again, a second pipeline exchanges each user's refresh token for fresh values.

1. In the login pipeline, select the step whose response contains the refresh token → **Extractions** → **Add Refresh Token Extraction 🔄**. This unlocks the **Refresh** pipeline and the **Refresh timer** mode.
2. Above the pipeline list, switch from **Login** to **Refresh** and build the refresh flow there. Use `<COOOKIES:REFRESH_TOKEN>` for the current user's refresh token; everything extracted during login is available too.
3. On the refresh step(s), add an **Auth Extraction ⭐** for the new token, and a **Refresh Token Extraction 🔄** if the server rotates refresh tokens. Both overwrite the user's previous values. A normal extraction that reuses a login extraction's name overwrites that value as well.
4. Select **Session: Refresh timer**, set the interval, then run the login pipeline. **Refresh now** (in the Refresh view) runs the refresh pipeline immediately without starting a timer.

Things to know:

- The refresh pipeline runs once per user that holds a refresh token. Checkpoint steps are not available in it, since it runs unattended.
- If a refresh fails for a user (request error, or the auth / refresh token can't be extracted), that user's previous values are kept, the error is logged, and the timer stops (see section 6).

## 8 — Static variables

`Static Variables` tab → add a name/value pair → use as `<COOOKIES:VAR_NAME>` inside any pipeline request. Useful for OAuth challenges, fixed headers, environment-specific values.

## 9 — Persist your config

`💾 Save` stores everything (both pipelines, extractions, credentials, settings) directly into the Burp project file. It's restored automatically next time you open the project — no need to re-import a `.coookies` file.

For portability, use `⬆ Export` / `⬇ Import` to save and load `.coookies` files.

---

## Debugging

Open **Burp Logger** to verify patterns are being resolved correctly, both during pipeline execution and in Burp tools.

---

See also: **[Patterns & Reference](PATTERNS.md)**