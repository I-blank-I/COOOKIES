# COOOKIES – Burp Suite Extension

![](./img/cookies.png)

![Burp Suite Pro](https://img.shields.io/badge/Burp%20Suite-Pro-orange) ![Version](https://img.shields.io/badge/version-2.0.1-blue)

Automate multi-step authentication flows and manage session tokens across multiple user accounts — all from inside Burp Suite.

---

## What it does

Build a pipeline of HTTP requests that logs users in and extracts session tokens. Once the pipeline runs, extracted values can be injected into any Burp tool via patterns like `<__COOOKIES__:username>`. Responses are monitored for session expiration strings and the pipeline re-runs automatically when a session dies.

---

## Installation

**Requires:** Burp Suite Professional v2026.2.3+

1. Download `COOOKIES.jar` from Releases
2. In Burp: `Extensions → Installed → Add` → select the JAR

---

## Docs

- **[Guide](docs/GUIDE.md)** — building a pipeline, credentials, running it, hotkeys, checkpoints, auto-refresh, saving your config
- **[Patterns & Reference](docs/PATTERNS.md)** — the pattern syntax, extraction types, and a full worked example

---

## Works great with LazyFlow

Configuring extraction rules manually for complex flows is tedious. **[LazyFlow](https://github.com/I-blank-I/LazyFlow)** automates it — select your login flow in Proxy, send to LazyFlow, and it generates a ready-to-import `.coookies` file with all placeholders and extraction rules pre-filled.

> Credentials are never filled automatically — you always add those yourself.

---

## Disclaimer

For authorized security testing only. Always obtain proper permission before testing systems you don't own.