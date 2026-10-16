# Zynox (Phase 1: Login + Username)

Telegram-style chat website. This phase has signup, login, logout and unique usernames.

## Files

- `wrangler.toml`  - Cloudflare config
- `schema.sql`     - database tables (users, sessions)
- `src/index.js`   - backend (Cloudflare Worker)
- `public/`        - website (index.html, style.css, app.js)

## Setup in Termux

```
pkg install unzip git
termux-setup-storage
cd ~
unzip ~/storage/downloads/zynox-web.zip
cd zynox-web
git init
git add .
git commit -m "Zynox phase 1"
```

Create an empty repo named `zynox-web` on GitHub, then:

```
git remote add origin https://github.com/zyno-cpu/zynox-web.git
git branch -M main
git push -u origin main
```

## Cloudflare setup (from browser)

1. Cloudflare dashboard -> Storage & Databases -> D1 -> Create database, name: `zynox-db`
2. Open that database -> Console -> paste everything from `schema.sql` -> Execute
3. Copy the Database ID, put it in `wrangler.toml` in place of `REPLACE_WITH_YOUR_DATABASE_ID`, commit and push
4. Workers & Pages -> Create -> Import a repository -> select `zynox-web` -> Deploy

Your site will open at `zynox.<your-subdomain>.workers.dev`.

## Rules implemented

- Username: 5-32 chars, a-z 0-9 _, starts with a letter, no trailing or double underscore, case-insensitive
- Duplicate usernames blocked by a UNIQUE database rule
- Passwords hashed with PBKDF2 (never stored as plain text)
- Session cookie: HttpOnly, Secure, SameSite=Lax, 30 days
