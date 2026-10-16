# Zynox

Telegram-style chat website.

## Phase A (this version)

- Email OTP login (code sent by Brevo)
- Profile setup: name, unique @username, password
- Password login for returning users
- Search users by @username
- Chat screen shell (real-time messaging comes in Phase B)

## Files

- `wrangler.toml`  - Cloudflare config (D1 id and sender email are set here)
- `schema.sql`     - database tables (v2, drops old tables)
- `src/index.js`   - backend (Cloudflare Worker)
- `public/`        - website

## Secrets (set in Cloudflare, never in code)

- `BREVO_API_KEY` - Worker, Settings, Variables and Secrets, type: Secret

`SENDER_EMAIL` in `wrangler.toml` must be a sender verified in Brevo.

## Rules implemented

- Username: 5-32 chars, a-z 0-9 _, starts with a letter, no trailing or double underscore, case-insensitive, unique (database rule)
- OTP: 6 digits, valid 10 minutes, 5 wrong attempts max, resend after 60 seconds, single use
- Passwords hashed with PBKDF2
- Session cookie: HttpOnly, Secure, SameSite=Lax, 30 days
