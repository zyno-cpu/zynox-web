// Zynox - backend (Cloudflare Worker + D1)
// Phase A: email OTP login, profile setup (name, @username, password), user search.

const RESERVED = new Set([
  "admin", "administrator", "zynox", "zynogram", "support", "help", "official",
  "system", "root", "moderator", "settings", "login", "signup", "telegram",
  "whatsapp", "security", "service", "staff", "info", "contact",
]);

const PBKDF2_ITERATIONS = 100000; // Workers max
const SESSION_DAYS = 30;
const COOKIE_NAME = "zx_session";
const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_RESEND_MS = 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

const enc = new TextEncoder();

// ---------- helpers ----------

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

function b64(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}

function unb64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function hex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(text) {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(
    await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256)
  );
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${b64(salt)}$${b64(hash)}`;
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function verifyPassword(password, stored) {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = parseInt(parts[1], 10);
  const salt = unb64(parts[2]);
  const expected = unb64(parts[3]);
  const actual = await derive(password, salt, iterations);
  return safeEqual(actual, expected);
}

// Fixed fake hash so login takes similar time for unknown usernames.
const DUMMY_HASH = "pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

// ---------- validation ----------

export function validateUsername(raw) {
  const value = String(raw ?? "").trim().replace(/^@/, "");
  const lower = value.toLowerCase();

  if (lower.length < 5) return { ok: false, error: "Username must be at least 5 characters." };
  if (lower.length > 32) return { ok: false, error: "Username can be at most 32 characters." };
  if (!/^[a-z0-9_]+$/.test(lower)) {
    return { ok: false, error: "Only a-z, 0-9 and underscores are allowed." };
  }
  if (!/^[a-z]/.test(lower)) return { ok: false, error: "Username must start with a letter." };
  if (lower.endsWith("_")) return { ok: false, error: "Username cannot end with an underscore." };
  if (lower.includes("__")) return { ok: false, error: "Username cannot contain two underscores in a row." };
  if (RESERVED.has(lower)) return { ok: false, error: "This username is reserved." };

  return { ok: true, display: value, lower };
}

function validateName(raw) {
  const name = String(raw ?? "").trim().replace(/\s+/g, " ");
  if (name.length < 1) return { ok: false, error: "Please enter your name." };
  if (name.length > 64) return { ok: false, error: "Name can be at most 64 characters." };
  return { ok: true, name };
}

function validatePassword(raw) {
  const p = String(raw ?? "");
  if (p.length < 8) return { ok: false, error: "Password must be at least 8 characters." };
  if (p.length > 128) return { ok: false, error: "Password is too long." };
  return { ok: true, password: p };
}

function validateEmail(raw) {
  const email = String(raw ?? "").trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { ok: false, error: "Enter a valid email address." };
  }
  return { ok: true, email };
}

// ---------- sessions ----------

function getCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

function sessionCookie(token, maxAgeSeconds) {
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

async function createSession(env, userId) {
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  const expires = now + SESSION_DAYS * 24 * 60 * 60 * 1000;
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
  ).bind(tokenHash, userId, expires, now).run();
  return { token, maxAge: SESSION_DAYS * 24 * 60 * 60 };
}

async function getUserFromRequest(env, request) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT u.id, u.email, u.name, u.username FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(tokenHash, Date.now()).first();
  return row || null;
}

function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, username: u.username };
}

// ---------- email OTP ----------

function makeCode() {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return String(n).padStart(6, "0");
}

async function sendOtpEmail(env, email, code) {
  if (!env.BREVO_API_KEY || !env.SENDER_EMAIL) {
    throw new Error("BREVO_API_KEY or SENDER_EMAIL is not configured");
  }
  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": env.BREVO_API_KEY,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({
      sender: { name: env.SENDER_NAME || "Zynox", email: env.SENDER_EMAIL },
      to: [{ email }],
      subject: `Your Zynox code: ${code}`,
      textContent:
        `Your Zynox login code is ${code}.\n\nIt expires in 10 minutes. ` +
        `If you did not request this, you can ignore this email.`,
      htmlContent:
        `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px;color:#17212b">` +
        `<h2 style="margin:0 0 12px">Zynox</h2>` +
        `<p style="margin:0 0 16px">Your login code is:</p>` +
        `<p style="font-size:34px;letter-spacing:8px;font-weight:700;margin:0 0 16px">${code}</p>` +
        `<p style="color:#667788;font-size:13px;margin:0">It expires in 10 minutes. ` +
        `If you did not request this, you can ignore this email.</p></div>`,
    }),
  });
  if (!res.ok) {
    throw new Error(`Brevo error ${res.status}: ${await res.text()}`);
  }
}

async function requestOtp(env, body) {
  const e = validateEmail(body.email);
  if (!e.ok) return json({ error: e.error }, 400);

  const now = Date.now();
  const existing = await env.DB.prepare("SELECT last_sent_at FROM otp_codes WHERE email = ?").bind(e.email).first();
  if (existing && now - existing.last_sent_at < OTP_RESEND_MS) {
    const wait = Math.ceil((OTP_RESEND_MS - (now - existing.last_sent_at)) / 1000);
    return json({ error: `Please wait ${wait} seconds before requesting a new code.`, retryAfter: wait }, 429);
  }

  const code = makeCode();
  const codeHash = await sha256Hex(`${e.email}:${code}`);
  await env.DB.prepare(
    `INSERT INTO otp_codes (email, code_hash, expires_at, attempts, last_sent_at)
     VALUES (?, ?, ?, 0, ?)
     ON CONFLICT(email) DO UPDATE SET
       code_hash = excluded.code_hash,
       expires_at = excluded.expires_at,
       attempts = 0,
       last_sent_at = excluded.last_sent_at`
  ).bind(e.email, codeHash, now + OTP_TTL_MS, now).run();

  try {
    await sendOtpEmail(env, e.email, code);
  } catch (err) {
    console.error(err);
    await env.DB.prepare("DELETE FROM otp_codes WHERE email = ?").bind(e.email).run();
    return json({ error: "Could not send the code. Please try again in a moment." }, 502);
  }
  return json({ ok: true, resendIn: OTP_RESEND_MS / 1000 });
}

async function verifyOtp(env, body) {
  const e = validateEmail(body.email);
  if (!e.ok) return json({ error: e.error }, 400);
  const code = String(body.code ?? "").trim();
  if (!/^\d{6}$/.test(code)) return json({ error: "Enter the 6-digit code." }, 400);

  const row = await env.DB.prepare(
    "SELECT code_hash, expires_at, attempts FROM otp_codes WHERE email = ?"
  ).bind(e.email).first();

  if (!row) return json({ error: "Request a new code to continue." }, 400);
  if (row.expires_at < Date.now()) {
    await env.DB.prepare("DELETE FROM otp_codes WHERE email = ?").bind(e.email).run();
    return json({ error: "This code has expired. Request a new one." }, 400);
  }
  if (row.attempts >= OTP_MAX_ATTEMPTS) {
    await env.DB.prepare("DELETE FROM otp_codes WHERE email = ?").bind(e.email).run();
    return json({ error: "Too many wrong attempts. Request a new code." }, 429);
  }

  const given = await sha256Hex(`${e.email}:${code}`);
  if (given !== row.code_hash) {
    await env.DB.prepare("UPDATE otp_codes SET attempts = attempts + 1 WHERE email = ?").bind(e.email).run();
    return json({ error: "Incorrect code." }, 400);
  }

  await env.DB.prepare("DELETE FROM otp_codes WHERE email = ?").bind(e.email).run();

  let user = await env.DB.prepare(
    "SELECT id, email, name, username FROM users WHERE email = ?"
  ).bind(e.email).first();

  if (!user) {
    const id = crypto.randomUUID();
    try {
      await env.DB.prepare("INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)").bind(id, e.email, Date.now()).run();
    } catch (err) {
      if (!String(err && err.message).includes("UNIQUE")) throw err;
    }
    user = await env.DB.prepare("SELECT id, email, name, username FROM users WHERE email = ?").bind(e.email).first();
  }

  const session = await createSession(env, user.id);
  return json(
    { user: publicUser(user), needsSetup: !user.username },
    200,
    { "set-cookie": sessionCookie(session.token, session.maxAge) }
  );
}

// ---------- profile + username ----------

async function checkUsername(env, url) {
  const v = validateUsername(url.searchParams.get("u"));
  if (!v.ok) return json({ available: false, reason: "invalid", message: v.error });
  const row = await env.DB.prepare("SELECT 1 AS x FROM users WHERE username_lower = ?").bind(v.lower).first();
  if (row) return json({ available: false, reason: "taken", message: "This username is already taken." });
  return json({ available: true, message: "Username is available." });
}

async function setupProfile(env, user, body) {
  if (user.username) return json({ error: "Your profile is already set up." }, 409);

  const n = validateName(body.name);
  if (!n.ok) return json({ error: n.error, field: "name" }, 400);
  const u = validateUsername(body.username);
  if (!u.ok) return json({ error: u.error, field: "username" }, 400);
  const p = validatePassword(body.password);
  if (!p.ok) return json({ error: p.error, field: "password" }, 400);

  const passwordHash = await hashPassword(p.password);

  try {
    // The UNIQUE constraint on username_lower is the real guard against duplicates,
    // even if two people submit the same username at the same moment.
    await env.DB.prepare(
      "UPDATE users SET name = ?, username = ?, username_lower = ?, password_hash = ? WHERE id = ? AND username IS NULL"
    ).bind(n.name, u.display, u.lower, passwordHash, user.id).run();
  } catch (e) {
    if (String(e && e.message).includes("UNIQUE")) {
      return json({ error: "This username is already taken.", field: "username" }, 409);
    }
    throw e;
  }

  const fresh = await env.DB.prepare("SELECT id, email, name, username FROM users WHERE id = ?").bind(user.id).first();
  return json({ user: publicUser(fresh) });
}

async function login(env, body) {
  const lower = String(body.username ?? "").trim().replace(/^@/, "").toLowerCase();
  const password = String(body.password ?? "");
  const generic = "Incorrect username or password.";

  if (!lower || !password) return json({ error: generic }, 401);

  const user = await env.DB.prepare(
    "SELECT id, email, name, username, password_hash FROM users WHERE username_lower = ?"
  ).bind(lower).first();

  const hash = user && user.password_hash ? user.password_hash : DUMMY_HASH;
  const ok = await verifyPassword(password, hash);
  if (!user || !user.password_hash || !ok) return json({ error: generic }, 401);

  const session = await createSession(env, user.id);
  return json(
    { user: publicUser(user), needsSetup: false },
    200,
    { "set-cookie": sessionCookie(session.token, session.maxAge) }
  );
}

async function logout(env, request) {
  const token = getCookie(request, COOKIE_NAME);
  if (token) {
    const tokenHash = await sha256Hex(token);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
  }
  return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
}

// ---------- search ----------

async function searchUsers(env, user, url) {
  const q = String(url.searchParams.get("q") ?? "").trim().replace(/^@/, "").toLowerCase();
  if (q.length < 1 || q.length > 32 || !/^[a-z0-9_]+$/.test(q)) return json({ users: [] });

  const like = q.replace(/[\\_%]/g, (m) => "\\" + m) + "%";
  const { results } = await env.DB.prepare(
    `SELECT id, name, username FROM users
     WHERE username_lower LIKE ? ESCAPE '\\' AND id != ? AND username IS NOT NULL
     ORDER BY (username_lower = ?) DESC, username_lower
     LIMIT 20`
  ).bind(like, user.id, q).all();

  return json({ users: results || [] });
}

// ---------- router ----------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    // Basic CSRF protection: state-changing requests must come from our own origin.
    if (request.method !== "GET" && request.method !== "HEAD") {
      const origin = request.headers.get("origin");
      if (origin && origin !== url.origin) return json({ error: "Forbidden." }, 403);
    }

    try {
      const path = url.pathname;
      const method = request.method;
      const readBody = () => request.json().catch(() => ({}));

      if (path === "/api/otp/request" && method === "POST") return await requestOtp(env, await readBody());
      if (path === "/api/otp/verify" && method === "POST") return await verifyOtp(env, await readBody());
      if (path === "/api/login" && method === "POST") return await login(env, await readBody());
      if (path === "/api/logout" && method === "POST") return await logout(env, request);
      if (path === "/api/username/check" && method === "GET") return await checkUsername(env, url);

      // everything below needs a signed-in user
      const user = await getUserFromRequest(env, request);

      if (path === "/api/me" && method === "GET") {
        return user ? json({ user: publicUser(user), needsSetup: !user.username }) : json({ user: null }, 401);
      }
      if (!user) return json({ error: "Please sign in." }, 401);

      if (path === "/api/profile/setup" && method === "POST") return await setupProfile(env, user, await readBody());

      if (!user.username) return json({ error: "Finish setting up your profile first." }, 403);

      if (path === "/api/users/search" && method === "GET") return await searchUsers(env, user, url);

      return json({ error: "Not found." }, 404);
    } catch (e) {
      console.error(e);
      return json({ error: "Something went wrong. Please try again." }, 500);
    }
  },
};
