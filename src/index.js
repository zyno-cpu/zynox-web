// Zynox - auth backend (Cloudflare Worker + D1)

const RESERVED = new Set([
  "admin", "administrator", "zynox", "zynogram", "support", "help", "official",
  "system", "root", "moderator", "settings", "login", "signup", "telegram",
  "whatsapp", "security", "service", "staff", "info", "contact",
]);

const PBKDF2_ITERATIONS = 100000; // Workers max
const SESSION_DAYS = 30;
const COOKIE_NAME = "zx_session";

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

// A fixed fake hash so login takes similar time for unknown usernames.
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
    `SELECT u.id, u.name, u.username FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(tokenHash, Date.now()).first();
  return row || null;
}

// ---------- handlers ----------

async function checkUsername(env, url) {
  const v = validateUsername(url.searchParams.get("u"));
  if (!v.ok) return json({ available: false, reason: "invalid", message: v.error });
  const row = await env.DB.prepare("SELECT 1 AS x FROM users WHERE username_lower = ?").bind(v.lower).first();
  if (row) return json({ available: false, reason: "taken", message: "This username is already taken." });
  return json({ available: true, message: "Username is available." });
}

async function signup(env, body) {
  const n = validateName(body.name);
  if (!n.ok) return json({ error: n.error }, 400);
  const u = validateUsername(body.username);
  if (!u.ok) return json({ error: u.error, field: "username" }, 400);
  const p = validatePassword(body.password);
  if (!p.ok) return json({ error: p.error, field: "password" }, 400);

  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(p.password);

  try {
    // The UNIQUE constraint on username_lower is the real guard against duplicates,
    // even if two people submit the same username at the same moment.
    await env.DB.prepare(
      "INSERT INTO users (id, name, username, username_lower, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(id, n.name, u.display, u.lower, passwordHash, Date.now()).run();
  } catch (e) {
    if (String(e && e.message).includes("UNIQUE")) {
      return json({ error: "This username is already taken.", field: "username" }, 409);
    }
    throw e;
  }

  const session = await createSession(env, id);
  return json(
    { user: { id, name: n.name, username: u.display } },
    201,
    { "set-cookie": sessionCookie(session.token, session.maxAge) }
  );
}

async function login(env, body) {
  const lower = String(body.username ?? "").trim().replace(/^@/, "").toLowerCase();
  const password = String(body.password ?? "");
  const generic = "Incorrect username or password.";

  if (!lower || !password) return json({ error: generic }, 401);

  const user = await env.DB.prepare(
    "SELECT id, name, username, password_hash FROM users WHERE username_lower = ?"
  ).bind(lower).first();

  const ok = await verifyPassword(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) return json({ error: generic }, 401);

  const session = await createSession(env, user.id);
  return json(
    { user: { id: user.id, name: user.name, username: user.username } },
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
      if (url.pathname === "/api/username/check" && request.method === "GET") {
        return await checkUsername(env, url);
      }
      if (url.pathname === "/api/me" && request.method === "GET") {
        const user = await getUserFromRequest(env, request);
        return user ? json({ user }) : json({ user: null }, 401);
      }
      if (url.pathname === "/api/logout" && request.method === "POST") {
        return await logout(env, request);
      }
      if (url.pathname === "/api/signup" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        return await signup(env, body);
      }
      if (url.pathname === "/api/login" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        return await login(env, body);
      }
      return json({ error: "Not found." }, 404);
    } catch (e) {
      console.error(e);
      return json({ error: "Something went wrong. Please try again." }, 500);
    }
  },
};
