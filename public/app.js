(function () {
  const $ = (id) => document.getElementById(id);

  const authView = $("auth-view");
  const chatView = $("chat-view");
  const loginForm = $("login-form");
  const signupForm = $("signup-form");
  const switchBtn = $("switch-mode");
  const authTitle = $("auth-title");
  const authSub = $("auth-sub");

  let mode = "login";

  async function api(path, options) {
    const res = await fetch(path, {
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      ...options,
    });
    let data = {};
    try { data = await res.json(); } catch (e) {}
    return { ok: res.ok, status: res.status, data };
  }

  // ---------- views ----------

  function showAuth() {
    chatView.classList.add("hidden");
    authView.classList.remove("hidden");
    setMode(mode);
  }

  function showChat(user) {
    authView.classList.add("hidden");
    chatView.classList.remove("hidden");
    $("me-name").textContent = user.name;
    $("me-user").textContent = "@" + user.username;
    $("me-avatar").textContent = user.name.trim().charAt(0).toUpperCase();
  }

  function setMode(next) {
    mode = next;
    const isLogin = mode === "login";
    loginForm.classList.toggle("hidden", !isLogin);
    signupForm.classList.toggle("hidden", isLogin);
    authTitle.textContent = isLogin ? "Sign in to Zynox" : "Create your account";
    authSub.textContent = isLogin
      ? "Enter your username and password."
      : "Pick a name and a unique username.";
    switchBtn.textContent = isLogin ? "Create a new account" : "I already have an account";
  }

  switchBtn.addEventListener("click", () => setMode(mode === "login" ? "signup" : "login"));

  // ---------- login ----------

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("login-error");
    err.textContent = "";
    const btn = loginForm.querySelector("button[type=submit]");
    btn.disabled = true;
    const { ok, data } = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("login-username").value,
        password: $("login-password").value,
      }),
    });
    btn.disabled = false;
    if (!ok) { err.textContent = data.error || "Could not sign in."; return; }
    loginForm.reset();
    showChat(data.user);
  });

  // ---------- signup + live username check ----------

  const usernameInput = $("signup-username");
  const usernameStatus = $("username-status");
  const usernameField = usernameInput.parentElement;
  const DEFAULT_HINT = "5-32 characters. Letters, numbers and underscores. Must start with a letter.";

  let usernameOk = false;
  let checkTimer = null;
  let checkSeq = 0;

  function setUsernameState(state, text) {
    usernameField.classList.remove("ok", "bad");
    usernameStatus.className = "msg hint";
    if (state === "ok") { usernameField.classList.add("ok"); usernameStatus.className = "msg good"; }
    if (state === "bad") { usernameField.classList.add("bad"); usernameStatus.className = "msg error"; }
    usernameStatus.textContent = text;
  }

  usernameInput.addEventListener("input", () => {
    usernameOk = false;
    clearTimeout(checkTimer);
    const value = usernameInput.value.trim();
    if (!value) { setUsernameState("idle", DEFAULT_HINT); return; }

    setUsernameState("idle", "Checking...");
    const seq = ++checkSeq;
    checkTimer = setTimeout(async () => {
      const { data } = await api("/api/username/check?u=" + encodeURIComponent(value), { method: "GET" });
      if (seq !== checkSeq) return; // a newer check is running
      if (data.available) { usernameOk = true; setUsernameState("ok", data.message); }
      else { setUsernameState("bad", data.message || "Username not available."); }
    }, 350);
  });

  signupForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("signup-error");
    err.textContent = "";
    const btn = signupForm.querySelector("button[type=submit]");
    btn.disabled = true;
    const { ok, data } = await api("/api/signup", {
      method: "POST",
      body: JSON.stringify({
        name: $("signup-name").value,
        username: usernameInput.value,
        password: $("signup-password").value,
      }),
    });
    btn.disabled = false;
    if (!ok) {
      err.textContent = data.error || "Could not create account.";
      if (data.field === "username") setUsernameState("bad", data.error);
      return;
    }
    signupForm.reset();
    setUsernameState("idle", DEFAULT_HINT);
    showChat(data.user);
  });

  // ---------- logout + boot ----------

  $("logout-btn").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST", body: "{}" });
    mode = "login";
    showAuth();
  });

  (async function boot() {
    const { ok, data } = await api("/api/me", { method: "GET" });
    if (ok && data.user) showChat(data.user);
    else showAuth();
  })();
})();
