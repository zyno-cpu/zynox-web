(function () {
  const $ = (id) => document.getElementById(id);

  const authView = $("auth-view");
  const chatView = $("chat-view");
  const forms = {
    email: $("email-form"),
    otp: $("otp-form"),
    setup: $("setup-form"),
    login: $("login-form"),
  };
  const authTitle = $("auth-title");
  const authSub = $("auth-sub");
  const switchBtn = $("switch-btn");

  let step = "email";
  let pendingEmail = "";

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

  function post(path, body) {
    return api(path, { method: "POST", body: JSON.stringify(body || {}) });
  }

  // ---------- avatar helpers ----------

  const COLORS = [
    ["#e17076", "#a8473f"], ["#7bc862", "#4a8a38"], ["#e5ca77", "#a68a2e"],
    ["#65aadd", "#3b78a8"], ["#a695e7", "#6c5bb5"], ["#ee7aae", "#b24a7c"],
    ["#6ec9cb", "#3a9496"], ["#faa774", "#c2733a"],
  ];

  function paintAvatar(el, name, seed) {
    let h = 0;
    for (const c of seed) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    const [a, b] = COLORS[h % COLORS.length];
    el.style.background = `linear-gradient(135deg, ${a}, ${b})`;
    el.textContent = (name || seed || "?").trim().charAt(0).toUpperCase();
  }

  // ---------- views ----------

  const COPY = {
    email: ["Sign in to Zynox", "Enter your email. We will send you a verification code."],
    otp: ["Check your email", ""],
    setup: ["Create your profile", "Choose your name and a unique username."],
    login: ["Sign in with password", "Enter your username and password."],
  };

  const SWITCH = {
    email: "Sign in with password",
    otp: "Use a different email",
    setup: "Use a different email",
    login: "Sign in with email code",
  };

  function showStep(next) {
    step = next;
    for (const k in forms) forms[k].classList.toggle("hidden", k !== next);
    authTitle.textContent = COPY[next][0];
    authSub.textContent = next === "otp" ? `We sent a 6-digit code to ${pendingEmail}.` : COPY[next][1];
    switchBtn.textContent = SWITCH[next];
  }

  function showAuth(startStep) {
    chatView.classList.add("hidden");
    authView.classList.remove("hidden");
    showStep(startStep || "email");
  }

  switchBtn.addEventListener("click", async () => {
    if (step === "email") return showStep("login");
    if (step === "setup") await post("/api/logout");
    showStep("email");
  });

  // ---------- step 1: email ----------

  let resendTimer = null;

  function startResendCountdown(seconds) {
    const btn = $("resend-btn");
    clearInterval(resendTimer);
    let left = seconds;
    btn.disabled = true;
    btn.textContent = `Resend code in ${left}s`;
    resendTimer = setInterval(() => {
      left -= 1;
      if (left <= 0) {
        clearInterval(resendTimer);
        btn.disabled = false;
        btn.textContent = "Resend code";
      } else {
        btn.textContent = `Resend code in ${left}s`;
      }
    }, 1000);
  }

  async function sendCode(email, errEl) {
    const { ok, data } = await post("/api/otp/request", { email });
    if (!ok) {
      errEl.textContent = data.error || "Could not send the code.";
      if (data.retryAfter) startResendCountdown(data.retryAfter);
      return false;
    }
    startResendCountdown(data.resendIn || 60);
    return true;
  }

  forms.email.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("email-error");
    err.textContent = "";
    const email = $("email-input").value.trim().toLowerCase();
    const btn = forms.email.querySelector("button[type=submit]");
    btn.disabled = true;
    const sent = await sendCode(email, err);
    btn.disabled = false;
    if (!sent) return;
    pendingEmail = email;
    $("otp-input").value = "";
    $("otp-error").textContent = "";
    showStep("otp");
    $("otp-input").focus();
  });

  // ---------- step 2: code ----------

  $("otp-input").addEventListener("input", (e) => {
    e.target.value = e.target.value.replace(/\D/g, "").slice(0, 6);
  });

  $("resend-btn").addEventListener("click", async () => {
    const err = $("otp-error");
    err.textContent = "";
    await sendCode(pendingEmail, err);
  });

  forms.otp.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("otp-error");
    err.textContent = "";
    const btn = forms.otp.querySelector("button[type=submit]");
    btn.disabled = true;
    const { ok, data } = await post("/api/otp/verify", { email: pendingEmail, code: $("otp-input").value });
    btn.disabled = false;
    if (!ok) { err.textContent = data.error || "Could not verify the code."; return; }
    clearInterval(resendTimer);
    if (data.needsSetup) { prepareSetup(); showStep("setup"); }
    else showChat(data.user);
  });

  // ---------- step 3: profile setup + live username check ----------

  const usernameInput = $("setup-username");
  const usernameStatus = $("username-status");
  const usernameField = usernameInput.parentElement;
  const DEFAULT_HINT = "5-32 characters. Letters, numbers and underscores. Must start with a letter.";

  let checkTimer = null;
  let checkSeq = 0;

  function setUsernameState(state, text) {
    usernameField.classList.remove("ok", "bad");
    usernameStatus.className = "msg hint";
    if (state === "ok") { usernameField.classList.add("ok"); usernameStatus.className = "msg good"; }
    if (state === "bad") { usernameField.classList.add("bad"); usernameStatus.className = "msg error"; }
    usernameStatus.textContent = text;
  }

  function prepareSetup() {
    forms.setup.reset();
    $("setup-error").textContent = "";
    setUsernameState("idle", DEFAULT_HINT);
  }

  usernameInput.addEventListener("input", () => {
    clearTimeout(checkTimer);
    const value = usernameInput.value.trim();
    if (!value) { setUsernameState("idle", DEFAULT_HINT); return; }

    setUsernameState("idle", "Checking...");
    const seq = ++checkSeq;
    checkTimer = setTimeout(async () => {
      const { data } = await api("/api/username/check?u=" + encodeURIComponent(value), { method: "GET" });
      if (seq !== checkSeq) return;
      if (data.available) setUsernameState("ok", data.message);
      else setUsernameState("bad", data.message || "Username not available.");
    }, 350);
  });

  forms.setup.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("setup-error");
    err.textContent = "";
    const btn = forms.setup.querySelector("button[type=submit]");
    btn.disabled = true;
    const { ok, data } = await post("/api/profile/setup", {
      name: $("setup-name").value,
      username: usernameInput.value,
      password: $("setup-password").value,
    });
    btn.disabled = false;
    if (!ok) {
      err.textContent = data.error || "Could not save your profile.";
      if (data.field === "username") setUsernameState("bad", data.error);
      return;
    }
    showChat(data.user);
  });

  // ---------- password login ----------

  forms.login.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("login-error");
    err.textContent = "";
    const btn = forms.login.querySelector("button[type=submit]");
    btn.disabled = true;
    const { ok, data } = await post("/api/login", {
      username: $("login-username").value,
      password: $("login-password").value,
    });
    btn.disabled = false;
    if (!ok) { err.textContent = data.error || "Could not sign in."; return; }
    forms.login.reset();
    showChat(data.user);
  });

  // ---------- chat shell ----------

  const searchInput = $("search-input");
  const resultsEl = $("results");
  let searchTimer = null;
  let searchSeq = 0;
  let activeUsername = null;

  function showChat(user) {
    authView.classList.add("hidden");
    chatView.classList.remove("hidden");
    chatView.classList.remove("conv-open");
    $("me-name").textContent = user.name;
    $("me-user").textContent = "@" + user.username;
    paintAvatar($("me-avatar"), user.name, user.username);
    closeConversation();
    searchInput.value = "";
    renderNote("No chats yet.<br>Search a friend by their @username to start.");
  }

  function renderNote(html) {
    resultsEl.innerHTML = "";
    const div = document.createElement("div");
    div.className = "results-note";
    div.innerHTML = html;
    resultsEl.appendChild(div);
  }

  function renderResults(users) {
    resultsEl.innerHTML = "";
    if (!users.length) { renderNote("No users found."); return; }
    for (const u of users) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "result" + (u.username === activeUsername ? " active" : "");

      const av = document.createElement("div");
      av.className = "avatar";
      paintAvatar(av, u.name, u.username);

      const info = document.createElement("div");
      info.className = "me";
      const nm = document.createElement("div");
      nm.className = "me-name";
      nm.textContent = u.name;
      const un = document.createElement("div");
      un.className = "me-user";
      un.textContent = "@" + u.username;
      info.append(nm, un);

      btn.append(av, info);
      btn.addEventListener("click", () => openConversation(u));
      resultsEl.appendChild(btn);
    }
  }

  searchInput.addEventListener("input", () => {
    clearTimeout(searchTimer);
    const q = searchInput.value.trim().replace(/^@/, "");
    if (!q) { renderNote("No chats yet.<br>Search a friend by their @username to start."); return; }
    const seq = ++searchSeq;
    searchTimer = setTimeout(async () => {
      const { data } = await api("/api/users/search?q=" + encodeURIComponent(q), { method: "GET" });
      if (seq !== searchSeq) return;
      renderResults(data.users || []);
    }, 250);
  });

  function openConversation(u) {
    activeUsername = u.username;
    $("panel-empty").classList.add("hidden");
    $("conv").classList.remove("hidden");
    $("conv-name").textContent = u.name;
    $("conv-user").textContent = "@" + u.username;
    paintAvatar($("conv-avatar"), u.name, u.username);
    $("conv-hint").textContent = "This is the start of your conversation with " + u.name;
    chatView.classList.add("conv-open");
    document.querySelectorAll(".result").forEach((el) => {
      el.classList.toggle("active", el.querySelector(".me-user").textContent === "@" + u.username);
    });
  }

  function closeConversation() {
    activeUsername = null;
    $("conv").classList.add("hidden");
    $("panel-empty").classList.remove("hidden");
    chatView.classList.remove("conv-open");
  }

  $("back-btn").addEventListener("click", closeConversation);

  $("logout-btn").addEventListener("click", async () => {
    await post("/api/logout");
    showAuth("email");
  });

  // ---------- boot ----------

  (async function boot() {
    const { ok, data } = await api("/api/me", { method: "GET" });
    if (ok && data.user) {
      if (data.needsSetup) {
        pendingEmail = data.user.email;
        prepareSetup();
        showAuth("setup");
      } else {
        showChat(data.user);
      }
    } else {
      showAuth("email");
    }
  })();
})();
