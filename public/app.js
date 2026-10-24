(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const authView = $("#auth-view");
  const vaultView = $("#vault-view");
  const authForm = $("#auth-form");
  const authMessage = $("#auth-message");
  const vaultMessage = $("#vault-message");
  const entryDialog = $("#entry-dialog");
  const entryForm = $("#entry-form");
  const SESSION_KEY = "impPassSession";
  let authMode = "login";
  let entries = [];
  let editingPid = null;
  const revealed = new Set();

  function setMessage(element, message = "", kind = "") {
    element.textContent = message;
    element.className = "form-message" + (kind ? " " + kind : "");
  }

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (options.body && !(options.body instanceof FormData)) {
      headers.set("Content-Type", "application/json");
    }
    const sessionId = sessionStorage.getItem(SESSION_KEY);
    if (sessionId) headers.set("Authorization", "Session " + sessionId);

    const response = await fetch(path, { ...options, headers });
    const raw = await response.text();
    let data = null;
    try { data = raw ? JSON.parse(raw) : null; } catch { data = raw; }
    if (!response.ok) {
      const message = data && typeof data === "object" && data.message
        ? data.message
        : "Request failed (" + response.status + ").";
      if (response.status === 401 || response.status === 403) {
        sessionStorage.removeItem(SESSION_KEY);
      }
      throw new Error(message);
    }
    return { data, response };
  }

  function setAuthMode(mode) {
    authMode = mode;
    const isLogin = mode === "login";
    $("#login-tab").classList.toggle("active", isLogin);
    $("#register-tab").classList.toggle("active", !isLogin);
    $("#login-tab").setAttribute("aria-selected", String(isLogin));
    $("#register-tab").setAttribute("aria-selected", String(!isLogin));
    $("#auth-title").textContent = isLogin ? "Welcome back." : "Make it yours.";
    $("#auth-description").textContent = isLogin
      ? "Your vault is right where you left it."
      : "Create an account for your personal vault.";
    $("#auth-submit span:first-child").textContent = isLogin ? "Unlock vault" : "Create account";
    $("#master-password").autocomplete = isLogin ? "current-password" : "new-password";
    $("#register-hint").hidden = isLogin;
    setMessage(authMessage);
  }

  function showVault(email) {
    authView.hidden = true;
    vaultView.hidden = false;
    $("#welcome-user").textContent = email ? "Signed in as " + email : "Your private collection, all in one place.";
    setMessage(vaultMessage);
  }

  function showAuth() {
    vaultView.hidden = true;
    authView.hidden = false;
    authForm.reset();
    setAuthMode("login");
  }

  async function authenticate(email, password) {
    const { response, data } = await request("/initSession", {
      method: "GET",
      headers: { email, password }
    });
    const sessionId = data && data.sessionID ? data.sessionID : response.headers.get("Session");
    if (!sessionId) throw new Error("The server did not return a session ID.");
    sessionStorage.setItem(SESSION_KEY, sessionId);
  }

  async function loadEntries() {
    setMessage(vaultMessage, "Loading your entries…");
    try {
      const { data } = await request("/password?pID=all");
      entries = Array.isArray(data) ? data : [];
      renderEntries();
      setMessage(vaultMessage);
    } catch (error) {
      entries = [];
      renderEntries();
      if (!sessionStorage.getItem(SESSION_KEY)) {
        showAuth();
        setMessage(authMessage, "Your session may have expired. Please sign in again.", "error");
      } else {
        setMessage(vaultMessage, error.message || "Couldn't load your entries.", "error");
      }
    }
  }

  function iconFor(name) {
    const first = (name || "?").trim().charAt(0);
    return first ? first.toUpperCase() : "?";
  }

  function renderEntries() {
    const query = $("#search").value.trim().toLowerCase();
    const filtered = entries.filter(entry => String(entry.pID || "").toLowerCase().includes(query));
    $("#entry-count").textContent = String(entries.length);
    $("#results-label").textContent = filtered.length + (filtered.length === 1 ? " entry" : " entries");
    const list = $("#password-list");
    list.replaceChildren();

    for (const entry of filtered) {
      const card = document.createElement("article");
      card.className = "password-card";
      const top = document.createElement("div");
      top.className = "entry-top";
      const icon = document.createElement("div");
      icon.className = "entry-icon";
      icon.textContent = iconFor(entry.pID);
      const meta = document.createElement("div");
      meta.className = "entry-meta";
      const title = document.createElement("h3");
      title.textContent = entry.pID || "Untitled";
      const subtitle = document.createElement("p");
      subtitle.textContent = "PASSWORD ENTRY";
      meta.append(title, subtitle);

      const actions = document.createElement("div");
      actions.className = "entry-actions";
      actions.append(
        actionButton("✎", "Edit entry", () => openEntryDialog(entry)),
        actionButton("⌫", "Delete entry", () => deleteEntry(entry.pID), "delete")
      );
      top.append(icon, meta, actions);

      const secret = document.createElement("div");
      secret.className = "secret-row";
      const value = document.createElement("span");
      value.className = "secret-value";
      const isRevealed = revealed.has(entry.pID);
      value.textContent = isRevealed ? String(entry.password ?? "") : "••••••••••••";
      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "secret-toggle";
      toggle.textContent = isRevealed ? "HIDE" : "REVEAL";
      toggle.addEventListener("click", () => {
        isRevealed ? revealed.delete(entry.pID) : revealed.add(entry.pID);
        renderEntries();
      });
      const copy = document.createElement("button");
      copy.type = "button";
      copy.className = "icon-button";
      copy.title = "Copy password";
      copy.setAttribute("aria-label", "Copy password for " + entry.pID);
      copy.textContent = "▣";
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(String(entry.password ?? ""));
          setMessage(vaultMessage, "Password copied. Clipboard contents may remain available to other apps.", "success");
        } catch {
          setMessage(vaultMessage, "Clipboard access was blocked by your browser.", "error");
        }
      });
      secret.append(value, toggle, copy);
      card.append(top, secret);
      list.append(card);
    }

    $("#empty-state").hidden = entries.length > 0;
    list.hidden = filtered.length === 0;
    if (entries.length > 0 && filtered.length === 0) {
      $("#empty-state").hidden = false;
      $("#empty-state h3").textContent = "No matching entries.";
      $("#empty-state p").textContent = "Try another name in the search box.";
      $("#empty-add").hidden = true;
    } else {
      $("#empty-state h3").textContent = "Your vault starts here.";
      $("#empty-state p").textContent = "Add your first entry and give your memory a break.";
      $("#empty-add").hidden = false;
    }
  }

  function actionButton(symbol, label, onClick, extraClass = "") {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "icon-button" + (extraClass ? " " + extraClass : "");
    button.textContent = symbol;
    button.title = label;
    button.setAttribute("aria-label", label);
    button.addEventListener("click", onClick);
    return button;
  }

  function openEntryDialog(entry = null) {
    editingPid = entry ? entry.pID : null;
    $("#dialog-title").textContent = entry ? "Edit entry" : "Add a password";
    $("#entry-name").value = entry ? entry.pID : "";
    $("#entry-password").value = entry ? entry.password : "";
    $("#entry-password").required = true;
    $("#save-entry span:first-child").textContent = entry ? "Update entry" : "Save entry";
    setMessage($("#entry-message"));
    entryDialog.showModal();
    $("#entry-name").focus();
  }

  async function deleteEntry(pid) {
    if (!window.confirm('Delete the "' + pid + '" entry? This cannot be undone.')) return;
    try {
      await request("/delete?pID=" + encodeURIComponent(pid), { method: "GET" });
      entries = entries.filter(entry => entry.pID !== pid);
      revealed.delete(pid);
      renderEntries();
      setMessage(vaultMessage, "Entry deleted.", "success");
    } catch (error) {
      setMessage(vaultMessage, error.message || "Couldn't delete that entry.", "error");
    }
  }

  $("#login-tab").addEventListener("click", () => setAuthMode("login"));
  $("#register-tab").addEventListener("click", () => setAuthMode("register"));

  authForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = $("#email").value.trim();
    const password = $("#master-password").value;
    const submit = $("#auth-submit");
    submit.disabled = true;
    setMessage(authMessage, authMode === "login" ? "Unlocking your vault…" : "Creating your account…");
    try {
      if (authMode === "register") {
        await request("/register", { method: "POST", body: JSON.stringify({ email, password }) });
        await authenticate(email, password);
      } else {
        await authenticate(email, password);
      }
      $("#master-password").value = "";
      showVault(email);
      await loadEntries();
    } catch (error) {
      sessionStorage.removeItem(SESSION_KEY);
      setMessage(authMessage, error.message || "Something went wrong. Please try again.", "error");
    } finally {
      submit.disabled = false;
    }
  });

  $("#add-password").addEventListener("click", () => openEntryDialog());
  $("#empty-add").addEventListener("click", () => openEntryDialog());
  $("#search").addEventListener("input", renderEntries);
  $("#sign-out").addEventListener("click", () => {
    sessionStorage.removeItem(SESSION_KEY);
    entries = [];
    revealed.clear();
    $("#search").value = "";
    showAuth();
  });
  $("#close-dialog").addEventListener("click", () => entryDialog.close());
  $("#cancel-entry").addEventListener("click", () => entryDialog.close());

  entryForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const pID = $("#entry-name").value.trim();
    const password = $("#entry-password").value;
    const save = $("#save-entry");
    if (!pID || !password) {
      setMessage($("#entry-message"), "Both fields are required.", "error");
      return;
    }
    save.disabled = true;
    setMessage($("#entry-message"), editingPid ? "Updating entry…" : "Saving entry…");
    try {
      if (editingPid && editingPid !== pID) {
        await request("/update?pID=" + encodeURIComponent(editingPid), {
          method: "PUT",
          body: JSON.stringify({ pID })
        });
        await request("/update?pID=" + encodeURIComponent(pID), {
          method: "PUT",
          body: JSON.stringify({ password })
        });
      } else if (editingPid) {
        await request("/update?pID=" + encodeURIComponent(editingPid), {
          method: "PUT",
          body: JSON.stringify({ password })
        });
      } else {
        await request("/new", { method: "PUT", body: JSON.stringify({ pID, password }) });
      }
      entryDialog.close();
      await loadEntries();
      setMessage(vaultMessage, editingPid ? "Entry updated." : "Entry saved.", "success");
    } catch (error) {
      setMessage($("#entry-message"), error.message || "Couldn't save this entry.", "error");
    } finally {
      save.disabled = false;
    }
  });

  document.querySelectorAll("[data-toggle]").forEach(button => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.toggle);
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      button.textContent = show ? "HIDE" : "SHOW";
      button.setAttribute("aria-label", (show ? "Hide " : "Show ") + input.name);
    });
  });

  // A session is held only for this browser tab. If it has expired, the API
  // reports that on the first vault request and the user can sign in again.
  if (sessionStorage.getItem(SESSION_KEY)) {
    authView.hidden = true;
    vaultView.hidden = false;
    loadEntries();
  }
})();