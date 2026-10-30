"use strict";

// The page is served by the API itself, so every call is same-origin and the
// HttpOnly session cookie rides along automatically.

const MAX_BYTES = 50 * 1024 * 1024;

const $ = (id) => document.getElementById(id);

const authView = $("auth-view");
const appView = $("app-view");
const account = $("account");
const whoami = $("whoami");
const logoutButton = $("logout");
const modeLogin = $("mode-login");
const modeSignup = $("mode-signup");
const authForm = $("auth-form");
const usernameInput = $("username");
const passwordInput = $("password");
const authHint = $("auth-hint");
const authSubmit = $("auth-submit");
const usage = $("usage");
const usageText = $("usage-text");
const usageBar = $("usage-bar");
const fileInput = $("file");
const fileName = $("file-name");
const uploadButton = $("upload");
const progress = $("progress");
const progressBar = $("progress-bar");
const refreshButton = $("refresh");
const filesEl = $("files");
const statusEl = $("status");

let mode = "login";
let quota = { used: 0, total: 0 };

function setStatus(text, kind) {
  statusEl.textContent = text;
  statusEl.className = "status" + (kind ? " " + kind : "");
}

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function api(path, options) {
  const res = await fetch(path, options || {});
  let body = null;
  if (res.status !== 204) {
    try {
      body = await res.json();
    } catch (_) {
      // A non-JSON body is reported through the status code below.
    }
  }
  if (!res.ok) {
    throw new ApiError((body && body.error) || "Request failed with HTTP " + res.status, res.status);
  }
  return body;
}

function postJSON(path, data) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data || {})
  });
}

// Any 401 means the session is gone: drop back to the sign-in form.
function handleError(err) {
  if (err instanceof ApiError && err.status === 401) {
    showAuth();
    setStatus(err.message, "error");
    return;
  }
  setStatus(err.message, "error");
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return (value < 10 ? value.toFixed(1) : Math.round(value)) + " " + units[unit];
}

/* ---------- Views ---------- */

function showAuth() {
  appView.hidden = true;
  account.hidden = true;
  authView.hidden = false;
  passwordInput.value = "";
  usernameInput.focus();
}

function showApp(me) {
  authView.hidden = true;
  appView.hidden = false;
  account.hidden = false;
  whoami.textContent = me.username;
  renderUsage(me.usedBytes, me.quotaBytes);
}

function setMode(next) {
  mode = next;
  const signup = mode === "signup";
  modeLogin.setAttribute("aria-pressed", String(!signup));
  modeSignup.setAttribute("aria-pressed", String(signup));
  authSubmit.textContent = signup ? "Create account" : "Sign in";
  passwordInput.autocomplete = signup ? "new-password" : "current-password";
  authHint.textContent = signup
    ? "3-32 characters for the username (letters, digits, _ or -). Password 8-72 characters."
    : "Welcome back, choom.";
}

function renderUsage(used, total) {
  quota = { used: used, total: total };
  const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
  usageText.textContent = formatBytes(used) + " / " + formatBytes(total);
  usageBar.style.width = pct + "%";
  usage.classList.toggle("is-full", pct >= 90);
}

function renderFiles(files) {
  filesEl.replaceChildren();
  if (!files || files.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "No files yet. Upload something.";
    filesEl.append(empty);
    return;
  }
  for (const file of files) {
    const item = document.createElement("li");

    const name = document.createElement("span");
    name.className = "file-name";
    name.textContent = file.name || file.key;
    name.title = file.name || file.key;

    const meta = document.createElement("span");
    meta.className = "file-meta";
    const when = file.lastModified ? new Date(file.lastModified).toLocaleString() : "";
    meta.textContent = formatBytes(file.size) + (when ? " · " + when : "");

    const actions = document.createElement("span");
    actions.className = "file-actions";

    const download = document.createElement("button");
    download.type = "button";
    download.className = "btn btn-ghost btn-small";
    download.textContent = "Download";
    download.addEventListener("click", () => downloadFile(file, download));

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "btn btn-danger btn-small";
    remove.textContent = "Delete";
    remove.addEventListener("click", () => deleteFile(file, remove));

    actions.append(download, remove);
    item.append(name, meta, actions);
    filesEl.append(item);
  }
}

/* ---------- Data ---------- */

function renderListError() {
  const item = document.createElement("li");
  item.className = "empty";
  item.textContent = "Couldn't load your files. Try Refresh.";
  filesEl.replaceChildren(item);
}

async function refresh() {
  // Listing first lets the server reconcile its quota ledger, so the usage
  // read right after it is current.
  let files;
  try {
    files = await api("/files");
  } catch (err) {
    renderListError();
    throw err;
  }
  renderFiles(files);
  const me = await api("/auth/me");
  renderUsage(me.usedBytes, me.quotaBytes);
}

async function start() {
  try {
    const me = await api("/auth/me");
    showApp(me);
  } catch (err) {
    showAuth();
    if (!(err instanceof ApiError && err.status === 401)) setStatus(err.message, "error");
    return;
  }
  refresh().catch(handleError);
}

/* ---------- Actions ---------- */

async function submitAuth(event) {
  event.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) {
    setStatus("Enter a username and a password.", "error");
    return;
  }

  authSubmit.disabled = true;
  try {
    await postJSON(mode === "signup" ? "/auth/signup" : "/auth/login", { username, password });
    const me = await api("/auth/me");
    showApp(me);
    setStatus(mode === "signup" ? "Account created. Jacked in." : "Signed in.");
  } catch (err) {
    setStatus(err.message, "error");
    return;
  } finally {
    authSubmit.disabled = false;
  }
  refresh().catch(handleError);
}

async function logout() {
  try {
    await postJSON("/auth/logout");
  } catch (_) {
    // Signing out locally is what matters; the cookie is cleared either way.
  }
  filesEl.replaceChildren();
  showAuth();
  setStatus("Signed out.");
}

async function downloadFile(file, button) {
  button.disabled = true;
  setStatus("Signing a link for " + (file.name || file.key) + "…");
  try {
    const signed = await api("/download-url?key=" + encodeURIComponent(file.key));
    // The signed link answers with Content-Disposition: attachment, so the
    // page stays put while the browser saves the file.
    setStatus("Link signed; your browser should start the download.");
    window.location.href = signed.url;
  } catch (err) {
    handleError(err);
  } finally {
    button.disabled = false;
  }
}

async function deleteFile(file, button) {
  if (!confirm("Delete " + (file.name || file.key) + "? This cannot be undone.")) return;
  button.disabled = true;
  try {
    await api("/files?key=" + encodeURIComponent(file.key), { method: "DELETE" });
    setStatus("Deleted " + (file.name || file.key) + ".");
    await refresh();
  } catch (err) {
    handleError(err);
    button.disabled = false;
  }
}

// fetch() cannot report upload progress, so the PUT to the bucket uses XHR.
function putWithProgress(url, file) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", url);
    xhr.setRequestHeader("Content-Type", file.type || "application/octet-stream");
    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) progressBar.style.width = (e.loaded / e.total) * 100 + "%";
    });
    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve();
      else reject(new Error("Upload failed with HTTP " + xhr.status));
    });
    xhr.addEventListener("error", () => {
      reject(new Error("Upload failed: the bucket could not be reached (check its CORS rules)."));
    });
    xhr.send(file);
  });
}

async function upload() {
  const file = fileInput.files[0];
  if (!file) {
    setStatus("Choose a file first.", "error");
    return;
  }
  if (file.size > MAX_BYTES) {
    setStatus("Files must be 50 MB or smaller.", "error");
    return;
  }
  if (quota.total > 0 && quota.used + file.size > quota.total) {
    setStatus("Not enough storage left for this file.", "error");
    return;
  }

  uploadButton.disabled = true;
  try {
    setStatus("Requesting an upload link…");
    const signed = await postJSON("/upload-url", { filename: file.name, size: file.size });

    setStatus("Uploading " + file.name + "…");
    progressBar.style.width = "0%";
    progress.hidden = false;
    await putWithProgress(signed.url, file);

    fileInput.value = "";
    fileName.textContent = "No file selected";
    setStatus("Upload complete.");
    await refresh();
  } catch (err) {
    handleError(err);
  } finally {
    progress.hidden = true;
    uploadButton.disabled = false;
  }
}

/* ---------- Wiring ---------- */

modeLogin.addEventListener("click", () => setMode("login"));
modeSignup.addEventListener("click", () => setMode("signup"));
authForm.addEventListener("submit", submitAuth);
logoutButton.addEventListener("click", logout);
uploadButton.addEventListener("click", upload);
refreshButton.addEventListener("click", () => refresh().catch(handleError));
fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  fileName.textContent = file ? file.name + " · " + formatBytes(file.size) : "No file selected";
});

start();
