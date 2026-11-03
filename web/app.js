"use strict";

// The page is served by the API itself, so every call is same-origin and the
// HttpOnly session cookie rides along automatically.

const MAX_BYTES = 50 * 1024 * 1024;
const MAX_NAME = 120;

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
const cancelButton = $("cancel-upload");
const conflictDialog = $("conflict");
const conflictText = $("conflict-text");
const refreshButton = $("refresh");
const filesEl = $("files");
const statusEl = $("status");

let mode = "login";
let quota = { used: 0, total: 0 };
let currentFiles = [];
let activeUpload = null; // the XHR of the upload in progress, for Cancel

function setStatus(text, kind) {
  statusEl.textContent = text;
  statusEl.className = "status" + (kind ? " " + kind : "");
}

class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.status = status;
    this.body = body || null;
  }
}

async function api(path, options) {
  let res;
  try {
    res = await fetch(path, options || {});
  } catch (_) {
    throw new ApiError("Couldn't reach the server. Check your connection and try again.", 0);
  }
  let body = null;
  if (res.status !== 204) {
    try {
      body = await res.json();
    } catch (_) {
      // A non-JSON body is reported through the status code below.
    }
  }
  if (!res.ok) {
    throw new ApiError((body && body.error) || "Request failed with HTTP " + res.status, res.status, body);
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

// "12.3 MB": one decimal, dropped when it is zero ("500 MB").
function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return value.toFixed(1).replace(/\.0$/, "") + " " + units[unit];
}

// The same rules as the server: spaces become "-", then only A-Z a-z 0-9 . _ -
// are allowed. Returns { name } or { error }.
function checkFilename(raw) {
  const name = raw.replace(/ /g, "-");
  if (!name) return { error: "The file needs a name." };
  const bad = [...new Set(name.replace(/[A-Za-z0-9._-]/g, ""))];
  if (bad.length > 0) {
    return {
      error: "File names may use only letters, digits, dot, underscore and dash. Rename the file to remove " +
        bad.map((c) => "\u201c" + c + "\u201d").join(" ") + "."
    };
  }
  if (new TextEncoder().encode(name).length > MAX_NAME) {
    return { error: "File name is longer than " + MAX_NAME + " characters. Rename the file first." };
  }
  if (!/[A-Za-z0-9]/.test(name)) return { error: "File name needs at least one letter or digit." };
  return { name: name };
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
  usageText.textContent = formatSize(used) + " of " + formatSize(total);
  usageBar.style.width = pct + "%";
  usage.classList.toggle("is-full", pct >= 90);
}

function renderFiles(files) {
  currentFiles = files || [];
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
    meta.textContent = formatSize(file.size) + (when ? " · " + when : "");

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
  await refreshUsage();
}

async function refreshUsage() {
  const me = await api("/auth/me");
  renderUsage(me.usedBytes, me.quotaBytes);
}

// After an error the ledger may have changed (a reservation released, a
// missing file dropped), so redraw what the server now says. A failure here
// must not hide the first error.
function refreshQuietly() {
  refresh().catch(() => {});
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
    if (err instanceof ApiError && err.status === 404) {
      // The server has dropped the file from the ledger; show the list
      // without it, and keep the message.
      setStatus((file.name || file.key) + ": " + err.message + ".", "error");
      refreshQuietly();
    } else if (err instanceof ApiError && err.status === 401) {
      handleError(err);
    } else {
      setStatus("Couldn't download " + (file.name || file.key) + ": " + err.message, "error");
    }
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
    refreshQuietly();
  }
}

// fetch() cannot report upload progress, so the PUT to the bucket uses XHR.
class UploadCancelled extends Error {}

function putWithProgress(url, file) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    activeUpload = xhr;
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
    xhr.addEventListener("abort", () => reject(new UploadCancelled("Upload cancelled.")));
    xhr.addEventListener("loadend", () => {
      if (activeUpload === xhr) activeUpload = null;
    });
    xhr.send(file);
  });
}

// askConflict shows the same-name dialog and resolves to "replace",
// "keepboth" or "cancel".
function askConflict(name, suggestion) {
  return new Promise((resolve) => {
    conflictText.textContent = "You already have a file named " + name +
      ". Replace it, keep both (the new one is stored as " + suggestion + "), or cancel?";
    conflictDialog.returnValue = "cancel";
    conflictDialog.addEventListener("close", () => resolve(conflictDialog.returnValue || "cancel"), { once: true });
    conflictDialog.showModal();
  });
}

// requestUpload asks for a signed PUT link, and on a name clash asks the user
// what to do and tries again with that choice. Resolves to null on Cancel.
async function requestUpload(name, size) {
  try {
    return await postJSON("/upload-url", { filename: name, size: size });
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 409 && err.body && err.body.conflict)) throw err;
    const choice = await askConflict(err.body.name, err.body.suggestion);
    if (choice === "cancel") return null;
    return postJSON("/upload-url", { filename: name, size: size, onConflict: choice });
  }
}

async function upload() {
  const file = fileInput.files[0];
  if (!file) {
    setStatus("Choose a file first.", "error");
    return;
  }
  const checked = checkFilename(file.name);
  if (checked.error) {
    setStatus(checked.error, "error");
    return;
  }
  if (file.size > MAX_BYTES) {
    setStatus("Files must be 50 MB or smaller.", "error");
    return;
  }
  // A replace frees the old file's space, so only the server can judge that.
  const sameName = currentFiles.some((f) => f.name === checked.name);
  if (!sameName && quota.total > 0 && quota.used + file.size > quota.total) {
    setStatus("Not enough storage left for this file: " + formatSize(quota.used) + " of " +
      formatSize(quota.total) + " used.", "error");
    return;
  }

  uploadButton.disabled = true;
  let signed = null;
  try {
    setStatus("Requesting an upload link…");
    signed = await requestUpload(checked.name, file.size);
    if (!signed) {
      setStatus("Upload cancelled.");
      return;
    }

    setStatus("Uploading " + signed.name + "…");
    progressBar.style.width = "0%";
    progress.hidden = false;
    try {
      await putWithProgress(signed.url, file);
    } catch (err) {
      // The PUT failed or was cancelled: give the reservation back now. The
      // server keeps the file if the bytes did land after all.
      await releaseUpload(signed.key);
      throw err;
    }

    setStatus("Checking the upload…");
    const usage = await api("/files/confirm?key=" + encodeURIComponent(signed.key), { method: "POST" });
    renderUsage(usage.usedBytes, usage.quotaBytes);

    fileInput.value = "";
    fileName.textContent = "No file selected";
    setStatus("Upload complete: " + signed.name + (signed.name !== checked.name ? " (kept both)" : "") + ".");
    await refresh();
  } catch (err) {
    if (err instanceof UploadCancelled) setStatus(err.message);
    else handleError(err);
    refreshQuietly();
  } finally {
    progress.hidden = true;
    uploadButton.disabled = false;
  }
}

async function releaseUpload(key) {
  try {
    const usage = await api("/files/release?key=" + encodeURIComponent(key), { method: "POST" });
    renderUsage(usage.usedBytes, usage.quotaBytes);
  } catch (_) {
    // The reservation still lapses on its own; the refresh after the error
    // shows whatever the server has.
  }
}

/* ---------- Wiring ---------- */

modeLogin.addEventListener("click", () => setMode("login"));
modeSignup.addEventListener("click", () => setMode("signup"));
authForm.addEventListener("submit", submitAuth);
logoutButton.addEventListener("click", logout);
uploadButton.addEventListener("click", upload);
cancelButton.addEventListener("click", () => {
  if (activeUpload) activeUpload.abort();
});
refreshButton.addEventListener("click", () => refresh().catch(handleError));
fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  fileName.textContent = file ? file.name + " · " + formatSize(file.size) : "No file selected";
});

start();
