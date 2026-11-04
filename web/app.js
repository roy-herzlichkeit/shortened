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
const usernameLabel = $("username-label");
const emailRow = $("email-row");
const emailInput = $("email");
const forgotOpen = $("forgot-open");
const forgotView = $("forgot-view");
const forgotForm = $("forgot-form");
const forgotLogin = $("forgot-login");
const resetForm = $("reset-form");
const resetCode = $("reset-code");
const resetPassword = $("reset-password");
const forgotBack = $("forgot-back");
const verifyView = $("verify-view");
const verifyText = $("verify-text");
const verifyForm = $("verify-form");
const verifyCode = $("verify-code");
const addressForm = $("address-form");
const addressInput = $("address");
const addressSubmit = $("address-submit");
const accountEmail = $("account-email");
const emailChangeForm = $("email-change-form");
const newEmail = $("new-email");
const emailChangePassword = $("email-change-password");
const emailCodeForm = $("email-code-form");
const emailCodeTarget = $("email-code-target");
const emailCode = $("email-code");
const passwordForm = $("password-form");
const currentPassword = $("current-password");
const newPassword = $("new-password");
const signupActions = $("signup-actions");
const signupResend = $("signup-resend");
const signupRestart = $("signup-restart");
const accountDialog = $("account-dialog");
const accountClose = $("account-close");
const accountStatus = $("account-status");

let mode = "login";
// What the code in the verify view confirms: "signup" (a sign-up waiting for
// its code, no account yet) or "account" (the address of a signed-in account).
let verifyMode = "account";
let quota = { used: 0, total: 0 };
let currentFiles = [];
let activeUpload = null; // the XHR of the upload in progress, for Cancel
let activeKey = null; // its reserved key, released if the tab closes mid-upload

// While the Account dialog is open, messages go to its own line, since the
// page's status line is behind the backdrop.
function setStatus(text, kind) {
  const el = accountDialog.open ? accountStatus : statusEl;
  el.textContent = text;
  el.className = "status" + (kind ? " " + kind : "");
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

// Any 401 means the session is gone: drop back to the sign-in form. A 403
// with needsEmail means the account has no confirmed address yet.
function handleError(err) {
  if (err instanceof ApiError && err.status === 401) {
    closeAccount();
    showAuth();
    setStatus(err.message, "error");
    return;
  }
  if (err instanceof ApiError && err.status === 403 && err.body && err.body.needsEmail) {
    api("/auth/me").then(showVerify, () => showAuth());
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

// Only one of the four views is shown at a time.
function showView(view) {
  for (const v of [authView, forgotView, verifyView, appView]) v.hidden = v !== view;
}

function showAuth() {
  showView(authView);
  account.hidden = true;
  passwordInput.value = "";
  usernameInput.focus();
}

// showSignupVerify asks for the code of a sign-up; the account is created
// when it is right.
function showSignupVerify(pending) {
  verifyMode = "signup";
  showView(verifyView);
  account.hidden = true;
  verifyCode.value = "";
  verifyText.textContent = "We sent a 6-digit code to " + pending.pendingEmail + ". Enter it to create the account " +
    pending.username + ". No mail? Check spam, or send a new code.";
  verifyForm.hidden = false;
  addressForm.hidden = true;
  signupActions.hidden = false;
  verifyCode.focus();
}

// The pending sign-up is gone (expired, or its name was taken meanwhile):
// back to the sign-up form, keeping what was typed.
function backToSignup(message) {
  setMode("signup");
  showAuth();
  if (message) setStatus(message, "error");
}

function showForgot() {
  showView(forgotView);
  account.hidden = true;
  forgotForm.hidden = false;
  resetForm.hidden = true;
  forgotLogin.value = usernameInput.value.trim();
  forgotLogin.focus();
}

// showVerify asks an account without a confirmed address for its code, or,
// if no address is waiting (an account from before email), for an address.
function showVerify(me) {
  verifyMode = "account";
  showView(verifyView);
  account.hidden = false;
  whoami.disabled = true; // no settings until the address is confirmed
  whoami.textContent = me.username;
  verifyCode.value = "";
  addressForm.hidden = false;
  signupActions.hidden = true;
  if (me.pendingEmail) {
    verifyText.textContent = "We sent a 6-digit code to " + me.pendingEmail +
      ". Enter it to start using your account. No mail? Check spam, or send a new code below.";
    verifyForm.hidden = false;
    addressInput.value = me.pendingEmail;
    addressSubmit.textContent = "Send a new code";
    verifyCode.focus();
  } else {
    verifyText.textContent = "Your account needs an email address before you can use it. " +
      "It confirms it's you and lets you reset your password.";
    verifyForm.hidden = true;
    addressInput.value = "";
    addressSubmit.textContent = "Send code";
    addressInput.focus();
  }
}

function showApp(me) {
  showView(appView);
  account.hidden = false;
  whoami.disabled = false; // the name opens the Account pop-up
  whoami.textContent = me.username;
  renderUsage(me);
  renderAccount(me);
}

async function openAccount() {
  accountStatus.textContent = "";
  accountStatus.className = "status";
  accountDialog.showModal();
  try {
    renderAccount(await api("/auth/me"));
  } catch (err) {
    handleError(err);
  }
}

function closeAccount() {
  if (accountDialog.open) accountDialog.close();
}

function renderAccount(me) {
  accountEmail.textContent = me.email;
  emailCodeForm.hidden = !me.pendingEmail;
  emailCodeTarget.textContent = me.pendingEmail || "";
}

function setMode(next) {
  mode = next;
  const signup = mode === "signup";
  modeLogin.setAttribute("aria-pressed", String(!signup));
  modeSignup.setAttribute("aria-pressed", String(signup));
  authSubmit.textContent = signup ? "Create account" : "Sign in";
  passwordInput.autocomplete = signup ? "new-password" : "current-password";
  usernameLabel.textContent = signup ? "Username" : "Username or email";
  emailRow.hidden = !signup;
  forgotOpen.hidden = signup;
  authHint.textContent = signup
    ? "3-32 characters for the username (letters, digits, _ or -). Password 8-72 characters. We mail a code to the address."
    : "Welcome back, choom.";
}

// renderUsage draws the meter from a usage answer ({usedBytes, storedBytes,
// reservedBytes, quotaBytes}). The bar and the figure are what the bucket
// holds; space held for an upload still in flight is shown apart, since the
// quota counts it but B2 doesn't have it yet.
function renderUsage(u) {
  const total = u.quotaBytes;
  const stored = u.storedBytes != null ? u.storedBytes : u.usedBytes;
  const reserved = u.reservedBytes || 0;
  quota = { used: stored + reserved, total: total };
  const pct = total > 0 ? Math.min(100, (stored / total) * 100) : 0;
  usageText.textContent = formatSize(stored) + " of " + formatSize(total) +
    (reserved > 0 ? " · " + formatSize(reserved) + " uploading" : "");
  usageBar.style.width = pct + "%";
  usage.classList.toggle("is-full", total > 0 && (stored + reserved) / total >= 0.9);
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
  renderUsage(me);
}

// After an error the ledger may have changed (a reservation released, a
// missing file dropped), so redraw what the server now says. A failure here
// must not hide the first error.
function refreshQuietly() {
  refresh().catch(() => {});
}

async function start() {
  let me;
  try {
    me = await api("/auth/me");
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      // Not signed in; maybe a sign-up is waiting for its code (after a reload).
      try {
        showSignupVerify(await api("/auth/signup/pending"));
      } catch (_) {
        showAuth();
      }
      return;
    }
    showAuth();
    setStatus(err.message, "error");
    return;
  }
  if (!me.verified) {
    showVerify(me);
    return;
  }
  showApp(me);
  refresh().catch(handleError);
}

/* ---------- Actions ---------- */

async function submitAuth(event) {
  event.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  const email = emailInput.value.trim();
  if (!username || !password || (mode === "signup" && !email)) {
    setStatus(mode === "signup" ? "Enter a username, an email address and a password." :
      "Enter your username or email, and your password.", "error");
    return;
  }

  authSubmit.disabled = true;
  try {
    if (mode === "signup") {
      // No account yet: it is created when the mailed code is entered.
      const pending = await postJSON("/auth/signup", { username, password, email });
      passwordInput.value = "";
      showSignupVerify(pending);
      setStatus("Code sent to " + pending.pendingEmail + ".");
      return;
    }
    await postJSON("/auth/login", { username, password });
    setStatus("Signed in.");
  } catch (err) {
    setStatus(err.message, "error");
    return;
  } finally {
    authSubmit.disabled = false;
  }
  await start();
}

// withButton disables a form's submit button while fn runs.
async function withButton(form, fn) {
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    await fn();
  } catch (err) {
    handleError(err);
  } finally {
    button.disabled = false;
  }
}

function submitVerify(event) {
  event.preventDefault();
  withButton(verifyForm, async () => {
    const code = verifyCode.value.trim();
    if (verifyMode === "signup") {
      try {
        await postJSON("/auth/signup/verify", { code });
      } catch (err) {
        if (err instanceof ApiError && (err.status === 410 || err.status === 409)) {
          backToSignup(err.message);
          return;
        }
        throw err;
      }
      setStatus("Account created. Jacked in.");
    } else {
      await postJSON("/auth/email/verify", { code });
      setStatus("Email confirmed. Jacked in.");
    }
    await start();
  });
}

async function resendSignupCode() {
  signupResend.disabled = true;
  try {
    const res = await postJSON("/auth/signup/resend");
    setStatus("New code sent to " + res.pendingEmail + ".");
    verifyCode.focus();
  } catch (err) {
    if (err instanceof ApiError && err.status === 410) backToSignup(err.message);
    else setStatus(err.message, "error");
  } finally {
    signupResend.disabled = false;
  }
}

function submitAddress(event) {
  event.preventDefault();
  withButton(addressForm, async () => {
    const res = await postJSON("/auth/email", { email: addressInput.value.trim() });
    showVerify(await api("/auth/me"));
    setStatus("Code sent to " + res.pendingEmail + ".");
  });
}

function submitForgot(event) {
  event.preventDefault();
  withButton(forgotForm, async () => {
    const res = await postJSON("/auth/forgot", { login: forgotLogin.value.trim() });
    setStatus(res.message);
    resetForm.hidden = false;
    resetCode.focus();
  });
}

function submitReset(event) {
  event.preventDefault();
  withButton(resetForm, async () => {
    await postJSON("/auth/reset", {
      login: forgotLogin.value.trim(),
      code: resetCode.value.trim(),
      password: resetPassword.value
    });
    resetCode.value = "";
    resetPassword.value = "";
    setStatus("Password changed. Every other session is signed out.");
    await start();
  });
}

function submitEmailChange(event) {
  event.preventDefault();
  withButton(emailChangeForm, async () => {
    const res = await postJSON("/auth/email", {
      email: newEmail.value.trim(),
      password: emailChangePassword.value
    });
    emailChangePassword.value = "";
    emailCodeTarget.textContent = res.pendingEmail;
    emailCodeForm.hidden = false;
    emailCode.focus();
    setStatus("Code sent to " + res.pendingEmail + ". Your address changes once you enter it.");
  });
}

function submitEmailCode(event) {
  event.preventDefault();
  withButton(emailCodeForm, async () => {
    const res = await postJSON("/auth/email/verify", { code: emailCode.value.trim() });
    emailCode.value = "";
    newEmail.value = "";
    renderAccount(await api("/auth/me"));
    setStatus("Your email is now " + res.email + ".");
  });
}

function submitPassword(event) {
  event.preventDefault();
  withButton(passwordForm, async () => {
    await postJSON("/auth/password", { current: currentPassword.value, password: newPassword.value });
    currentPassword.value = "";
    newPassword.value = "";
    setStatus("Password changed. Every other session is signed out.");
  });
}

async function logout() {
  try {
    await postJSON("/auth/logout");
  } catch (_) {
    // Signing out locally is what matters; the cookie is cleared either way.
  }
  filesEl.replaceChildren();
  closeAccount();
  setMode("login");
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
    activeKey = signed.key;
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
    renderUsage(usage);

    fileInput.value = "";
    fileName.textContent = "No file selected";
    setStatus("Upload complete: " + signed.name + (signed.name !== checked.name ? " (kept both)" : "") + ".");
    await refresh();
  } catch (err) {
    if (err instanceof UploadCancelled) setStatus(err.message);
    else handleError(err);
    refreshQuietly();
  } finally {
    activeKey = null;
    progress.hidden = true;
    uploadButton.disabled = false;
  }
}

async function releaseUpload(key) {
  try {
    const usage = await api("/files/release?key=" + encodeURIComponent(key), { method: "POST" });
    renderUsage(usage);
  } catch (_) {
    // The reservation still lapses on its own; the refresh after the error
    // shows whatever the server has.
  }
}

/* ---------- Wiring ---------- */

modeLogin.addEventListener("click", () => setMode("login"));
modeSignup.addEventListener("click", () => setMode("signup"));
authForm.addEventListener("submit", submitAuth);
forgotOpen.addEventListener("click", showForgot);
forgotBack.addEventListener("click", () => {
  showAuth();
  setStatus("");
});
forgotForm.addEventListener("submit", submitForgot);
resetForm.addEventListener("submit", submitReset);
verifyForm.addEventListener("submit", submitVerify);
addressForm.addEventListener("submit", submitAddress);
emailChangeForm.addEventListener("submit", submitEmailChange);
emailCodeForm.addEventListener("submit", submitEmailCode);
passwordForm.addEventListener("submit", submitPassword);
logoutButton.addEventListener("click", logout);
signupResend.addEventListener("click", resendSignupCode);
signupRestart.addEventListener("click", () => {
  backToSignup();
  setStatus("");
});
whoami.addEventListener("click", openAccount);
accountClose.addEventListener("click", closeAccount);
// A click on the backdrop (outside the panel) closes it too.
accountDialog.addEventListener("click", (event) => {
  if (event.target === accountDialog) closeAccount();
});
uploadButton.addEventListener("click", upload);
cancelButton.addEventListener("click", () => {
  if (activeUpload) activeUpload.abort();
});
refreshButton.addEventListener("click", () => refresh().catch(handleError));
fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  fileName.textContent = file ? file.name + " · " + formatSize(file.size) : "No file selected";
});

// Closing or leaving the tab mid-upload: hand the reservation back so it
// doesn't count for its whole window. sendBeacon outlives the page; if the
// bytes did land, the server keeps the file anyway.
window.addEventListener("pagehide", () => {
  if (activeKey) navigator.sendBeacon("/files/release?key=" + encodeURIComponent(activeKey));
});

start();
