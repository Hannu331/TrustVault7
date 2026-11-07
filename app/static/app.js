"use strict";
/* TrustVault frontend: plain JavaScript, no framework.
   All text goes in through the DOM API (never innerHTML), so a file name can never run as code.
   The browser only displays things; the server decides who may see what. */

const state = {
  token: sessionStorage.getItem("tv_token"),
  me: null,
  page: null,
  filters: {},
};

/* ------------------------------------------------------------------ helpers */

// h("div", {class: "x"}, "text", childElement) builds a DOM element.
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (value === true) el.setAttribute(key, "");
    else if (value !== false && value != null) el.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    el.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return el;
}

const $ = (selector) => document.querySelector(selector);
const when = (timestamp) => timestamp.slice(0, 16).replace("T", " ");
// Plain-language names for what happened (the brackets say which kind of right was used).
const ACTION_LABELS = {
  upload: "uploaded", download: "read (downloaded)", update_metadata: "edited details (edit)",
  content_replaced: "edited content (edit)", delete: "deleted", grant_set: "gave access (grant)",
  grant_revoked: "removed access (revoke)", read_refused: "tried to read: refused",
  edit_refused: "tried to edit: refused", share_refused: "tried to share: refused",
  delete_refused: "tried to delete: refused", audit_refused: "tried to see activity: refused",
  search: "searched", login: "signed in", login_failed: "failed sign-in", logout: "signed out",
};
const words = (action) => ACTION_LABELS[action] || action.replace(/_/g, " ");

function toast(text, good = false) {
  const box = $("#toast");
  box.textContent = text;
  box.className = "show " + (good ? "good" : "bad");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (box.className = ""), 4500);
}

async function api(path, options = {}) {
  const init = { method: "GET", headers: {}, ...options };
  if (state.token) init.headers.Authorization = "Bearer " + state.token;
  if (init.json) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.json);
  }
  const res = await fetch("/api" + path, init);
  if (res.status === 401 && path !== "/auth/login") {
    signOutLocally();
    throw new Error("Your session ended. Please sign in again.");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = Array.isArray(body.detail) ? body.detail[0].msg : body.detail;
    throw new Error(detail || "That request was rejected.");
  }
  return res;
}
const getJson = async (path, options) => (await api(path, options)).json();

// Wrap click/submit handlers so a failure shows as a message instead of a silent error.
const safe = (fn) => async (event) => {
  try {
    await fn(event);
  } catch (err) {
    toast(err.message);
  }
};

function table(headers, rows) {
  return h(
    "table",
    {},
    h("thead", {}, h("tr", {}, headers.map((text) => h("th", {}, text)))),
    h("tbody", {}, rows),
  );
}
const pill = (access) =>
  h("span", { class: "pill " + access }, { owner: "Owner", edit: "Can edit", read: "Can read" }[access]);
const pageHead = (title, sub) => h("div", { class: "page-head" }, h("h1", {}, title), h("p", { class: "sub" }, sub));

/* ------------------------------------------------------------------ sign in / out */

const DEMO_USERS = ["admin", "alice", "bob", "vera"];

async function showLogin() {
  const config = await fetch("/api/config").then((r) => r.json()).catch(() => ({ demo: false }));
  const username = h("input", { name: "u", required: true, autocomplete: "username" });
  const password = h("input", { name: "p", type: "password", required: true, autocomplete: "current-password" });
  const form = h(
    "form",
    { onsubmit: safe(signIn) },
    h("label", {}, "Username", username),
    h("label", {}, "Password", password),
    h("button", { class: "btn" }, "Sign in"),
  );
  const demo = !config.demo ? null : h(
    "div",
    { class: "demo" },
    "Demo accounts:",
    DEMO_USERS.map((name) =>
      h("button", { type: "button", class: "btn ghost", onclick: () => { username.value = name; password.value = name + "-Demo-2026!"; } }, name),
    ),
  );
  $("#app").replaceChildren(
    h(
      "div",
      { class: "login" },
      h(
        "div",
        { class: "login-art" },
        h("div", { class: "brand" }, h("img", { src: "mark.svg", alt: "" }), "TrustVault"),
        h("h1", {}, "The right people read it. Every attempt is on record."),
        h("p", {}, "Share confidential documents with named people, take access back instantly, and prove who opened what."),
      ),
      h("div", { class: "login-form" }, h("h2", {}, "Sign in"), form, demo),
    ),
  );
}

async function signIn(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const result = await getJson("/auth/login", { method: "POST", json: { username: form.get("u"), password: form.get("p") } });
  state.token = result.token;
  sessionStorage.setItem("tv_token", result.token);
  start();
}

async function signOut() {
  await api("/auth/logout", { method: "POST" });
  signOutLocally();
}

function signOutLocally() {
  state.token = null;
  state.me = null;
  state.page = null;
  sessionStorage.removeItem("tv_token");
  $("#drawer-root").replaceChildren();
  showLogin();
}

async function start() {
  if (!state.token) return showLogin();
  try {
    state.me = await getJson("/auth/me");
  } catch {
    return;
  }
  showShell();
}

/* ------------------------------------------------------------------ shell and navigation */

const NAV = {
  owner: [["mine", "My documents"], ["shared", "Shared with me"], ["upload", "Upload"], ["account", "Account"]],
  viewer: [["shared", "Shared with me"], ["account", "Account"]],
  admin: [["overview", "Overview"], ["mine", "My documents"], ["upload", "Upload"], ["access", "Access list"], ["people", "People"], ["audit", "Audit trail"], ["account", "Account"]],
};

function showShell() {
  // A temporary password must be replaced before anything else is shown.
  const items = state.me.must_change_password ? [["account", "Change password"]] : NAV[state.me.role];
  if (!items.some(([id]) => id === state.page)) state.page = items[0][0];
  const navButtons = items.map(([id, label]) =>
    h("button", { class: id === state.page ? "active" : "", onclick: () => { state.page = id; showShell(); } }, label),
  );
  $("#app").replaceChildren(
    h(
      "aside",
      { class: "rail" },
      h("div", { class: "brand" }, h("img", { src: "mark.svg", alt: "" }), "TrustVault"),
      h("nav", {}, navButtons),
      h("div", { class: "who" }, h("strong", {}, state.me.username), h("span", {}, state.me.role), h("button", { class: "link", onclick: safe(signOut) }, "Sign out")),
    ),
    h("main", { id: "main" }),
  );
  showPage();
}

async function showPage() {
  const main = $("#main");
  const page = state.page;
  try {
    if (page === "mine" || page === "shared") await documentsPage(main, page);
    else if (page === "upload") uploadPage(main);
    else if (page === "account") accountPage(main);
    else if (page === "overview") await overviewPage(main);
    else if (page === "people") await peoplePage(main);
    else if (page === "audit") await auditPage(main);
    else if (page === "access") await accessPage(main);
  } catch (err) {
    toast(err.message);
  }
}

/* ------------------------------------------------------------------ documents list */

async function documentsPage(main, kind) {
  const query = new URLSearchParams(Object.entries(state.filters).filter(([, value]) => value));
  const all = await getJson("/documents?" + query);
  const docs = all.filter((doc) => (kind === "mine") === (doc.access === "owner"));

  const field = (name, label, type = "text") =>
    h("input", { name, type, placeholder: label, title: label, "aria-label": label, value: state.filters[name] || "" });
  const search = h(
    "form",
    {
      class: "row filters",
      onsubmit: safe((event) => {
        event.preventDefault();
        state.filters = Object.fromEntries(new FormData(event.target));
        return showPage();
      }),
    },
    field("q", "Name contains"),
    field("owner", "Owner"),
    field("category", "Category"),
    field("date_from", "Uploaded from", "date"),
    field("date_to", "Uploaded to", "date"),
    h("button", { class: "btn" }, "Search"),
    h("button", { type: "button", class: "btn ghost", onclick: () => { state.filters = {}; showPage(); } }, "Clear"),
  );

  const rows = docs.map((doc) =>
    h(
      "tr",
      {},
      h("td", {}, h("button", { class: "link", onclick: safe(async () => {
          try {
            await openDrawer(doc.id);
          } catch (err) {
            showPage(); // access may have been removed: refresh the list so the stale row disappears
            throw err;
          }
        }) }, doc.name)),
      h("td", {}, doc.owner),
      h("td", {}, doc.category),
      h("td", {}, pill(doc.access)),
      h("td", {}, when(doc.updated_at)),
    ),
  );
  const empty =
    kind === "mine"
      ? "No documents match. Upload one from the Upload page."
      : "Nothing has been shared with you yet. Documents appear here when an owner grants you access.";

  main.replaceChildren(
    pageHead(kind === "mine" ? "My documents" : "Shared with me", kind === "mine" ? "Documents you own and control." : "Documents others have given you access to."),
    search,
    h("div", { class: "card" }, docs.length ? table(["Name", "Owner", "Category", "Your access", "Updated"], rows) : h("p", { class: "empty" }, empty)),
  );
}

/* ------------------------------------------------------------------ upload */

function uploadPage(main) {
  const form = h(
    "form",
    {
      class: "row",
      onsubmit: safe(async (event) => {
        event.preventDefault();
        await api("/documents", { method: "POST", body: new FormData(event.target) });
        toast("Document uploaded", true);
        state.page = "mine";
        showShell();
      }),
    },
    h("input", { type: "file", name: "file", required: true, "aria-label": "File" }),
    h("input", { name: "category", value: "general", "aria-label": "Category", title: "Category" }),
    h("button", { class: "btn" }, "Upload"),
  );
  main.replaceChildren(
    pageHead("Upload", "New documents are private to you until you share them."),
    h("div", { class: "card" }, form, h("p", { class: "sub" }, "Allowed: PDF, PNG, JPG, DOCX, XLSX, TXT, CSV. Up to 10 MB. The file's contents are checked, not just its extension.")),
  );
}

/* ------------------------------------------------------------------ document drawer */

async function openDrawer(id) {
  const doc = await getJson("/documents/" + id);
  const isOwner = doc.access === "owner";
  const canEdit = isOwner || doc.access === "edit";
  const refresh = () => { openDrawer(id); showPage(); };
  const close = () => $("#drawer-root").replaceChildren();

  const sections = [actionsSection(doc, canEdit, isOwner, close)];
  if (canEdit) sections.push(editSection(doc, refresh));
  if (isOwner) {
    sections.push(await sharingSection(doc, refresh));
    sections.push(await activitySection(doc));
  }

  $("#drawer-root").replaceChildren(
    h("div", { class: "scrim", onclick: close }),
    h(
      "aside",
      { class: "drawer", role: "dialog", "aria-label": doc.name },
      h(
        "div",
        { class: "drawer-head" },
        h("div", {}, h("h2", {}, doc.name), h("p", { class: "sub" }, `${doc.owner} · ${doc.category} · version ${doc.version} · ${doc.size} bytes`)),
        h("button", { class: "btn ghost", onclick: close, "aria-label": "Close" }, "Close"),
      ),
      pill(doc.access),
      sections,
    ),
  );
}
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") $("#drawer-root").replaceChildren();
});

async function downloadDocument(doc) {
  const res = await api(`/documents/${doc.id}/download`);
  const url = URL.createObjectURL(await res.blob());
  const link = h("a", { href: url, download: doc.name });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function actionsSection(doc, canEdit, isOwner, close) {
  const buttons = [h("button", { class: "btn", onclick: safe(() => downloadDocument(doc)) }, "Download")];
  if (isOwner) {
    buttons.push(
      h(
        "button",
        {
          class: "btn danger",
          onclick: safe(async () => {
            if (!confirm("Delete this document? Everyone loses access.")) return;
            await api("/documents/" + doc.id, { method: "DELETE" });
            close();
            showPage();
          }),
        },
        "Delete",
      ),
    );
  }
  return h("section", { class: "row" }, buttons);
}

function editSection(doc, refresh) {
  const rename = h(
    "form",
    {
      class: "row",
      onsubmit: safe(async (event) => {
        event.preventDefault();
        const form = new FormData(event.target);
        await api("/documents/" + doc.id, { method: "PUT", json: { name: form.get("name"), category: form.get("category") } });
        toast("Details saved", true);
        refresh();
      }),
    },
    h("input", { name: "name", value: doc.name, "aria-label": "Name" }),
    h("input", { name: "category", value: doc.category, "aria-label": "Category" }),
    h("button", { class: "btn ghost" }, "Save details"),
  );
  const fileInput = h("input", { type: "file", "aria-label": "Replacement file" });
  const replace = h(
    "button",
    {
      class: "btn ghost",
      onclick: safe(async () => {
        if (!fileInput.files[0]) throw new Error("Choose a file first.");
        const body = new FormData();
        body.append("file", fileInput.files[0]);
        await api(`/documents/${doc.id}/content`, { method: "PUT", body });
        toast("Content replaced", true);
        refresh();
      }),
    },
    "Replace file",
  );
  return h("section", {}, h("h3", {}, "Edit"), rename, h("div", { class: "row" }, fileInput, replace));
}

async function sharingSection(doc, refresh) {
  const people = await getJson("/users/directory");
  const list = doc.grants.length
    ? table(
        ["Person", "Access", ""],
        doc.grants.map((grant) =>
          h(
            "tr",
            {},
            h("td", {}, grant.username),
            h("td", {}, pill(grant.permission)),
            h(
              "td",
              {},
              h(
                "button",
                {
                  class: "btn danger",
                  onclick: safe(async () => {
                    await api(`/documents/${doc.id}/grants/${grant.user_id}`, { method: "DELETE" });
                    toast("Access removed. It stops working immediately.", true);
                    refresh();
                  }),
                },
                "Remove",
              ),
            ),
          ),
        ),
      )
    : h("p", { class: "empty" }, "Only you can open this document.");

  const grantForm = h(
    "form",
    {
      class: "row",
      onsubmit: safe(async (event) => {
        event.preventDefault();
        const form = new FormData(event.target);
        await api(`/documents/${doc.id}/grants/${form.get("user")}`, { method: "PUT", json: { permission: form.get("permission") } });
        toast("Access granted", true);
        refresh();
      }),
    },
    h("select", { name: "user", "aria-label": "Person" }, people.map((p) => h("option", { value: p.id }, `${p.username} (${p.role})`))),
    h("select", { name: "permission", "aria-label": "Permission" }, h("option", { value: "read" }, "Can read"), h("option", { value: "edit" }, "Can edit")),
    h("button", { class: "btn" }, "Give access"),
  );
  return h("section", {}, h("h3", {}, "Who can open this"), list, grantForm);
}

async function activitySection(doc) {
  const events = await getJson(`/documents/${doc.id}/audit`);
  const items = events.map((e) =>
    h("li", { class: e.outcome }, `${e.actor_name || "Someone"}: ${words(e.action)}`, h("time", {}, when(e.ts) + (e.outcome === "ok" ? "" : " · " + e.outcome))),
  );
  return h("section", {}, h("h3", {}, "Who touched it, and when"), h("ul", { class: "timeline" }, items));
}

/* ------------------------------------------------------------------ account */

function accountPage(main) {
  const forced = state.me.must_change_password;
  const form = h(
    "form",
    {
      class: "row",
      onsubmit: safe(async (event) => {
        event.preventDefault();
        const f = new FormData(event.target);
        if (f.get("new") !== f.get("again")) throw new Error("The two new passwords do not match.");
        await api("/auth/password", { method: "POST", json: { current: f.get("current"), new: f.get("new") } });
        signOutLocally();
        toast("Password changed. Sign in with your new password.", true);
      }),
    },
    h("input", { name: "current", type: "password", placeholder: "Current password", required: true, autocomplete: "current-password" }),
    h("input", { name: "new", type: "password", placeholder: "New password (10+ characters)", minlength: 10, required: true, autocomplete: "new-password" }),
    h("input", { name: "again", type: "password", placeholder: "New password again", minlength: 10, required: true, autocomplete: "new-password" }),
    h("button", { class: "btn" }, "Change password"),
  );
  main.replaceChildren(
    pageHead(forced ? "Choose your own password" : "Account", forced ? "You were given a temporary password. Replace it to continue." : "Changing your password signs you out everywhere."),
    h("div", { class: "card" }, form),
  );
}

/* ------------------------------------------------------------------ administrator pages */

function integrityBanner(result) {
  return result.valid
    ? h(
        "div",
        { class: "banner good" },
        "Audit chain verified: no record has been changed in the middle of the log.",
        h("div", { class: "mono" }, `Latest record #${result.head_seq}: ${result.head}`),
        h("div", { class: "sub" }, "Save this fingerprint outside the system. Checking it later also catches deleted newest records."),
      )
    : h("div", { class: "banner bad" }, `Audit chain broken at record ${result.first_bad_seq}. Treat the log as tampered with.`);
}

async function overviewPage(main) {
  const [activity, verify] = await Promise.all([getJson("/admin/activity"), getJson("/admin/audit/verify")]);
  const count = (test) => activity.by_action_24h.filter(test).reduce((sum, row) => sum + row.n, 0);
  const refused = count((r) => r.outcome === "denied");
  const stats = h(
    "div",
    { class: "stats" },
    h("div", { class: "stat" }, h("b", {}, count(() => true)), "events, last 24h"),
    h("div", { class: "stat" }, h("b", {}, count((r) => r.action === "download")), "downloads"),
    h("div", { class: "stat" }, h("b", {}, count((r) => r.action.startsWith("grant"))), "permission changes"),
    h("div", { class: refused ? "stat alert" : "stat" }, h("b", {}, refused), "refused attempts"),
  );
  const notable = activity.notable.length
    ? table(["Who", "Refused attempts"], activity.notable.map((n) => h("tr", {}, h("td", {}, n.actor), h("td", {}, n.refused))))
    : h("p", { class: "empty" }, "Nobody has been refused three or more times in the last day.");
  const changes = table(
    ["When", "By", "Action", "Document", "Detail"],
    activity.permission_changes.map((c) =>
      h("tr", {}, h("td", {}, when(c.ts)), h("td", {}, c.actor_name), h("td", {}, words(c.action)), h("td", {}, c.doc_id ?? ""), h("td", { class: "mono" }, c.detail)),
    ),
  );
  main.replaceChildren(
    pageHead("Overview", "What happened on the platform, and what deserves a look."),
    integrityBanner(verify),
    stats,
    h("div", { class: "card" }, h("h2", {}, "Worth noticing"), notable),
    h("div", { class: "card" }, h("h2", {}, "Permission and account changes"), changes),
  );
}

// Builds the JSON for POST /admin/users from the form (the checkbox is a boolean, not a form field).
function newUserPayload(form) {
  const f = new FormData(form);
  return { username: f.get("username"), password: f.get("password"), role: f.get("role"), require_password_change: form.elements.require.checked };
}

async function peoplePage(main) {
  const users = await getJson("/admin/users");
  const rows = users.map((u) =>
    h(
      "tr",
      {},
      h("td", {}, u.username),
      h("td", {}, u.role),
      h("td", {}, !u.active ? "Disabled" : u.expires_at ? "Active until " + u.expires_at.slice(0, 10) : "Active"),
      h(
        "td",
        {},
        u.id === state.me.id
          ? ""
          : h(
              "button",
              {
                class: "btn ghost",
                onclick: safe(async () => {
                  await api("/admin/users/" + u.id, { method: "PATCH", json: { active: !u.active } });
                  toast(u.active ? "Disabled. Their sessions ended." : "Enabled.", true);
                  showPage();
                }),
              },
              u.active ? "Disable" : "Enable",
            ),
      ),
    ),
  );
  const create = h(
    "form",
    {
      class: "row",
      onsubmit: safe(async (event) => {
        event.preventDefault();
        await api("/admin/users", { method: "POST", json: newUserPayload(event.target) });
        toast("User created", true);
        showPage();
      }),
    },
    h("input", { name: "username", placeholder: "Username", required: true }),
    h("input", { name: "password", type: "password", placeholder: "Password (10+ characters)", minlength: 10, required: true }),
    h("select", { name: "role", "aria-label": "Role" }, ["viewer", "owner", "admin"].map((r) => h("option", { value: r }, r))),
    h("label", { class: "check" }, h("input", { type: "checkbox", name: "require", checked: true }), "Must choose own password at first sign-in"),
    h("button", { class: "btn" }, "Create user"),
  );
  main.replaceChildren(
    pageHead("People", "Roles decide what someone can do. Document access is granted per document."),
    h("div", { class: "card" }, table(["User", "Role", "Status", ""], rows)),
    h("div", { class: "card" }, h("h2", {}, "Add a person"), create),
  );
}

async function auditPage(main) {
  const filters = state.auditFilters || {};
  const query = new URLSearchParams(Object.entries(filters).filter(([, v]) => v));
  query.set("limit", "300");
  const [records, verify] = await Promise.all([getJson("/admin/audit?" + query), getJson("/admin/audit/verify")]);
  const form = h(
    "form",
    {
      class: "row filters",
      onsubmit: safe((event) => {
        event.preventDefault();
        state.auditFilters = Object.fromEntries(new FormData(event.target));
        return showPage();
      }),
    },
    h("input", { name: "actor", placeholder: "Person", value: filters.actor || "", "aria-label": "Person" }),
    h("input", { name: "action", placeholder: "Action, e.g. download", value: filters.action || "", "aria-label": "Action" }),
    h("input", { name: "doc_id", placeholder: "Document id", type: "number", min: 1, value: filters.doc_id || "", "aria-label": "Document id" }),
    h("select", { name: "outcome", "aria-label": "Result" }, ["", "ok", "denied", "error"].map((o) => h("option", { value: o, selected: o === (filters.outcome || "") }, o || "Any result"))),
    h("button", { class: "btn" }, "Filter"),
  );
  const rows = records.map((r) =>
    h("tr", {}, h("td", { class: "mono" }, r.seq), h("td", {}, when(r.ts)), h("td", {}, r.actor_name || "-"), h("td", {}, words(r.action)), h("td", {}, r.doc_id ?? ""), h("td", { class: r.outcome }, r.outcome)),
  );
  const anchorForm = h(
    "form",
    {
      class: "row filters",
      onsubmit: safe(async (event) => {
        event.preventDefault();
        const f = new FormData(event.target);
        const q = new URLSearchParams({ anchor_seq: f.get("seq"), anchor_hash: f.get("hash").trim() });
        const result = await getJson("/admin/audit/verify?" + q);
        toast(result.valid ? "Fingerprint matches. Nothing has been removed since." : "Fingerprint check FAILED: records were changed or removed.", result.valid);
      }),
    },
    h("input", { name: "seq", type: "number", min: 1, required: true, placeholder: "Saved record #", "aria-label": "Saved record number" }),
    h("input", { name: "hash", required: true, placeholder: "Saved fingerprint (64 characters)", "aria-label": "Saved fingerprint", class: "wide" }),
    h("button", { class: "btn ghost" }, "Check against saved fingerprint"),
  );
  main.replaceChildren(
    pageHead("Audit trail", "Every upload, download, change, deletion, permission change and refused attempt."),
    integrityBanner(verify),
    anchorForm,
    form,
    h("div", { class: "card" }, table(["#", "When", "Who", "Action", "Doc", "Result"], rows)),
  );
}

async function accessPage(main) {
  const [rows, log] = await Promise.all([getJson("/admin/access"), getJson("/admin/audit?limit=300")]);
  const sharing = rows.map((r) =>
    h(
      "tr",
      {},
      h("td", {}, r.document, r.deleted ? " (deleted)" : ""),
      h("td", {}, r.person),
      h("td", {}, pill(r.access)),
      h("td", {}, r.granted_by || "uploaded it"),
      h("td", {}, when(r.since)),
      h("td", {}, r.access === "owner" || r.deleted ? "" : h("button", { class: "btn danger", onclick: safe(async () => {
        await api(`/admin/grants/${r.doc_id}/${r.person_id}`, { method: "DELETE" });
        toast("Access removed. It stops working immediately.", true);
        showPage();
      }) }, "Remove")),
    ),
  );
  const operations = log.filter((e) => e.doc_id !== null).map((e) =>
    h("tr", {}, h("td", {}, when(e.ts)), h("td", {}, e.actor_name || "-"), h("td", {}, words(e.action)), h("td", {}, e.doc_id), h("td", { class: e.outcome }, e.outcome)),
  );
  main.replaceChildren(
    pageHead("Access list", "Who can read or edit which document, who gave it to them, and everything that was done."),
    h("div", { class: "card" }, h("h2", {}, "Who has access to what"), rows.length ? table(["Document", "Person", "Access", "Given by", "Since", ""], sharing) : h("p", { class: "empty" }, "No documents yet. Owners and administrators upload them and share them with people here.")),
    h("div", { class: "card" }, h("h2", {}, "What was done"), operations.length ? table(["When", "Who", "Operation", "Doc", "Result"], operations) : h("p", { class: "empty" }, "Nothing has happened yet.")),
  );
}


start();
