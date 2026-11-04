"use strict";
// All content is inserted with textContent / DOM nodes, never innerHTML: stored filenames cannot become script.
const $ = (s) => document.querySelector(s);
let token = sessionStorage.getItem("tv_token"), me = null, view = "docs", openDoc = null;

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) k.startsWith("on") ? e.addEventListener(k.slice(2), v) : (v !== false && e.setAttribute(k, v === true ? "" : v));
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
function say(text, good) { const m = $("#msg"); if (!m) return; m.textContent = text; m.className = good ? "good" : "err"; setTimeout(() => { m.textContent = ""; m.className = ""; }, 5000); }

async function api(path, opt = {}) {
  const o = { method: "GET", headers: {}, ...opt }; if (token) o.headers.Authorization = "Bearer " + token;
  if (o.json) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(o.json); }
  const r = await fetch("/api" + path, o);
  if (r.status === 401 && path !== "/auth/login") { logoutLocal(); throw new Error("Session ended. Sign in again."); }
  if (!r.ok) { let d = r.statusText; try { const j = await r.json(); d = typeof j.detail === "string" ? j.detail : "Request was rejected"; } catch {} throw new Error(d); }
  return r;
}
const j = async (p, o) => (await api(p, o)).json();
const act = (fn) => async (ev) => { try { await fn(ev); } catch (e) { say(e.message); } };

function logoutLocal() { token = null; me = null; sessionStorage.removeItem("tv_token"); render(); }

async function render() {
  const root = $("#app"); root.replaceChildren(h("div", { id: "msg", role: "status" }));
  if (!token) return loginView(root);
  try { me = await j("/auth/me"); } catch { return loginView(root); }
  root.append(h("header", {}, h("h1", {}, "TrustVault"), h("span", {}, `${me.username} (${me.role})`),
    ...(me.role === "admin" ? [h("button", { class: "ghost", onclick: () => { view = "admin"; render(); } }, "Admin")] :
        [h("button", { class: "ghost", onclick: () => { view = "docs"; openDoc = null; render(); } }, "Documents")]),
    h("button", { class: "ghost", onclick: act(async () => { await api("/auth/logout", { method: "POST" }); logoutLocal(); }) }, "Sign out")));
  const main = h("main"); root.append(main);
  if (me.role === "admin") return adminView(main);
  return openDoc ? docView(main, openDoc) : docsView(main);
}

function loginView(root) {
  root.append(h("div", { class: "login" }, h("h2", {}, "Sign in to TrustVault"),
    h("form", { onsubmit: act(async (ev) => { ev.preventDefault();
        const f = new FormData(ev.target);
        const r = await j("/auth/login", { method: "POST", json: { username: f.get("u"), password: f.get("p") } });
        token = r.token; sessionStorage.setItem("tv_token", token); render(); }) },
      h("label", {}, "Username", h("input", { name: "u", required: true, autocomplete: "username" })),
      h("label", {}, "Password", h("input", { name: "p", type: "password", required: true, autocomplete: "current-password" })),
      h("button", {}, "Sign in"))));
}

async function docsView(main, params = {}) {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
  const docs = await j("/documents" + (q ? "?" + q : ""));
  const f = (name, ph, type = "text") => h("input", { name, placeholder: ph, type, "aria-label": ph, value: params[name] || "" });
  main.replaceChildren(
    h("section", {}, h("h2", {}, "Find documents"),
      h("form", { onsubmit: act((ev) => { ev.preventDefault(); const d = Object.fromEntries(new FormData(ev.target)); return docsView(main, d); }) },
        f("q", "Name contains"), f("owner", "Owner"), f("category", "Category"), f("date_from", "From", "date"), f("date_to", "To", "date"), h("button", {}, "Search"))),
    ...(me.role === "owner" ? [h("section", {}, h("h2", {}, "Upload a document"),
      h("form", { onsubmit: act(async (ev) => { ev.preventDefault(); const fd = new FormData(ev.target);
          await api("/documents", { method: "POST", body: fd }); say("Uploaded", true); render(); }) },
        h("input", { type: "file", name: "file", required: true, "aria-label": "File" }),
        h("input", { name: "category", value: "general", "aria-label": "Category" }), h("button", {}, "Upload")),
      h("p", { class: "muted" }, "PDF, PNG, JPG, DOCX, XLSX, TXT or CSV up to 10 MB. Content is checked, not just the extension."))] : []),
    h("section", {}, h("h2", {}, `Documents you can open (${docs.length})`),
      docs.length ? h("table", {}, h("thead", {}, h("tr", {}, ...["Name", "Owner", "Category", "Your access", "Updated", ""].map((x) => h("th", {}, x)))),
        h("tbody", {}, docs.map((d) => h("tr", {}, h("td", {}, d.name), h("td", {}, d.owner), h("td", {}, d.category), h("td", {}, d.access),
          h("td", {}, d.updated_at.slice(0, 10)), h("td", {}, h("button", { class: "ghost", onclick: () => { openDoc = d.id; render(); } }, "Open"))))))
        : h("p", { class: "muted" }, "Nothing here yet. Documents appear when you upload them or when an owner shares them with you.")));
}

async function download(id, name) {
  const r = await api(`/documents/${id}/download`); const url = URL.createObjectURL(await r.blob());
  const a = h("a", { href: url, download: name }); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}

async function docView(main, id) {
  const d = await j("/documents/" + id), owner = d.access === "owner", canEdit = owner || d.access === "edit";
  const secs = [h("section", {}, h("h2", {}, d.name), h("p", { class: "muted" }, `Owner ${d.owner} · ${d.category} · v${d.version} · ${d.size} bytes · your access: ${d.access}`),
    h("div", { class: "row" }, h("button", { onclick: act(() => download(id, d.name)) }, "Download"),
      ...(canEdit ? [h("input", { type: "file", id: "repl", "aria-label": "Replacement file" }),
        h("button", { class: "ghost", onclick: act(async () => { const fl = $("#repl").files[0]; if (!fl) throw new Error("Choose a file first");
          const fd = new FormData(); fd.append("file", fl); await api(`/documents/${id}/content`, { method: "PUT", body: fd }); say("Content replaced", true); render(); }) }, "Replace content")] : []),
      ...(owner ? [h("button", { class: "danger", onclick: act(async () => { if (!confirm("Delete this document?")) return; await api("/documents/" + id, { method: "DELETE" }); openDoc = null; render(); }) }, "Delete")] : [])))];
  if (owner) {
    const dir = await j("/users/directory"), au = await j(`/documents/${id}/audit`);
    secs.push(h("section", {}, h("h2", {}, "Who has access"),
      d.grants.length ? h("table", {}, h("tbody", {}, d.grants.map((g) => h("tr", {}, h("td", {}, g.username), h("td", {}, g.permission),
        h("td", {}, h("button", { class: "danger", onclick: act(async () => { await api(`/documents/${id}/grants/${g.user_id}`, { method: "DELETE" }); say("Access removed", true); render(); }) }, "Remove access")))))) : h("p", { class: "muted" }, "Only you can open this document."),
      h("form", { onsubmit: act(async (ev) => { ev.preventDefault(); const f = new FormData(ev.target);
          await api(`/documents/${id}/grants/${f.get("u")}`, { method: "PUT", json: { permission: f.get("p") } }); say("Access granted", true); render(); }) },
        h("select", { name: "u", "aria-label": "Person" }, dir.map((u) => h("option", { value: u.id }, `${u.username} (${u.role})`))),
        h("select", { name: "p", "aria-label": "Permission" }, h("option", { value: "read" }, "Can read"), h("option", { value: "edit" }, "Can edit")),
        h("button", {}, "Grant access"))),
      h("section", {}, h("h2", {}, "Activity on this document"), h("table", {}, h("thead", {}, h("tr", {}, ...["When", "Who", "What", "Result"].map((x) => h("th", {}, x)))),
        h("tbody", {}, au.map((a) => h("tr", {}, h("td", {}, a.ts.replace("T", " ").slice(0, 19)), h("td", {}, a.actor_name || "-"), h("td", {}, a.action), h("td", { class: a.outcome }, a.outcome)))))));
  }
  main.replaceChildren(...secs);
}

async function adminView(main) {
  const [users, act24, au, ver] = await Promise.all([j("/admin/users"), j("/admin/activity"), j("/admin/audit?limit=100"), j("/admin/audit/verify")]);
  const tbl = (cols, rows) => h("table", {}, h("thead", {}, h("tr", {}, cols.map((c) => h("th", {}, c)))), h("tbody", {}, rows));
  main.replaceChildren(
    h("section", {}, h("h2", {}, "Audit trail integrity"),
      h("p", { class: ver.valid ? "ok" : "denied" }, ver.valid ? "Chain verified: no record has been altered or removed." : `Chain BROKEN at record ${ver.first_bad_seq}. Treat the log as tampered.`)),
    h("section", {}, h("h2", {}, "Worth noticing (last 24 hours)"),
      act24.notable.length ? tbl(["Who", "Refused attempts"], act24.notable.map((n) => h("tr", {}, h("td", {}, n.actor), h("td", {}, n.refused)))) : h("p", { class: "muted" }, "No one has been refused three or more times."),
      h("p", { class: "muted" }, act24.by_action_24h.map((a) => `${a.action}/${a.outcome}: ${a.n}`).join("   "))),
    h("section", {}, h("h2", {}, "People"),
      tbl(["User", "Role", "Active", ""], users.map((u) => h("tr", {}, h("td", {}, u.username), h("td", {}, u.role), h("td", {}, u.active ? "yes" : "no"),
        h("td", {}, u.id === me.id ? "" : h("button", { class: "ghost", onclick: act(async () => { await api("/admin/users/" + u.id, { method: "PATCH", json: { active: !u.active } }); render(); }) }, u.active ? "Disable and sign out" : "Enable"))))),
      h("form", { onsubmit: act(async (ev) => { ev.preventDefault(); const f = Object.fromEntries(new FormData(ev.target));
          await api("/admin/users", { method: "POST", json: f }); say("User created", true); render(); }) },
        h("input", { name: "username", placeholder: "Username", required: true }), h("input", { name: "password", type: "password", placeholder: "Password (10+ characters)", minlength: 10, required: true }),
        h("select", { name: "role", "aria-label": "Role" }, ["viewer", "owner", "admin"].map((r) => h("option", { value: r }, r))), h("button", {}, "Create user"))),
    h("section", {}, h("h2", {}, "Permission changes"), tbl(["When", "By", "Action", "Document", "Detail"], act24.permission_changes.map((p) =>
      h("tr", {}, h("td", {}, p.ts.slice(0, 19)), h("td", {}, p.actor_name), h("td", {}, p.action), h("td", {}, p.doc_id ?? ""), h("td", { class: "muted" }, p.detail))))),
    h("section", {}, h("h2", {}, "Documents (metadata only, content is never visible to administrators)"),
      tbl(["ID", "Name", "Owner", "Category", "Grants", "Status"], act24.documents.map((d) => h("tr", {}, h("td", {}, d.id), h("td", {}, d.name), h("td", {}, d.owner), h("td", {}, d.category), h("td", {}, d.grants), h("td", {}, d.deleted_at ? "deleted" : "active"))))),
    h("section", {}, h("h2", {}, "Recent audit records"), tbl(["#", "When", "Who", "Action", "Doc", "Result"], au.map((a) =>
      h("tr", {}, h("td", {}, a.seq), h("td", {}, a.ts.slice(0, 19)), h("td", {}, a.actor_name || "-"), h("td", {}, a.action), h("td", {}, a.doc_id ?? ""), h("td", { class: a.outcome }, a.outcome))))));
}
render();
