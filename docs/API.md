# API: who may call what
"Owner of doc" = role `owner` AND `documents.owner_id` = caller. "Grant" = row in `grants`. Document ids must be 1 to 2147483647, otherwise `422`. Interactive docs (`/docs`, `/openapi.json`) are disabled; this file is the API reference. Refusals of every kind (bad or missing token, wrong role, no document access) are audited. While `must_change_password` is set (new or admin-reset accounts) every endpoint except `/api/auth/me`, `/api/auth/password` and `/api/auth/logout` returns `403`. Anything not allowed returns `404` for documents (indistinguishable from missing), `403` for role-gated endpoints, `401` when not signed in. All refusals are audited.

| Method & path | Allowed | Notes |
|---|---|---|
| GET /api/config | anyone | Only `{demo: bool}`, to show demo sign-in buttons |
| POST /api/auth/password | signed-in (also while a temporary password is pending) | `{current, new}`; current password required, throttled and audited; ends **all** the user's sessions |
| POST /api/auth/login | anyone | Throttled: 5 failures / 15 min per IP+username; failures audited |
| POST /api/auth/logout | signed-in | Deletes that session |
| GET /api/auth/me | signed-in | |
| GET /api/users/directory | owner or admin role | Active non-admin users, for choosing who to send a document to |
| POST /api/documents | owner or admin role | multipart `file`, `category`. Allow-listed type + magic bytes, 10 MB. The uploader owns it |
| GET /api/documents | signed-in | Filters `q, owner, category, date_from, date_to`. Returns only documents you own or hold a grant on |
| GET /api/documents/{id} | owner of doc, or read/edit grant | Grants list only included for the owner |
| GET /api/documents/{id}/download | owner of doc, or read/edit grant | Integrity-checked, `attachment`, `nosniff` |
| PUT /api/documents/{id} | owner of doc, or an `edit` grant (any role except admin) | Body `{name?, category?}`; unknown fields rejected |
| PUT /api/documents/{id}/content | owner of doc, or an `edit` grant (any role except admin) | Replaces file, bumps version |
| DELETE /api/documents/{id} | owner of doc only | Soft delete |
| PUT /api/documents/{id}/grants/{user_id} | owner of doc only (owner or administrator who uploaded it) | `{permission: read|edit}` to any active non-admin account except yourself |
| DELETE /api/documents/{id}/grants/{user_id} | owner of doc only | Effective on next request |
| GET /api/documents/{id}/audit | owner of doc only | |
| GET /api/admin/users | admin | |
| POST /api/admin/users | admin | `{username, password, role, require_password_change}` (default true: the person must choose their own password at first sign-in; false only for shared evaluation accounts) |
| PATCH /api/admin/users/{id} | admin (not self) | role / active / password; deletes the target's sessions |
| GET /api/admin/audit | admin | Filters `action, outcome, actor, doc_id, limit` |
| GET /api/admin/audit/verify | admin | Recomputes the hash chain. Optional `anchor_seq` + `anchor_hash` (a fingerprint saved earlier) also detects deleted newest records |
| GET /api/admin/activity | admin | Refusal clusters, permission changes, document metadata |
| GET /api/admin/access | admin | One row per owner and per grant: who can do what to which document, who gave it, since when |
| DELETE /api/admin/grants/{doc_id}/{user_id} | admin | Removes anyone's access to any document, immediately, audited. Administrators can never ADD access to or open other people's documents |
