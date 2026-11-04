# API: who may call what
"Owner of doc" = role `owner` AND `documents.owner_id` = caller. "Grant" = row in `grants`. Anything not allowed returns `404` for documents (indistinguishable from missing), `403` for role-gated endpoints, `401` when not signed in. All refusals are audited.

| Method & path | Allowed | Notes |
|---|---|---|
| POST /api/auth/login | anyone | Throttled: 5 failures / 15 min per IP+username; failures audited |
| POST /api/auth/logout | signed-in | Deletes that session |
| GET /api/auth/me | signed-in | |
| GET /api/users/directory | owner role | Active non-admin users, for choosing who to share with |
| POST /api/documents | owner role | multipart `file`, `category`. Allow-listed type + magic bytes, 10 MB |
| GET /api/documents | signed-in non-admin | Filters `q, owner, category, date_from, date_to`. Returns only docs you own or hold a grant on (admin gets `[]`) |
| GET /api/documents/{id} | owner of doc, or read/edit grant | Grants list only included for the owner |
| GET /api/documents/{id}/download | owner of doc, or read/edit grant | Integrity-checked, `attachment`, `nosniff` |
| PUT /api/documents/{id} | owner of doc, or edit grant (owner role) | Body `{name?, category?}`; unknown fields rejected |
| PUT /api/documents/{id}/content | owner of doc, or edit grant (owner role) | Replaces file, bumps version |
| DELETE /api/documents/{id} | owner of doc only | Soft delete |
| PUT /api/documents/{id}/grants/{user_id} | owner of doc only | `{permission: read|edit}`. Not to admins, self, or `edit` to viewers |
| DELETE /api/documents/{id}/grants/{user_id} | owner of doc only | Effective on next request |
| GET /api/documents/{id}/audit | owner of doc only | |
| GET /api/admin/users | admin | |
| POST /api/admin/users | admin | |
| PATCH /api/admin/users/{id} | admin (not self) | role / active / password; deletes the target's sessions |
| GET /api/admin/audit | admin | Filters `action, outcome, actor, doc_id, limit` |
| GET /api/admin/audit/verify | admin | Recomputes the hash chain |
| GET /api/admin/activity | admin | Refusal clusters, permission changes, document metadata |
