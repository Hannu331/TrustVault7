# TrustVault

Secure document sharing where the server decides every access and every attempt, allowed or refused, is recorded in a hash-chained audit trail.
Python 3.12, FastAPI, SQLite, vanilla JS frontend served by the same app.

## Run (clean clone)
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m scripts.seed          # creates schema, demo users, 2 documents
uvicorn app.main:app --port 8000   # open http://localhost:8000
pytest -q                        # 27 tests
python -m scripts.mutation_check # removes one authz check at a time; tests must fail
```
Docker: `docker build -t trustvault . && docker run -p 8000:8000 -v tv:/data trustvault`
Deploy: any host that runs the Dockerfile (Render, Fly, Railway). Mount a persistent volume at `/data`, put it behind HTTPS, and set `TV_PW_ADMIN`, `TV_PW_ALICE`, `TV_PW_BOB`, `TV_PW_VERA` before the first start to override the demo passwords. **Run one instance only** (see THREATS T20).

## Demo accounts (seed data; change on any real deployment)
| Role | Username | Password |
|---|---|---|
| Administrator | admin | admin-Demo-2026! |
| Document owner | alice | alice-Demo-2026! |
| Document owner | bob | bob-Demo-2026! |
| Viewer | vera | vera-Demo-2026! |

Try: log in as `vera`, open alice's salary letter (read granted). As `bob`, search for it: not visible. As `alice`, remove vera's access, then use vera's still-open tab: refused on the next click.

## Permission model (in my words)
Roles say what you may do in general. Grants say what you may do to one document.
- **Administrator**: manages people, sees document *metadata*, audit and activity. **Never** reads, downloads or searches content, even if promoted later while holding old grants.
- **Owner**: uploads; has full control of documents they own (share, revoke, delete, edit, see per-document audit); can be granted `read` or `edit` on others' documents.
- **Viewer**: read-only by role. Can only receive `read` grants. Cannot upload.
- Per-document grants only: no folders, no groups (see "Not built"). A document is reachable only if you own it (as an owner) or hold a grant row. Authorisation is one function, `app/authz.py:authorize`, called by every document route, and search embeds the same rule in its SQL.
- Unauthorised and non-existent documents return the same `404`. Refusals are audited.

## Revocation: what "immediately" means, and what it costs
Sessions are opaque random tokens whose hashes are stored server-side; there are no JWTs and no signed download URLs. Every request re-reads the session, the user's active flag and role, and the grant from the database. Removing a grant, disabling a user or changing a role takes effect on the very next request; disabling or changing a user also deletes all their sessions. Cost: one or two small DB reads per request, and no horizontal scaling without a shared DB. Not revocable: bytes a person already downloaded.

## Audit trail
Append-only table (SQLite triggers reject UPDATE/DELETE) where each record contains the SHA-256 of the previous one. Someone with raw database access could drop the triggers, but editing or deleting any row then breaks the chain, which the admin page verifies (`/api/admin/audit/verify`, tested). What the chain cannot stop: a full rewrite by someone who recomputes every hash. Mitigation not built: publish the head hash externally on a schedule (THREATS T15).

## Not built (deliberately)
Groups and folder inheritance (every inherited permission is another place to leak; per-document grants are easy to reason about and test); external/guest sharing; versions history and restore UI (soft delete exists, blobs kept); retention policies; MFA; the optional AI "who should see this" assistant (would have to be suggest-only with the suggestion and the decision audited; skipped to keep the permission core small); malware scanning; encryption at rest.

## Unfinished / honest gaps
See THREATS.md "Accepted". Highest: administrator can reset a user's password and so impersonate them (audited, not prevented); no ownership transfer when an owner is demoted; single-instance login throttle.
